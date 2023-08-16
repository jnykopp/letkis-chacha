(in-package :letkis-chacha)

;;; Copyright (c) 2023 Janne Nykopp. See file "LICENSE".

(defun is-chacha-state-p (s)
  "Check if S is ChaCha state."
  (and (typep s '(simple-array (unsigned-byte 32) 1))
       (= (length s) 16)))
(deftype state ()
  "Inner state of the Chacha20 algorithm. Read
https://www.rfc-editor.org/rfc/rfc8439.txt for further information."
  '(satisfies is-chacha-state-p))

(declaim
 (ftype
  (function ((simple-array (unsigned-byte 8) 1)
             (unsigned-byte 32)
             (simple-array (unsigned-byte 8) 1))
            state)
  make-chacha-state))
(defun make-chacha-state (key counter nonce)
  "Create a chacha `state' instance from KEY, COUNTER and
NONCE. Return it. KEY and NONCE should be vectors of unsigned bytes;
KEY should be 256 bits, i.e. 32 bytes and NONCE 96 bits, i.e. 12
bytes. COUNTER should be 32-bit unsigned integer."
  (declare (type (simple-array (unsigned-byte 8) 1) key nonce))
  (declare (type (unsigned-byte 32) counter))
  (assert (= (length key) 32))
  (assert (= (length nonce) 12))
  (let ((state (make-array 16 :element-type '(unsigned-byte 32)
                              :initial-contents (list #x61707865 #x3320646e #x79622d32 #x6b206574
                                                      0 0 0 0 0 0 0 0   ; init with key
                                                      counter 0 0 0)))) ; 0's replaced with nonce
    (macrolet ((32b-from-8b-array (array start-index)
                 `(logior (aref ,array ,start-index)
                          (ash (aref ,array (incf ,start-index)) 8)
                          (ash (aref ,array (incf ,start-index)) 16)
                          (ash (aref ,array (incf ,start-index)) 24))))
      (loop :for state-ind :from 4 :upto 11
            :for key-byte-ind :from 0
            :do (setf (aref state state-ind) (32b-from-8b-array key key-byte-ind)))
      (loop :for state-ind :from 13 :upto 15
            :for nonce-byte-ind :from 0
            :do (setf (aref state state-ind) (32b-from-8b-array nonce nonce-byte-ind)))
      state)))

(declaim (ftype (function ((unsigned-byte 32) (unsigned-byte 32)) (unsigned-byte 32)) %+mod32))
(defun %+mod32 (a b)
  "Add two 32-bit unsigned integers modulo 2^32."
  (declare (optimize (speed 3)) (type (unsigned-byte 32) a b))
  (logand (+ a b) #xffffffff))

(declaim (ftype (function (state) (unsigned-byte 32)) incf-chacha-counter))
(defun incf-chacha-counter (state)
  "Increment counter in STATE. Mutates STATE. Returns new counter value."
  (declare (optimize (speed 3)) (type (simple-array (unsigned-byte 32) 1) state))
  (setf #1=(aref state 12) (%+mod32 #1# 1)))

(declaim (ftype (function (state) (simple-array (unsigned-byte 8) 1)) serialize-chacha-state))
(defun serialize-chacha-state (state)
  "Convert chacha STATE to byte vector and return it."
  (let ((ser (make-array 64 :element-type '(unsigned-byte 8))))
    (macrolet ((u32-to-u8-arr (val arr index-from)
                 `(setf (aref ,arr ,index-from) (logand #x000000ff ,val)
                        (aref ,arr (incf ,index-from)) (ash (logand #x0000ff00 ,val) -8)
                        (aref ,arr (incf ,index-from)) (ash (logand #x00ff0000 ,val) -16)
                        (aref ,arr (incf ,index-from)) (ash (logand #xff000000 ,val) -24))))
      (loop :for val :across state
            :for ser-i :from 0
            :do (u32-to-u8-arr val ser ser-i))
      ser)))

(declaim (ftype (function (state state) state) add-into-state))
(defun add-into-state (s1 s2)
  "Add state S2 into state S1. Mutates S1. Returns S1."
  (map-into s1 #'%+mod32 s1 s2))

#+ecl
(ffi:defcbody ecl-rot-uint32 (:int :uint32-t) :uint32-t "((#1 << #0) | (#1 >> (32 - #0)))")

;;; This Chacha20 implementation is straightforward translation of the
;;; pseudocode in IETF RFC 8439 and counts as derivative work. The
;;; derived parts in this work are marked with docstring or comment
;;; text "This code was derived from IETF RFC 8439. Please reproduce
;;; this note if possible." The pseudocode is published under the
;;; following license:
;;;
;;; Copyright (c) 2018 IETF Trust and Yoav Nir & Adam Langley. All
;;; rights reserved. Redistribution and use in source and binary
;;; forms, with or without modification, are permitted provided that
;;; the following conditions are met:
;;;
;;; 1. Redistributions of source code must retain the above copyright
;;;    notice, this list of conditions and the following disclaimer.
;;;
;;; 2. Redistributions in binary form must reproduce the above
;;;    copyright notice, this list of conditions and the following
;;;    disclaimer in the documentation and/or other materials provided
;;;    with the distribution.
;;;
;;; 3. Neither the name of Internet Society, IETF or IETF Trust, nor
;;;    the names of specific contributors, may be used to endorse or
;;;    promote products derived from this software without specific
;;;    prior written permission.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
;;; CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES,
;;; INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
;;; MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;;; DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
;;; BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
;;; EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;; TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;;; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
;;; ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
;;; TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
;;; THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
;;; SUCH DAMAGE.

(declaim (ftype (function
                 ((unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32))
                 (values (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32) (unsigned-byte 32)))
                q-round))
(defun q-round (a b c d)
  "Do the chacha quarter round for the four 32-bit unsigned
integers. Return 4 32-bit unsigned integers as values.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (declare (optimize (speed 3)) (type (unsigned-byte 32) a b c d))
  (macrolet ((rotateb (count uint32) #+sbcl `(sb-rotate-byte:rotate-byte ,count (byte 32 0) ,uint32)
                                     #+ecl  `(ecl-rot-uint32 ,count ,uint32)
                                     #-(or ecl sbcl) #.(error "Only implemented for ECL and SBCL.")))
    (let ((ar a) (br b) (cr c) (dr d))
      (declare (type (unsigned-byte 32) ar br cr dr))
      (setf ar (%+mod32 ar br)  dr (logxor dr ar)  dr (rotateb 16 dr)
            cr (%+mod32 cr dr)  br (logxor br cr)  br (rotateb 12 br)
            ar (%+mod32 ar br)  dr (logxor dr ar)  dr (rotateb 8  dr)
            cr (%+mod32 cr dr)  br (logxor br cr)  br (rotateb 7  br))
      (values ar br cr dr))))

(declaim (ftype (function
                 (state (integer 0 15) (integer 0 15) (integer 0 15) (integer 0 15)) state)
                q-round-s))
(defun q-round-s (state i1 i2 i3 i4)
  "Execute chacha quarter round for chacha STATE indexes I1, I2, I3
and I4 mutating it along the way. Return new state."
  (declare (optimize (speed 3))
           (type (integer 0 15) i1 i2 i3 i4)
           (type (simple-array (unsigned-byte 32) 1) state))
  (macrolet ((ind (i) `(aref state ,i)))
    (let ((a (ind i1)) (b (ind i2)) (c (ind i3)) (d (ind i4)))
      (multiple-value-bind (ar br cr dr) (q-round a b c d)
        (setf (ind i1) ar  (ind i2) br  (ind i3) cr  (ind i4) dr))))
  state)

(declaim (ftype (function (state) null) inner-block))
(defun inner-block (state)
  "Execute chacha inner block with STATE, mutating STATE.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (declare (optimize (speed 3)))
  (loop :for inds :in '((0 4 8 12)  (1 5 9 13)  (2 6 10 14) (3 7 11 15)
                        (0 5 10 15) (1 6 11 12) (2 7 8 13)  (3 4 9 14))
        :do (apply #'q-round-s state inds)))

(declaim (ftype (function (state) state) chacha20-block))
(defun chacha20-block (initial-state)
  "Execute chacha 20 block based on INITIAL-STATE. INITIAL-STATE is not
mutated. New state is returned. This is done so because initial state
is reused in encryption for generating keystream, only with counter
increased.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (let ((state (alexandria:copy-array initial-state)))
    (loop :repeat 10 :do (inner-block state))
    (add-into-state state initial-state)))

(declaim (ftype (function
                 ((array (unsigned-byte 8) 1)
                  (unsigned-byte 32)
                  (array (unsigned-byte 8) 1)
                  (array (unsigned-byte 8) 1))
                 (array (unsigned-byte 8) 1))
                chacha20-encrypt))
(defun chacha20-encrypt (key counter nonce plaintext)
  "Encrypt octet vector PLAINTEXT with given octet vectors KEY and
NONCE, and given 32-bit unsigned integer NONCE. If given ciphertext as
PLAINTEXT, will decrypt ciphertext. KEY should be 32 and NONCE 12
bytes long. COUNTER should be 32-bit unsigned integer. PLAINTEXT can
be of arbitrary length.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (declare (type (unsigned-byte 32) counter))
  (assert (equal (mapcar #'length (list key nonce)) '(32 12)))
  (let ((initial-state (make-chacha-state key counter nonce)))
    (loop :for j :from 0 :upto (floor #1=(length plaintext) 64)
          :for key-stream := (serialize-chacha-state (chacha20-block initial-state))
          :do
             (loop :for c :across key-stream :for i :from (* j 64) :below #1#
                    :do (setf #2=(aref plaintext i) (logxor #2# c)))
             (incf-chacha-counter initial-state)))
  plaintext)

;;; ----------------------------------------------------------------------
;;; This is not from RFC 8439 but own concoction. Key derivation using
;;; Chacha20, inspired by RFC 8439 section 2.7 mentioning "Chacha20
;;; could be used as a key-derivation function, by generating an
;;; arbitrarily long keystream."

(defparameter *chacha20-kdf-iterations* 1000
  "How many iterations of chacha20 to run at each loop step in
`chacha20-kdf'. Should be a fixnum. 1000 is a bit much for Raspberry
Pi 3 but ok for a contemporary laptop.")

(defparameter *chacha20-kdf-timeout* 5
  "If `chacha20-kdf' run time exceeds this many seconds, condition
`chacha20-kdf-timeout' will be signalled. Should be a fixnum.")

(define-condition chacha20-kdf-timeout (error)
  ((timeout :initarg :timeout :initform nil :accessor timeout))
  (:report (lambda (condition stream)
             (format stream "Letkis-ChaCha KDF run time exceeded timeout of ~a seconds"
                     (timeout condition)))))

(declaim (ftype (function
                 ((simple-array (unsigned-byte 8) 1)
                  (simple-array (unsigned-byte 8) 1)
                  &optional (unsigned-byte 32) fixnum)
                 (simple-array (unsigned-byte 8) 1))
                chacha20-kdf))
(defun chacha20-kdf (password salt
                     &optional (iterations *chacha20-kdf-iterations*) (timeout *chacha20-kdf-timeout*))
  "Take a PASSWORD of any length and at minimum 32-octet long SALT and
generate and return 44 octets of data. ITERATIONS can be used to tune
the cost of this function. Note that changing ITERATIONS naturally
changes the derived key also, so ITERATIONS is an important parameter
as well and should be stored when used. The returned result can be
e.g. used to initialize key and nonce for
`aead-chacha20-poly1305-encrypt'. To avoid denial of service with
(perhaps accidentally) excessively large ITERATIONS, a TIMEOUT
value (in seconds) may be given. If run time exceeds this value, an
error will be signalled.

Implementation notes: First 12 octets of SALT are directly used as
nonce for Chacha state. A 32-octet vector is created and filled from
beginning with octets from PASSWORD and XORred from end with remaining
SALT octets. This 32-octet vector is used as the key material for
Chacha20 initial state. Note that with an empty password the key will
start with 12 zero octets.

If PASSWORD is longer than 32 octets and SALT longer than 44 octets,
remaining octets are combined (PASSWORD first) and transformed into
pseudo-random bytes indicating how much initially to seek the Chacha
keystream forward. Finally run a loop that collects one byte of
serialized Chacha20 state altogether 44 times, where Chacha20 block is
run ITERATIONS times in every loop step.

As Chacha20 is a CSPRNG the resulting 44 octets sampled from the
random keystream should be good key material: uniformly distributed
between all possible values, with e.g. no remains of any bias from a
natural language encoded to octets."
  (declare (type (simple-array (unsigned-byte 8) 1) password salt))
  (declare (type fixnum iterations))
  (assert (>= (length salt) 32))
  (assert (>= timeout 0))
  (let* ((pw-len (length password))
         (salt-len (length salt))
         (initial-key-material (concatenate '(simple-array (unsigned-byte 8) 1)
                                            (subseq password 0 (min 32 pw-len))
                                            (%num-to-octets 0 (max 0 (- 32 pw-len)))))
         (nonce-salt (subseq salt 0 12))
         (pw-salt (subseq salt 12))
         (index-scrambler (concatenate '(simple-array (unsigned-byte 8) 1)
                                       (when (> pw-len 32) (subseq password 32))
                                       (when (> salt-len 44) (subseq salt 44))))
         (gen-key-nonce (make-array 44 :element-type '(unsigned-byte 8)))) ;output
    ;; Build keymaterial from salt
    (loop :for s :across pw-salt
          :for i :from 31 :downto 0
          :do (setf #1=(aref initial-key-material i) (logxor s #1#)))
    ;; Make sure we don't run out of stream even in worst case.
    (assert (< (+ (* #x100 (length index-scrambler) (* iterations 44))) 274877906880))
    (let ((chacha-state (make-chacha-state initial-key-material 1 nonce-salt))
          (deadline (+ (get-universal-time) timeout))
          (curr-timeout timeout))
      (flet ((get-ith-octet (i &optional (offs 0))
               ;; Function for first running chacha-state I steps
               ;; forward and then picking one octet (indexed by OFFS
               ;; modulo 64 from the state's 64 octets).
               (declare (type (unsigned-byte 8) offs))
               (declare (type fixnum i))
               (loop :repeat i
                     ;; Meat of the loop.
                     :for state := (serialize-chacha-state (chacha20-block chacha-state))
                     :do (incf-chacha-counter chacha-state)
                     ;; Rest of code checks for a timeout. Provides
                     ;; some restarts in that case.
                     :when (and deadline (>= (get-universal-time) deadline))
                       :do (restart-case (error 'chacha20-kdf-timeout :timeout curr-timeout)
                             (set-new-timeout (tm)
                               :report "Set new timeout (seconds) and continue"
                               :interactive (lambda ()
                                              (format *query-io* "New timeout (seconds): ")
                                              (force-output *query-io*)
                                              (let ((val (read *query-io*)))
                                                (check-type val fixnum) (assert (>= val 0))
                                                (list val)))
                               (incf curr-timeout tm)
                               (setf deadline (+ (get-universal-time) tm)))
                             (run-unbound ()
                               :report "Ignore timeout, run as long as required"
                               (setf deadline nil)))
                     ;; Finally pick one octet from the key stream.
                     :finally (return (aref state (mod offs 64))))))
        (if (> (length index-scrambler) 0)
            ;; Just side-effectfully forward the ChaCha20 chacha-state
            ;; CSPRNG pseudo-randomly according to the possibly
            ;; remaining password and salt octets so that excess
            ;; password & salt material participates meaningfully in
            ;; the resulting key derivation.
            (loop :for weak-octet :across index-scrambler
                  :do (get-ith-octet (get-ith-octet 1 weak-octet))))
        ;; Now initial state is set. Proceed to extract key and nonce.
        (loop :for i :from 0 :below 44
              :do (setf (aref gen-key-nonce i) (get-ith-octet iterations)))))
    gen-key-nonce))
