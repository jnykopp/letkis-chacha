;;; Unit tests for letkis-chacha.

(in-package :letkis-chacha/test)

;;; Copyright (c) 2023 Janne Nykopp. See file "LICENSE".

;;; ----------------------------------------------------------------------
;;; Helper functions & macros

(defmacro multi-value-compare (form &rest exp-results)
  (let ((syms (loop :repeat (length exp-results) :collect (gensym))))
    `(multiple-value-bind ,syms ,form
       ,@(loop :for exp-result :in exp-results :for sym :in syms
               :collect `(parachute:is = ,exp-result ,sym)))))

(defun copy-chacha-state (state)
  "Create and return a copy of STATE."
  (check-type state letkis-chacha::state)
  (alexandria:copy-array state))

(defun str-to-n-halfbyte-vec (str halfbytes)
  "Helper function for converting STR, being a string that contains only string
representation of unsigned hex numbers plus possible whitespace or
commas or semicolons or whatever are the separators between individual
hex number blocks, of HALFBYTES number of ascii letters per
number. Returns a vector of unsigned numbers of the corresponding
element size."
  (check-type str string)
  (let ((clean-str
          (remove-if-not
           (lambda (c) (find c '(#\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9 #\a #\b #\c #\d #\e #\f)))
           str)))
    (assert (= 0 (mod #1=(length clean-str) halfbytes)))
    (concatenate `(simple-array (unsigned-byte ,(* 4 halfbytes)) 1)
                 (loop :for i :from 0 :below (length clean-str) :by halfbytes
                       :collect (parse-integer (subseq clean-str i (+ i halfbytes)) :radix 16)))))

(defun str-to-u32vec (str)
  "Shorthand for creating uint32-vectors out of STR."
  (str-to-n-halfbyte-vec str 8))
(defun str-to-u8vec (str)
  "Shorthand for creating uint8-vectors out of STR."
  (str-to-n-halfbyte-vec str 2))

(defun comp-state (expected-str state)
  (check-type state letkis-chacha::state)
  (parachute:is equalp (str-to-u32vec expected-str) #1=state
                "Expected ~a, got state ~a" expected-str #1#))

(defun hexdump-str-to-u8vec (str)
  "Here the STR is assumed to be a hexdump string, consisting of one or
more lines, whose first 3 characters are address offset, separated
with 2 spaces from individual bytes (max 47 characters, including 32
characters for hex number representation in blocks of 2 characters,
each hex number separated from each other by a space), again separated
by 2 spaces from ascii representation of the bytes (max 16
characters). Only individual bytes are significant here."
  (let* ((rows (uiop:split-string str :separator '(#\Newline)))
         (vecs (loop :for row :in rows
                     :for row-start := (position #\Space row :test-not #'char=)
                     :for clean-row := (subseq row (+ 5 row-start) (+ 52 row-start))
                     :collect (str-to-u8vec clean-row))))
    (apply #'concatenate '(simple-array (unsigned-byte 8) 1) vecs)))

(defun comp-serialized (expected-str state)
  (parachute:is equalp (hexdump-str-to-u8vec expected-str)
                #1=(letkis-chacha::serialize-chacha-state state)
                "Expected ~a, got state ~a" expected-str #1#))

;;; ----------------------------------------------------------------------
;;; Tests matching IETF RFC 8439 test vectors; 2-1-1 is section 2.1.1
;;; etc.
;;;
;;; All following test vector values (hexadecimal numbers, strings
;;; containing hex numbers and hex dumps) are derived from the
;;; pseudocode / test vector definitions in IETF RFC 8439 and counts
;;; as derivative work. The derived parts in this work are marked with
;;; docstring or comment text "These test vector values were derived
;;; from IETF RFC 8439. Please reproduce this note if possible." The
;;; pseudocode is published under the following license:
;;; 
;;; All test vector values (following strings containing hex numbers
;;; and hex dumps) are derived from test vector definitions in IETF
;;; RFC 8439. The test vectors (pseudocode) are published under the
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

(parachute:define-test 2-1-1-quarter-round
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (multi-value-compare 
   (letkis-chacha::q-round #x11111111 #x01020304 #x9b8d6f43 #x01234567)
   #xea2a92f4 #xcb1cf8ce #x4581472e #x5881c4bb))


(parachute:define-test 2-2-1-quarter-round-on-state
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (let ((state
          (str-to-u32vec "879531e0  c5ecf37d  516461b1  c9a62f8a
                          44c20ef3  3390af7f  d9fc690b  2a5f714c
                          53372767  b00a5631  974c541a  359e9963
                          5c971061  3d631689  2098d9d6  91dbd320")))
    (comp-state "879531e0  c5ecf37d *bdb886dc  c9a62f8a
                 44c20ef3  3390af7f  d9fc690b *cfacafd2
                *e46bea80  b00a5631  974c541a  359e9963
                 5c971061 *ccc07c79  2098d9d6  91dbd320"
                (letkis-chacha::q-round-s state 2 7 8 13))))

(parachute:define-test 2-3-2-block-function
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (let* ((key (str-to-u8vec "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:
                             14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"))
         (nonce (str-to-u8vec "00:00:00:09:00:00:00:4a:00:00:00:00"))
         (block-count 1)
         (state (letkis-chacha::make-chacha-state key block-count nonce)))
    (comp-state "61707865  3320646e  79622d32  6b206574
                 03020100  07060504  0b0a0908  0f0e0d0c
                 13121110  17161514  1b1a1918  1f1e1d1c
                 00000001  09000000  4a000000  00000000"
                state)
    (comp-state "837778ab  e238d763  a67ae21e  5950bb2f
                 c4f2d0c7  fc62bb2f  8fa018fc  3f5ec7b7
                 335271c2  f29489f3  eabda8fc  82e46ebd
                 d19c12b4  b04e16de  9e83d0cb  4e3c50a2"
                (loop :repeat 10
                      :with mutat-state := (copy-chacha-state state)
                      :do (letkis-chacha::inner-block mutat-state)
                      :finally (return mutat-state)))
    (comp-state "e4e7f110  15593bd1  1fdd0f50  c47120a3
                 c7f4d1c7  0368c033  9aaa2204  4e6cd4c3
                 466482d2  09aa9f07  05d7c214  a2028bd9
                 d19c12b5  b94e16de  e883d0cb  4e3c50a2"
                (setf state (letkis-chacha::chacha20-block state)))
    (comp-serialized "000  10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4  .....;Y.P.... q.
                      016  c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e  ....3.h..\"....lN
                      032  d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2  ..dF............
                      048  b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e  ......N......P<N"
                     state)))

(parachute:define-test 2-4-2-cipher
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (let* ((key (str-to-u8vec "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:
                             14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"))
         (nonce (str-to-u8vec "00:00:00:00:00:00:00:4a:00:00:00:00"))
         (counter 1)
         (plaintext (hexdump-str-to-u8vec
                     "000  4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c  Ladies and Gentl
                      016  65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73  emen of the clas
                      032  73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63  s of '99: If I c
                      048  6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f  ould offer you o
                      064  6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20  nly one tip for
                      080  74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73  the future, suns
                      096  63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69  creen would be i
                      112  74 2e                                            t."))
         (init-block (letkis-chacha::make-chacha-state key counter nonce))
         ks-block-1 ks-block-2)
    (comp-state "61707865  3320646e  79622d32  6b206574
                 03020100  07060504  0b0a0908  0f0e0d0c
                 13121110  17161514  1b1a1918  1f1e1d1c
                 00000001  00000000  4a000000  00000000"
                init-block)
    (comp-state "f3514f22  e1d91b40  6f27de2f  ed1d63b8
                 821f138c  e2062c3d  ecca4f7e  78cff39e
                 a30a3b8a  920a6072  cd7479b5  34932bed
                 40ba4c79  cd343ec6  4c2c21ea  b7417df0"
                (setf ks-block-1 (letkis-chacha::chacha20-block init-block)))
    (letkis-chacha::incf-chacha-counter init-block)
    (comp-state "61707865  3320646e  79622d32  6b206574
                 03020100  07060504  0b0a0908  0f0e0d0c
                 13121110  17161514  1b1a1918  1f1e1d1c
                 00000002  00000000  4a000000  00000000"
                init-block)
    (comp-state "9f74a669  410f633f  28feca22  7ec44dec
                 6d34d426  738cb970  3ac5e9f3  45590cc4
                 da6e8b39  892c831a  cdea67c1  2b7e1d90
                 037463f3  a11a2073  e8bcfb88  edc49139"
                (setf ks-block-2 (letkis-chacha::chacha20-block init-block)))
    (parachute:is
     equalp
     (str-to-u8vec "22:4f:51:f3:40:1b:d9:e1:2f:de:27:6f:b8:63:1d:ed:8c:13:1f:82:3d:2c:06
                    e2:7e:4f:ca:ec:9e:f3:cf:78:8a:3b:0a:a3:72:60:0a:92:b5:79:74:cd:ed:2b
                    93:34:79:4c:ba:40:c6:3e:34:cd:ea:21:2c:4c:f0:7d:41:b7:69:a6:74:9f:3f
                    63:0f:41:22:ca:fe:28:ec:4d:c4:7e:26:d4:34:6d:70:b9:8c:73:f3:e9:c5:3a
                    c4:0c:59:45:39:8b:6e:da:1a:83:2c:89:c1:67:ea:cd:90:1d:7e:2b:f3:63")
     (concatenate 'vector
                  (letkis-chacha::serialize-chacha-state ks-block-1)
                  (subseq (letkis-chacha::serialize-chacha-state ks-block-2)
                          0 (mod (length plaintext) 64))))
    (parachute:is
     equalp
     (hexdump-str-to-u8vec
      "000  6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81  n.5.%h..A..(..i.
       016  e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b  .~z..C`..'......
       032  f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57  ..e.RG3..Y=..b.W
       048  16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8  .9.$.QR..S.5..a.
       064  07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e  ....P.jaV....\".^
       080  52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36  R.QM.........y76
       096  5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42  Z...t.[......x^B
       112  87 4d                                            .M")
     (letkis-chacha:chacha20-encrypt key counter nonce plaintext))))

;;; Then Poly1305

(parachute:define-test 2-5-2-poly-round
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (let* ((keymaterial (str-to-u8vec "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03
                                     80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"))
         (r-pre-clamp (letkis-chacha::%octets-to-num (subseq keymaterial 0 16)))
         (clamped-r #x806d5400e52447c036d555408bed685)
         (message
           (hexdump-str-to-u8vec
            "000  43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f  Cryptographic Fo
             016  72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f  rum Research Gro
             032  75 70                                            up")))
    ;; Test that clamping works
    (parachute:is = clamped-r (letkis-chacha::%poly1305-clamp r-pre-clamp))
    ;; Skipping test of internal state and blocks for now as they're
    ;; difficult to extract from the implementation. Comparing end
    ;; results ought to be enough.
    (parachute:is
     equalp
     (str-to-u8vec "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9")
     (letkis-chacha:poly1305-mac message keymaterial))))

(parachute:define-test 2-6-2-poly-keygen
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (let ((key
          (hexdump-str-to-u8vec
           "000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
            016  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f  ................"))
        (nonce (hexdump-str-to-u8vec
                "000  00 00 00 00 00 01 02 03 04 05 06 07              ............")))
    (parachute:is
     equalp
     (hexdump-str-to-u8vec
      "000  8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71  ....._...P@'J..q
       016  a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46  .3.7...........F")
     (letkis-chacha:poly1305-key-gen key nonce))))

;;; Then AEAD_CHACHA20_POLY1305

(parachute:define-test 2-8-2-aead-chacha-poly
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (let* ((plaintext
           (hexdump-str-to-u8vec
            "000  4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c  Ladies and Gentl
             016  65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73  emen of the clas
             032  73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63  s of '99: If I c
             048  6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f  ould offer you o
             064  6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20  nly one tip for
             080  74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73  the future, suns
             096  63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69  creen would be i
             112  74 2e                                            t."))
         (key
           (hexdump-str-to-u8vec
            "000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
             016  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f  ................"))
         (aad
           (hexdump-str-to-u8vec
            "000  50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7              PQRS........"))
         (constant
           (hexdump-str-to-u8vec
            "000  07 00 00 00                                      ...."))
         (iv
           (hexdump-str-to-u8vec
            "000  40 41 42 43 44 45 46 47                          @ABCDEFG"))
         (our-ciphertext-and-tag
           (letkis-chacha:aead-chacha20-poly1305-encrypt
            key
            (concatenate '(simple-array (unsigned-byte 8) 1) constant iv)
            plaintext
            aad))
         (our-ciphertext (subseq our-ciphertext-and-tag 0 #1=(- (length our-ciphertext-and-tag) 16)))
         (our-tag (subseq our-ciphertext-and-tag #1#)))
    (parachute:is
     equalp
     (hexdump-str-to-u8vec
      "000  d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2  ...4d.`.{...S.~.
       016  a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6  ...Q)n......6.b.
       032  3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b  =..^..g....i..r.
       048  1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36  .q.....)....~.;6
       064  92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58  ....-w......(..X
       080  fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc  ..$...u.U...H1..
       096  3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b  ?....Kz..v.e...K
       112  61 16                                            a.")
     our-ciphertext)
    (parachute:is equalp (str-to-u8vec "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91") our-tag)))

;;; Appendix test vectors
;;; First some helpers

(defun get-string-block-from (str index)
  (subseq str index (search #(#\Newline #\Newline) str :start2 index)))

(defun get-index-after (indicator str)
  (+ (or (search indicator str) (error "~a not found" indicator)) (1+ (length indicator))))

(defun get-value-for (indicator str)
  (get-string-block-from str (get-index-after indicator str)))

(defun get-key-counter-nonce (testvec)
  (list (hexdump-str-to-u8vec (get-value-for "Key:" testvec))
        (parse-integer (or (ignore-errors (get-value-for "Initial Block Counter =" testvec))
                           (get-value-for "Block Counter =" testvec)))
        (hexdump-str-to-u8vec (get-value-for "Nonce:" testvec))))

(defun init-chacha-from-test-vector (testvec)
  (apply #'letkis-chacha::make-chacha-state (get-key-counter-nonce testvec)))

(defun get-individual-vectors (testvec)
  (loop :with index := 0
        :for pos1 := (when index (search "  Test Vector #" testvec :start2 index))
        :for pos2 := (when pos1 (search "  Test Vector #" testvec :start2 (1+ pos1)))
        :while pos1
        :collect (subseq testvec pos1 pos2)
        :do (setf index pos2)))

(defmacro define-testvec-loop (all-testvecs &body loop-body)
  `(let ((vecs (get-individual-vectors ,all-testvecs)))
     (macrolet ((hexdump-get (l)
                  `(mapcar (lambda (x) (hexdump-str-to-u8vec (get-value-for x vec))) ',l))
                (str-get (l) `(mapcar (lambda (x) (str-to-u8vec (string-downcase (get-value-for x vec))))
                                      ',l)))
       (loop :for vec :in vecs
             ,@loop-body))))

(parachute:define-test a-1-chacha20-block-functions
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (define-testvec-loop
      "  Test Vector #1:

  Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 00              ............

  Block Counter = 0

    ChaCha state at the end
        ade0b876  903df1a0  e56a5d40  28bd8653
        b819d2bd  1aed8da0  ccef36a8  c70d778b
        7c5941da  8d485751  3fe02477  374ad8b8
        f4b8436a  1ca11815  69b687c3  8665eeb2

  Keystream:
  000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
  016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..
  032  da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37  .AY|QWH.w$.?..J7
  048  6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86  jC.........i..e.

  Test Vector #2:

  Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 00              ............

  Block Counter = 1

    ChaCha state at the end
        bee7079f  7a385155  7c97ba98  0d082d73
        a0290fcb  6965e348  3e53c612  ed7aee32
        7621b729  434ee69c  b03371d5  d539d874
        281fed31  45fb0a51  1f0ae1ac  6f4d794b

  Keystream:
  000  9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d  ....UQ8z...|s-..
  016  cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed  ..).H.ei..S>2.z.
  032  29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5  ).!v..NC.q3.t.9.
  048  31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f  1..(Q..E....KyMo

  Test Vector #3:

  Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 00              ............

  Block Counter = 1

    ChaCha state at the end
        2452eb3a  9249f8ec  8d829d9b  ddd4ceb1
        e8252083  60818b01  f38422b8  5aaa49c9
        bb00ca8e  da3ba7b4  c4b592d1  fdf2732f
        4436274e  2561b3c8  ebdd4aa6  a0136c00

  Keystream:
  000  3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd  :.R$..I.........
  016  83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a  . %....`.\"...I.Z
  032  8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd  ......;...../s..
  048  4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0  N'6D..a%.J...l..

  Test Vector #4:

  Key:
  000  00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 00              ............

  Block Counter = 2

    ChaCha state at the end
        fb4dd572  4bc42ef1  df922636  327f1394
        a78dea8f  5e269039  a1bebbc1  caf09aae
        a25ab213  48a6b46c  1b9d9bcb  092c5be6
        546ca624  1bec45d5  87f47473  96f0992e

  Keystream:
  000  72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32  r.M....K6&.....2
  016  8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca  ....9.&^........
  032  13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09  ..Z.l..H.....[,.
  048  24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96  $.lT.E..st......

  Test Vector #5:

  Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 02              ............

  Block Counter = 0

    ChaCha state at the end
        374dc6c2  3736d58c  b904e24a  cd3f93ef
        88228b1a  96a4dfb3  5b76ab72  c727ee54
        0e0e978a  f3145c95  1b748ea8  f786c297
        99c28f5f  628314e8  398a19fa  6ded1b53

  Keystream:
  000  c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd  ..M7..67J.....?.
  016  1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7  ..\".....r.v[T.'.
  032  8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7  .....\....t.....
  048  5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d  _......b...9S..m"
    :for state := (init-chacha-from-test-vector vec)
    :do
    (comp-state (get-value-for "ChaCha state at the end" vec)
                (setf state (letkis-chacha::chacha20-block state)))
    (comp-serialized (get-value-for "Keystream:" vec) state)))

(parachute:define-test a-2-chacha20-encryption
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (define-testvec-loop
      "  Test Vector #1:

  Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 00              ............

  Initial Block Counter = 0

  Plaintext:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  032  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  048  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Ciphertext:
  000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
  016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..
  032  da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37  .AY|QWH.w$.?..J7
  048  6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86  jC.........i..e.

  Test Vector #2:

  Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 02              ............

  Initial Block Counter = 1

  Plaintext:
  000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
  016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
  032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
  048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
  064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
  080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
  096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
  112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
  128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
  144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
  160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
  176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
  192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an \"IETF Cont
  208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution\". Such
  224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
  240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
  256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
  272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
  288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
  304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
  320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
  336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
  352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
  368  73 73 65 64 20 74 6f                             ssed to

  Ciphertext:
  000  a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70  ...}../.O7l.>.sp
  016  41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec  A`].OOW...,.KyU.
  032  2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05  *....r)....7..p.
  048  0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d  ....G...V.1.^.%.
  064  40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e  @B.'....KK....D.
  080  20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50   ........./B.RyP
  096  42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c  B..ws....G.)..A.
  112  68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a  h.eU*....vM^...Z
  128  d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66  ...I..r..b..&..f
  144  42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d  BK.m-....C..7.%.
  160  c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28  ......l.9...if.(
  176  e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b  .5U;.l\..{5....+
  192  08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f  .q..c.9.^.....(.
  208  a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c  ..2.5.<vY...=..l
  224  cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84  .:..9y.+7 ......
  240  a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b  ....d....6....K.
  256  c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0  ....k.;.Uiu?....
  272  8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f  ...c..o..%T...A.
  288  58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62  Xi.R..?.o......b
  304  be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6  ...-.....4......
  320  98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85  ...Y...dw3.=....
  336  14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab  .......A.8M.....
  352  7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd  z....o!.[./70.|.
  368  c4 fd 80 6c 22 f2 21                             ...l\".!

  Test Vector #3:

  Key:
  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

  Nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 02              ............

  Initial Block Counter = 42

  Plaintext:
  000  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61  'Twas brillig, a
  016  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f  nd the slithy to
  032  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64  ves.Did gyre and
  048  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77   gimble in the w
  064  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77  abe:.All mimsy w
  080  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65  ere the borogove
  096  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20  s,.And the mome
  112  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e     raths outgrabe.

  Ciphertext:
  000  62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df  b.4....._..Bo'..
  016  5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf  _....L.s....[...
  032  16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71  .m=..!...._.Lahq
  048  fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb  ...O.e...l....S.
  064  f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6  ..d..\"4.*5k>vC..
  080  1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77  .U2.W....%h.}??w
  096  04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1  .......MP..Km.1.
  112  87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1     ....r..6uzyz..."
    :for (key counter nonce) := (get-key-counter-nonce vec)
    :for (plain ciphr) := (hexdump-get ("Plaintext:" "Ciphertext:"))
    :do (parachute:is equalp ciphr
                      (letkis-chacha::chacha20-encrypt key counter nonce plain))))

(parachute:define-test a-3-poly1305-mac
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (define-testvec-loop
      "  Test Vector #1:

  One-time Poly1305 Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Text to MAC:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  032  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  048  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Tag:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Test Vector #2:

  One-time Poly1305 Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p....\"z.>

  Text to MAC:
  000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
  016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
  032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
  048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
  064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
  080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
  096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
  112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
  128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
  144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
  160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
  176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
  192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an \"IETF Cont
  208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution\". Such
  224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
  240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
  256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
  272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
  288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
  304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
  320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
  336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
  352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
  368  73 73 65 64 20 74 6f                             ssed to

  Tag:
  000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p....\"z.>

  Test Vector #3:

  One-time Poly1305 Key:
  000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p....\"z.>
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Text to MAC:
  000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
  016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
  032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
  048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
  064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
  080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
  096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
  112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
  128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
  144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
  160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
  176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
  192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an \"IETF Cont
  208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution\". Such
  224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
  240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
  256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
  272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
  288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
  304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
  320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
  336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
  352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
  368  73 73 65 64 20 74 6f                             ssed to

  Tag:
  000  f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0  .G~|.T.....yL1..

  Test Vector #4:

  One-time Poly1305 Key:
  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

  Text to MAC:
  000  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61  'Twas brillig, a
  016  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f  nd the slithy to
  032  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64  ves.Did gyre and
  048  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77   gimble in the w
  064  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77  abe:.All mimsy w
  080  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65  ere the borogove
  096  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20  s,.And the mome
  112  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e     raths outgrabe.

  Tag:
  000  45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62  EAf.~..a...|...b"
    :for (key input tag) := (hexdump-get ("  One-time Poly1305 Key:" "  Text to MAC:" "  Tag:"))
    :do (parachute:is equalp tag (letkis-chacha::poly1305-mac input key)))

  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (define-testvec-loop
      "   Test Vector #5:

   R:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   data:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF

   tag:
   03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   Test Vector #6:

   R:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   S:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF

   data:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   tag:
   03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   Test Vector #7:

   R:
   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   data:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   tag:
   05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   Test Vector #8:

   R:
   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   data:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
   01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01

   tag:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   Test Vector #9:

   R:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   data:
   FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF

   tag:
   FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF

   Test Vector #10:

   R:
   01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00

   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   data:
   E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
   33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   tag:
   14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00

   Test Vector #11:

   R:
   01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00

   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   data:
   E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
   33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   tag:
   13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    :for (r s data tag) := (str-get ("   R:" "   S:" "   data:" "   tag:"))
    :do (parachute:is
         equalp tag
         (letkis-chacha::poly1305-mac
          data (concatenate '(simple-array (unsigned-byte 8) 1) r s)))))

(parachute:define-test a-4-key-generation
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (define-testvec-loop
      "  Test Vector #1:

  The ChaCha20 Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  The nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 00              ............

  Poly1305 one-time key:
  000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
  016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..

  Test Vector #2:

  The ChaCha20 Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................

  The nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 02              ............

  Poly1305 one-time key:
  000  ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76  ..%O._dts......v
  016  06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39  ..3.lD{..&f....9

  Test Vector #3:

  The ChaCha20 Key:
  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

  The nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 02              ............

  Poly1305 one-time key:
  000  96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b  .^;...~.V....).K
  016  13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae  ...u..?..Y...3.."
    :for (ck nonce pk) := (hexdump-get ("The ChaCha20 Key:" "The nonce:" "Poly1305 one-time key:"))
    :do (parachute:is equalp pk (letkis-chacha::poly1305-key-gen ck nonce))))

(defun aead-decryption (vec)
  (let ((key (hexdump-str-to-u8vec (get-value-for "  The ChaCha20 Key:" vec)))
        (ciphertext (hexdump-str-to-u8vec (get-value-for "  Ciphertext:" vec)))
        (nonce (hexdump-str-to-u8vec (get-value-for "  The nonce:" vec)))
        (aad (hexdump-str-to-u8vec (get-value-for "  The AAD:" vec)))
        (rcvd-tag (hexdump-str-to-u8vec (get-value-for "  Received Tag:" vec)))
        (plaintext (hexdump-str-to-u8vec (get-value-for "  Plaintext::" vec))))
    (parachute:is
     equalp
     plaintext
     (letkis-chacha:aead-chacha20-poly1305-decrypt
      key nonce (concatenate '(simple-array (unsigned-byte 8) 1) ciphertext rcvd-tag) aad))))

(parachute:define-test a-5-aead-decryption
  ;; These test vector values were derived from IETF RFC 8439. Please
  ;; reproduce this note if possible.
  (define-testvec-loop
      "  Test Vector #1:

  The ChaCha20 Key:
  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

  Ciphertext:
  000  64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd  d...u...`.b...C.
  016  5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2  ^.\.4\....g..l..
  032  4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0  Ll..u]C....N8-&.
  048  bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf  ...<2.....;.5X..
  064  33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81  3/..q......J....
  080  14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55  ...n..3.`....7.U
  096  97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38  ...n...a..2N+5.8
  112  36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4  6..{j|.....{S.g.
  128  b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9  ..lv{.MF..R.....
  144  90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e  .@...3\"^.....lR>
  160  af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a  .E4..?..[.Gq..Tj
  176  0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a  ..+..VN..B\"s.H'.
  192  0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e  ..1`S.v..U..1YCN
  208  ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10  ..NFm.Z.s.rv'.z.
  224  49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30  I....6...h..w.q0
  240  30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29  0[.......{qMlo,)
  256  a6 ad 5c b4 02 2b 02 70 9b                       ..\..+.p.

  The nonce:
  000  00 00 00 00 01 02 03 04 05 06 07 08              ............

  The AAD:
  000  f3 33 88 86 00 00 00 00 00 00 4e 91              .3........N.

  Received Tag:
  000  ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38  ...g...\"9#6....8

  Plaintext:
  000  49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20  Internet-Drafts
  016  61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65  are draft docume
  032  6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20  nts valid for a
  048  6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d  maximum of six m
  064  6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65  onths and may be
  080  20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63   updated, replac
  096  65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64  ed, or obsoleted
  112  20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65   by other docume
  128  6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e  nts at any time.
  144  20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72   It is inappropr
  160  69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65  iate to use Inte
  176  72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72  rnet-Drafts as r
  192  65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61  eference materia
  208  6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65  l or to cite the
  224  6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20  m other than as
  240  2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67  /...work in prog
  256  72 65 73 73 2e 2f e2 80 9d                       ress./..."
    :for (key ctxt nonce aad rcvd-tag plaintext)
      := (hexdump-get ("The ChaCha20 Key:" "Ciphertext:" "The nonce:"
                       "The AAD:" "Received Tag:" "Plaintext:"))
    :do (parachute:is
         equalp
         plaintext
         (letkis-chacha:aead-chacha20-poly1305-decrypt
          key nonce (concatenate '(simple-array (unsigned-byte 8) 1) ctxt rcvd-tag) aad))))
