(in-package :letkis-chacha)

;;; Copyright (c) 2023 Janne Nykopp. See file "LICENSE".

;;; This Poly1305 implementation is straightforward translation of the
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

(declaim (ftype (function ((unsigned-byte 128)) (unsigned-byte 128))
                %poly1305-clamp))
(defun %poly1305-clamp (r)
  "Clamp R to be appropriate. Return a clamped R.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (logand r #x0ffffffc0ffffffc0ffffffc0fffffff))

(declaim (ftype (function ((simple-array (unsigned-byte 8) 1) (simple-array (unsigned-byte 8) 1))
                          t)
                poly1305-mac))
(defun poly1305-mac (msg key)
  "Generate a 16 octet tag out of octet vectors MSG and KEY. MSG can
be of arbitrary length. KEY must be 32 octets long.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (assert (= (length key) 32))
  (let ((r (%poly1305-clamp (%octets-to-num (subseq key 0 16))))
        (s (%octets-to-num (subseq key 16)))
        (a 0)
        (p (- (ash 1 130) 5))
        (msg-len (length msg)))
    (loop :for i :from 1 :upto (ceiling msg-len 16)
          :for n := (%octets-to-num
                     (%cat-to-vec (subseq msg (* (1- i) 16) (min (* i 16) msg-len)) #x01))
          :do (setf a (+ a n))
              (setf  a (mod (* r a) p)))
    (%num-to-octets (mod (+ a s) (expt 2 128)) 16)))

(defun poly1305-key-gen (key nonce)
  "Poly1305 Key Generation.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (subseq (serialize-chacha-state (chacha20-block (make-chacha-state key 0 nonce))) 0 32))
