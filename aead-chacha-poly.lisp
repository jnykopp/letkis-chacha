(in-package :letkis-chacha)

;;; Copyright (c) 2023 Janne Nykopp. See file "LICENSE".

;;; This AEAD Chacha20 Poly1305 implementation is straightforward
;;; translation of the pseudocode in IETF RFC 8439 and counts as
;;; derivative work. The derived parts in this work are marked with
;;; docstring or comment text "This code was derived from IETF RFC
;;; 8439. Please reproduce this note if possible." The pseudocode is
;;; published under the following license:
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

(defun %aead-chacha20-poly1305-tag (key nonce ct aad)
  "Compose AEAD Construction for Poly1305 from given KEY, NONCE, CT (can
be plaintext too) and AAD and return the matching tag.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (check-type key (array (unsigned-byte 8) 1))   (assert (= (length key) 32))
  (check-type nonce (array (unsigned-byte 8) 1)) (assert (= (length nonce) 12))
  (check-type ct (array (unsigned-byte 8) 1))
  (check-type aad (array (unsigned-byte 8) 1))
  (assert (< (length ct) 274877906881))
  (assert (< (length aad) (expt 2 64)))
  (let* ((one-time-key (poly1305-key-gen key nonce))
         (aad-len (length aad))  (ct-len (length ct))
         (aad-pad-len (logand (- 16 (mod aad-len 16)) 15))
         (ct-pad-len  (logand (- 16 (mod ct-len 16)) 15))
         (aead-construction (concatenate
                             '(simple-array (unsigned-byte 8) 1)
                             aad (%num-to-octets 0 aad-pad-len)
                             ct (%num-to-octets 0 ct-pad-len)
                             (%num-to-octets aad-len 8)
                             (%num-to-octets ct-len 8))))
    (poly1305-mac aead-construction one-time-key)))

(defun aead-chacha20-poly1305-encrypt (key nonce plaintext aad)
  "Encrypt given PLAINTEXT with given KEY, NONCE and AAD.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (check-type key (array (unsigned-byte 8) 1))   (assert (= (length key) 32))
  (check-type nonce (array (unsigned-byte 8) 1)) (assert (= (length nonce) 12))
  (check-type plaintext (array (unsigned-byte 8) 1))
  (check-type aad (array (unsigned-byte 8) 1))
  (assert (< (length plaintext) 274877906881))
  (let* ((ciphertext (chacha20-encrypt key 1 nonce plaintext))
         (tag (%aead-chacha20-poly1305-tag key nonce ciphertext aad)))
    (values (concatenate '(simple-array (unsigned-byte 8) 1) ciphertext tag)
            ciphertext
            tag)))

(defun aead-chacha20-poly1305-decrypt (key nonce ciphertext-plus-tag aad)
  "Decrypt given CIPHERTEXT-PLUS-TAG (octet vector with ciphertext
concatenated with 16 octet tag) with given KEY, NONCE and AAD. Note
that decryption isn't even attempted if tag is not valid.

This code was derived from IETF RFC 8439. Please reproduce this note
if possible."
  (check-type key (array (unsigned-byte 8) 1))   (assert (= (length key) 32))
  (check-type nonce (array (unsigned-byte 8) 1)) (assert (= (length nonce) 12))
  (check-type ciphertext-plus-tag (array (unsigned-byte 8) 1))
  (check-type aad (array (unsigned-byte 8) 1))
  (assert (> #1=(length ciphertext-plus-tag) 16))
  (let* ((ciphertext (subseq ciphertext-plus-tag 0 #2=(- #1# 16)))
         (tag (subseq ciphertext-plus-tag #2#))
         (reconstrued-tag (%aead-chacha20-poly1305-tag key nonce ciphertext aad)))
    (if (equalp reconstrued-tag tag)
        (chacha20-encrypt key 1 nonce ciphertext)
        (error "MAC mismatch!"))))
