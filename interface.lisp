(in-package :letkis-chacha)

;;; Copyright (c) 2023 Janne Nykopp. See file "LICENSE".

(defparameter *letkis-random-fn* (lambda (limit random-state) (random limit random-state))
  "Function to call to obtain random numbers. Needs to accept two
arguments like `random': limit and random-state.")

(defun encode-octets (pt-octets pw-octets &optional aad (iteration-count *chacha20-kdf-iterations*))
  "Encode plaintext PT-OCTETS with given password PW-OCTETS. Optional
AAD (additional authenticated data) can be given. Optional
ITERATION-COUNT can be used to determine KDF work factor. Return octet
array where first 2 octets are iteration count, next 12 octets are
salt octets, and rest are ciphertext."
  (check-type pt-octets (array (unsigned-byte 8) 1))
  (check-type pw-octets (array (unsigned-byte 8) 1))
  (check-type aad (or null (array (unsigned-byte 8) 1)))
  (check-type iteration-count fixnum)
  (assert (< 0 iteration-count #.(expt 2 16)))
  (let* ((rs (make-random-state t))
         (salt (coerce (loop :repeat 32 :collect (funcall *letkis-random-fn* 256 rs))
                       '(simple-array (unsigned-byte 8) 1)))
         (key-nonce (chacha20-kdf pw-octets salt iteration-count))
         (ciphertext (aead-chacha20-poly1305-encrypt
                      (subseq key-nonce 0 32)
                      (subseq key-nonce 32)
                      pt-octets
                      (if aad aad #.(coerce #() '(array (unsigned-byte 8) 1))))))
    (concatenate '(simple-array (unsigned-byte 8) 1)
                 (%num-to-octets iteration-count 2) salt ciphertext)))

(defun decode-octets (iters-salt-and-ct-octets pw-octets &optional aad)
  "Decode salt+plaintext ITERS-SALT-AND-CT-OCTETS (where first 2 octets
are iteration count, next 12 octets are salt and following octets the
ciphertext), with given password PW-OCTETS. Optional AAD (additional
authenticated data) must be given and must match exactly the AAD which
might have been given in encoding. Return plaintext octets."
  (check-type iters-salt-and-ct-octets (array (unsigned-byte 8) 1))
  (assert (>= (length iters-salt-and-ct-octets) 34))
  (check-type pw-octets (array (unsigned-byte 8) 1))
  (check-type aad (or null (array (unsigned-byte 8) 1)))
  (let* ((iteration-count (%octets-to-num (subseq iters-salt-and-ct-octets 0 2)))
         (salt (subseq iters-salt-and-ct-octets 2 34))
         (key-nonce (chacha20-kdf pw-octets salt iteration-count)))
    (aead-chacha20-poly1305-decrypt (subseq key-nonce 0 32)
                                    (subseq key-nonce 32)
                                    (subseq iters-salt-and-ct-octets 34)
                                    (if aad aad #.(coerce #() '(array (unsigned-byte 8) 1))))))

(defun encode-file (filename pw-octets &optional aad result-filename)
  "Encode plaintext in file FILENAME using password PW-OCTETS. Optional
AAD (additional authenticated data) can be given. If RESULT-FILENAME
is given and doesn't already exist, store the salt and ciphertext
combination there. Return the salt and ciphertext."
  (let* ((file-contents (%read-file-octets filename))
         (salt-and-ct (encode-octets file-contents pw-octets aad)))
    (when result-filename
      (%write-file-octets result-filename salt-and-ct))
    salt-and-ct))

(defun decode-file (filename pw-octets &optional aad result-filename)
  "Decode ciphertext in file FILENAME using password PW-OCTETS. Optional
AAD must be given and must match exactly the AAD which might have been
given in encoding. if RESULT-FILENAME is given and doesn't already
exist, store the plaintext there. Return the plaintext."
  (let* ((encrypted-file-contents (%read-file-octets filename))
         (plaintext (decode-octets encrypted-file-contents pw-octets aad)))
    (when result-filename
      (%write-file-octets result-filename plaintext))
    plaintext))
