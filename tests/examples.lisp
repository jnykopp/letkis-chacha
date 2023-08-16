(in-package :letkis-chacha/test)

;;; Copyright (c) 2023 Janne Nykopp. See file "LICENSE".

;;; ----------------------------------------------------------------------
;;; Some helpers.
(defun utf8-to-u8vec (str)
  "Convert STR (utf-8) to an array of unsigned bytes."
  (flexi-streams:string-to-octets str :external-format :utf-8))
(defun u8vec-to-utf8 (vec)
  "Convert an array of unsigned bytes VEC to a utf-8 string."
  (flexi-streams:octets-to-string vec :external-format :utf-8))

;;; ----------------------------------------------------------------------
;;; The RFC Standard defines a combination of Chacha20 cipher and
;;; Poly1305 MAC as Authenticated Encryption with Additional Data
;;; algorithm for encrypting and decrypting data. This is what you
;;; generally would use.
(defun aead-chacha-poly-encrypt (msg key nonce aad)
  "Sample convenience function for encrypting a utf-8 string MSG with
utf-8 string additional data AAD, using given binary arrays NONCE and
KEY."
  (check-type msg string)
  (check-type key (array (unsigned-byte 8) 1))   (assert (= (length key) 32))
  (check-type nonce (array (unsigned-byte 8) 1)) (assert (= (length nonce) 12))
  (check-type aad string)
  (letkis-chacha:aead-chacha20-poly1305-encrypt key nonce (utf8-to-u8vec msg) (utf8-to-u8vec aad)))

(defun aead-chacha-poly-decrypt (ciphertext tag key nonce aad)
  "Sample convenience function for decrypting. AAD can be a utf-8
string. Returns the decrypted message as a utf-8 string."
  (check-type ciphertext (array (unsigned-byte 8) 1))
  (check-type tag (array (unsigned-byte 8) 1))   (assert (= (length tag) 16))
  (check-type key (array (unsigned-byte 8) 1))   (assert (= (length key) 32))
  (check-type nonce (array (unsigned-byte 8) 1)) (assert (= (length nonce) 12))
  (check-type aad string)
  (u8vec-to-utf8
   (letkis-chacha:aead-chacha20-poly1305-decrypt
    key
    nonce
    (concatenate '(array (unsigned-byte 8) 1) ciphertext tag)
    (utf8-to-u8vec aad))))

(parachute:define-test aead-chacha-poly-encrypt-and-decrypt
  (let ((plaintext "Letkis maailmalla on, Letkis tanssi nuorison")
        (additional-data "Lyrics by Sauvo Puhtila")
        (key (str-to-u8vec "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f
                            10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"))
        (nonce (str-to-u8vec "12:34:56:78:9a:bc:de:f0:01:23:45:67")))
    (multiple-value-bind (combination ciphertext tag)
        (aead-chacha-poly-encrypt plaintext key nonce additional-data)
      (parachute:is equalp combination (concatenate '(array (unsigned-byte 8) 1) ciphertext tag))
      (parachute:is
       equalp
       #(26 250 149 197 77 235 213 44 82 160 53 15 254 235 109 226 183 174 200 3 24 67
         193 225 36 34 49 119 12 250 105 35 191 86 213 122 219 145 210 224 242 62 99 191)
       ciphertext)
      (parachute:is equalp #(14 104 44 139 16 99 122 80 240 207 26 130 252 6 39 125) tag)
      ;; Decrypt test
      (let ((deciphered (aead-chacha-poly-decrypt ciphertext tag key nonce additional-data)))
        (parachute:is string= plaintext deciphered)))))

;;; ----------------------------------------------------------------------
;;; RFC 8439 defines a one-time authenticator Poly1305 which is
;;; essentially a hash function. You may want to use it as standalone
;;; hash for whatever purposes, but make sure you understand the
;;; design's details! See RFC 8439 section 2.5 for further
;;; information. Also see section RFC 8439 section 2.6 and function
;;; `letkis-chacha:poly1305-key-gen' for Poly1305 key generation. Here
;;; we just feed it some random bytes.
(defun poly1305-hash (msg key)
  (check-type msg string)
  (check-type key (array (unsigned-byte 8) 1))
  (assert (= (length key) 32))
  (letkis-chacha:poly1305-mac (utf8-to-u8vec msg) key))

(parachute:define-test poly1305-hash-example
  ;; Example of a hash function using Poly1305 as the algorithm. KEY must
  ;; be an array of 32 octets (and unique, *including the clamping*, for
  ;; each application of the hash function if you desire to prevent forging
  ;; of hashes), and MSG can be a string of any length.
  (parachute:is
   equalp
   #(245 11 38 23 200 42 46 103 139 7 3 25 64 63 236 135)
   (poly1305-hash
    "Letkis täällä tunnetaan, Letkis meillä osataan"
    (str-to-u8vec "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8  ; r
                   01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b  ; s")))
  ;; NOTE! Due to clamping, this seemingly different key
  ;; (modifications in r-part) yields the same hash, as after clamping
  ;; they're identical. Beware!
  (parachute:is
   equalp
   #(245 11 38 23 200 42 46 103 139 7 3 25 64 63 236 135)
   (poly1305-hash
    "Letkis täällä tunnetaan, Letkis meillä osataan"
    (str-to-u8vec "85:d6:be:18:54:55:6d:f3:7e:44:52:0e:42:d5:06:c8  ; r
                   01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b  ; s")))
  ;; But when a minimal meaningful change is made to the key material,
  ;; we notice an avalanche effect in the hash.
  (parachute:is
   equalp
   #(195 121 130 21 88 190 67 236 243 170 175 195 52 108 78 197)
   (poly1305-hash
    "Letkis täällä tunnetaan, Letkis meillä osataan"
    (str-to-u8vec "84:d6:be:18:54:55:6d:f3:7e:44:52:0e:42:d5:06:c8  ; r
                   01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b  ; s"))))

;;; ----------------------------------------------------------------------
;;; NOTICE: the following tests/examples use the author's own key
;;; derivation function `letkis-chacha::chacha20-kdf' which is not a
;;; part of any of the RFCs. *Caveat emptor!*

(defun encode-msg (msg pw &optional aad)
  "Helper function to encode message MSG with password PW, optionally
using additional authenticated data AAD. All parameters are utf-8
strings. Return octet vector of salt and ciphertext."
  ;; Note: You can change the KDF work factor by rebinding
  ;; `letkis-chacha:*chacha20-kdf-iterations*'. Not necessary,
  ;; though. Here explicitly bound to the default value of 1000.
  ;;
  ;; Note2: On Raspberry Pi 3 and ECL, the key derivation is very slow
  ;; with 1000 iterations per step. For this combination (the test for
  ;; the combination is rather too broad, but it won't harm), set it
  ;; to much higher value.
  (let ((letkis-chacha:*chacha20-kdf-iterations* 1000)
        (letkis-chacha:*chacha20-kdf-timeout*
          (if (and (find :ecl *features*) (equalp (machine-type) "aarch64")
                   ;; Some tests in this file bind timeout to zero to
                   ;; test the signalling. This test for 0 timeout is
                   ;; here only to not mess with those tests.
                   (> letkis-chacha:*chacha20-kdf-timeout* 0))
              40
              letkis-chacha:*chacha20-kdf-timeout*)))
    (letkis-chacha:encode-octets (utf8-to-u8vec msg) (utf8-to-u8vec pw)
                                 (when aad (utf8-to-u8vec aad)))))

(defun decode-msg (iters-salt-and-ciphertext pw &optional aad)
  "Helper function to decode ITERS-SALT-AND-CIPHERTEXT (octet vector)
using password PW (utf-8 string) and optional AAD (utf-8
string). Assumes the plaintext is utf-8 string."
  ;; Note: On Raspberry Pi 3 and ECL, the key derivation is very slow
  ;; with 1000 iterations per step. For this combination (the test for
  ;; the combination is rather too broad, but it won't harm), set it
  ;; to much higher value.
  (let ((letkis-chacha:*chacha20-kdf-timeout*
          (if (and (find :ecl *features*) (equalp (machine-type) "aarch64"))
              40
              letkis-chacha:*chacha20-kdf-timeout*)))
    (u8vec-to-utf8 (letkis-chacha:decode-octets iters-salt-and-ciphertext (utf8-to-u8vec pw)
                                                (when aad (utf8-to-u8vec aad))))))

(parachute:define-test encode-decode-test-no-aad
  (let* ((plaintext "Ken letkassa kestä ei,
                     Sen varmaan pikku-hukka vei
                     Jenkkaamme letkaamaan
                     Ei heikkopäät saa tullakaan")
         (password "hunter2")
         (letkis-chacha:*letkis-random-fn* (constantly 23))
         (salt-and-ct (encode-msg plaintext password))
         (expected-salt-and-ct
           (coerce #(232 3 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23
                     23 23 23 23 23 23 23 23 62 90 90 201 254 88 207 102 199 41 208 57 214 221 216
                     106 239 239 51 155 62 0 32 214 218 193 154 178 170 106 235 236 159 161 217 59
                     253 18 225 105 110 234 143 252 200 146 229 85 39 45 218 23 67 215 43 247 220
                     169 170 1 33 101 128 145 18 24 26 179 180 102 96 20 213 84 201 107 92 12 23 225
                     43 32 184 195 137 125 31 90 120 5 169 142 107 221 203 107 154 232 247 151 64 34
                     105 164 81 149 226 159 188 86 15 74 163 25 227 227 251 39 54 240 243 182 49 225
                     161 41 15 108 156 231 84 227 244 172 243 36 83 95 75 69 163 28 20 223 164 238
                     161 51 31 73 128 128 56 26 202 202 137 196 182 253 114 255 248 27 167 208 109
                     190 6 101 211 161 183 88 2 206 133 87 78 43 249 18)
                   '(array (unsigned-byte 8) 1))))
    (parachute:is = 23 (funcall letkis-chacha:*letkis-random-fn* 255 nil))
    (parachute:is equalp expected-salt-and-ct salt-and-ct)
    (parachute:is string= plaintext (decode-msg expected-salt-and-ct password))
    (parachute:fail (decode-msg expected-salt-and-ct "*******"))
    (parachute:fail (decode-msg expected-salt-and-ct password "additional-data"))))

(parachute:define-test encode-decode-test-with-aad
  (let* ((plaintext "Letkis tanssi nuorison,
                     Letkis maailmalla on
                     Lentää valtamerten taa,
                     Siellä letkis on se joka valloittaa")
         (password "_______________swordfish_______________")
         (additional-data "Music by Rauno Lehtinen")
         (letkis-chacha:*letkis-random-fn* (constantly 44))
         (salt-and-ct (encode-msg plaintext password additional-data))
         (expected-salt-and-ct
           (coerce #(232 3 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44
                     44 44 44 44 44 44 44 44 11 245 212 163 204 32 42 148 82 100 80 189 252 117 26
                     131 119 137 188 188 246 144 151 66 120 77 124 200 202 195 203 222 121 1 137 49
                     190 186 9 38 81 59 163 4 44 86 172 60 67 159 7 181 34 241 112 213 141 58 147
                     163 32 247 148 254 16 216 207 58 107 130 231 60 18 28 29 149 212 122 5 154 111
                     236 187 28 227 221 85 73 77 19 223 145 93 8 186 27 67 199 3 208 120 151 130 235
                     203 59 187 75 147 114 216 7 165 73 177 179 128 79 83 166 9 34 100 216 17 29 113
                     130 174 60 234 38 208 186 160 48 101 78 90 139 189 174 166 127 74 253 131 117 2
                     35 184 252 109 196 23 252 231 3 35 9 153 105 223 182 43 211 106 132 117 139 169
                     196 14 226 205 113 72 14 55 72 50 164 144 137 168 243)
                   '(array (unsigned-byte 8) 1))))
    (parachute:is = 44 (funcall letkis-chacha:*letkis-random-fn* 255 nil))
    (parachute:is equalp expected-salt-and-ct salt-and-ct)
    (parachute:is string= plaintext (decode-msg expected-salt-and-ct password additional-data))
    (parachute:fail (decode-msg expected-salt-and-ct "Mary? Sturgeon? Haddock?" additional-data))
    (parachute:fail (decode-msg expected-salt-and-ct password "Music by Someone Else"))))

(parachute:define-test test-kdf-timeout-handling
  ;; This demonstrates how the `letkis-chacha::chacha20-kdf'
  ;; internally used by `encode-msg' and `decode-msg' may signal if
  ;; the derivation takes too long, and how to invoke specific
  ;; restarts in that case.
  (let ((letkis-chacha:*chacha20-kdf-timeout* 0)
        (msg "Testing") (pw "123")
        (letkis-chacha:*letkis-random-fn* (constantly 75))
        (result #(232 3 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75 75
                  75 75 75 75 75 75 75 109 141 255 175 83 149 223 125 88 108 235 1 183 182 130 63
                  124 195 111 220 226 156 162))
        (handler-bind-saw-signal nil))
    (parachute:fail (encode-msg msg pw) letkis-chacha:chacha20-kdf-timeout)
    (parachute:fail
        (handler-bind
            ((letkis-chacha:chacha20-kdf-timeout
               (lambda (e)
                 (setf handler-bind-saw-signal t)
                 (parachute:true (find-restart 'letkis-chacha:set-new-timeout e))
                 (parachute:true (find-restart 'letkis-chacha:run-unbound e)))))
          (encode-msg msg pw)))
    (parachute:true handler-bind-saw-signal)
    (parachute:is equalp result
                  (handler-bind ((letkis-chacha:chacha20-kdf-timeout
                                   (lambda (c)
                                     (declare (ignore c))
                                     (invoke-restart 'letkis-chacha:run-unbound))))
                    (encode-msg msg pw)))
    (parachute:is equalp result
                  (handler-bind ((letkis-chacha:chacha20-kdf-timeout
                                   (lambda (c)
                                     (declare (ignore c))
                                     (invoke-restart 'letkis-chacha::set-new-timeout 1000))))
                    (encode-msg msg pw)))))

;;; There are also functions for encoding and decoding files by name,
;;; but they are not tested here as those are just a thin layer on top
;;; of `letkis-chacha:encode-octets' and `letkis-chacha:decode-octets'.
