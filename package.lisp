(defpackage #:letkis-chacha
  (:use #:cl)
  (:export
   ;; Low-level interfaces
   #:chacha20-encrypt
   #:poly1305-mac
   #:poly1305-key-gen

   ;; AEAD interface
   #:aead-chacha20-poly1305-encrypt
   #:aead-chacha20-poly1305-decrypt

   ;; Error handling for high-level interfaces
   #:*chacha20-kdf-iterations*
   #:*chacha20-kdf-timeout*
   #:chacha20-kdf-timeout
   #:run-unbound
   #:set-new-timeout

   ;; High-level interfaces (Non-standard! See readme!)
   #:encode-octets
   #:decode-octets
   #:encode-file
   #:decode-file

   ;; For overriding random (used for obtaining salt in
   ;; high-level-interfaces)
   #:*letkis-random-fn*))
