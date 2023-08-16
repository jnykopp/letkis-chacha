;;;; letkis-chacha.asd

(asdf:defsystem #:letkis-chacha
  :description "Implementation of ChaCha20/Poly1306 algorithms."
  :author "Janne Nykopp <newcup@iki.fi>"
  :license  "BSD"
  :version "1.0.0"
  :serial t
  :depends-on (#:uiop #:alexandria
               #+sbcl #:sb-rotate-byte)
  :components ((:file "package")
               (:file "chacha20")
               (:file "utils")
               (:file "poly1305")
               (:file "aead-chacha-poly")
               (:file "interface")))

(asdf:defsystem #:letkis-chacha/test
  :depends-on (#:letkis-chacha #:parachute #:flexi-streams)
  :pathname "tests"
  :components ((:file "package")
               (:file "unit-tests")
               (:file "examples"))
  :perform (asdf:test-op (op c) (uiop:symbol-call :parachute :test :letkis-chacha/test)))
