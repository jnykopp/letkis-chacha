(in-package :letkis-chacha)

;;; Copyright (c) 2023 Janne Nykopp. See file "LICENSE".

(declaim (ftype (function ((simple-array (unsigned-byte 8) 1)) (integer 0 *))
                %octets-to-num))
(defun %octets-to-num (octets)
  "Return given network-endian OCTETS as an integer."
  (loop :for o :across octets
        :for e :from 0
        :summing (* (expt 256 e) o)))

(declaim (ftype (function ((integer 0 *) &optional (integer 0 *))
                          (simple-array (unsigned-byte 8) 1))
                %num-to-octets))
(defun %num-to-octets (num &optional desired-len)
  "Return given integer NUM as network-endian octet vector. If
DESIRED-LEN is given, make the octet vector exactly that many octets
long by padding tail with zeros. Errors if NUM doesn't fit given
DESIRED-LEN."
  (let* ((bytes (loop :with n := num
                      :while (> n 0)
                      :collect (mod n 256)
                      :do (setf n (ash n -8))))
         (blen (length bytes))
         (pad (when (and desired-len (> desired-len blen))
                (loop :for i :from blen :below desired-len :collect 0))))
    (when (and desired-len (> blen desired-len))
      (error "~d requires ~d octets; ~d requested" num blen desired-len))
    (concatenate `(simple-array (unsigned-byte 8) (,(or desired-len blen))) bytes pad)))

(declaim (ftype (function ((simple-array (unsigned-byte 8) 1) &rest (unsigned-byte 8))
                          (simple-array (unsigned-byte 8) 1))
                %cat-to-vec))
(defun %cat-to-vec (vec &rest values)
  "Concatenate VALUES to tail of octet vector VEC. Return a new
vector."
  (apply #'concatenate '(simple-array (unsigned-byte 8) 1) (list vec values)))

(defun %read-file-octets (filename)
  (with-open-file (in filename :element-type '(unsigned-byte 8))
    (apply #'concatenate '(simple-array (unsigned-byte 8) 1)
           (loop :for buf := (make-array #1=(* 8 1024) :element-type '(unsigned-byte 8))
                 :for r := (read-sequence buf in)
                 :collect (subseq buf 0 (min r #1#))
                 :while (>= r #1#)))))

(defun %write-file-octets (filename vec)
  (with-open-file (out filename :element-type '(unsigned-byte 8)
                                :direction :output :if-does-not-exist :create)
    (write-sequence vec out)))
