(ns saml20-clj.shared-test
  (:require [expectations :refer [expect]]
            [saml20-clj.shared :as shared])
  (:import java.security.PublicKey
           org.apache.commons.io.IOUtils))

(def ^:private test-string
  "Th1s 15 50m3 s7r1ng w17h 13773r5 and numb3rs!")

(def ^:private test-xml
  "<tag1 hasmore=\"1\"><tag2 hasmore=\"1\"><tag3>foobar</tag3></tag2><tag4>inter arma enim silent leges</tag4></tag1>")

(def ^:private test-xml-response
  [{:tag     :tag1
    :attrs   {:hasmore "1"}
    :content [{:tag     :tag2
               :attrs   {:hasmore "1"}
               :content [{:tag     :tag3
                          :attrs   nil
                          :content ["foobar"]}]}
              {:tag     :tag4
               :attrs   nil
               :content ["inter arma enim silent leges"]}]}
   nil])

;; Testing string to stream and stream to string transformations.
(expect
 test-string
 (shared/bytes->str (IOUtils/toByteArray (shared/str->inputstream test-string))))

;; Testing xml parsing from a string.
(expect
 test-xml-response
 (shared/parse-xml-str test-xml))

;; make sure conversion to/from base 64 works as expected
(expect
 "QUJDREVG"
 (shared/str->base64 "ABCDEF"))

(expect
 "ABCDEF"
 (shared/base64->str "QUJDREVG"))

;; make sure conversion to/from base 64 w/ DEFLATE compression works as expected
(expect
 "c3RydnF1AwA="
 (shared/str->deflate->base64 "ABCDEF"))

(expect
 "ABCDEF"
 (shared/base64->inflate->str "c3RydnF1AwA="))

;; we should be able to decode base-64 stuff that contains newlines in it
(expect
 "ABCDEF"
 (shared/base64->inflate->str "c3Ry\ndnF1\r\nAwA="))

(expect
 "ABCDEF"
 (shared/base64->str "QUJDR\nEV\r\nG"))

;; make sure we can encode string -> bytes -> hex
(expect
 "41424358595a"
 (-> "ABCXYZ" shared/str->bytes shared/bytes->hex))

(def ^:private test-certificate-string
  "MIIDsjCCApqgAwIBAgIGAWtM1OOxMA0GCSqGSIb3DQEBCwUAMIGZMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxGjAYBgNVBAMMEW1ldGFiYXNlLXZpY3RvcmlhMRwwGgYJKoZI
hvcNAQkBFg1pbmZvQG9rdGEuY29tMB4XDTE5MDYxMjE3NTQ0OFoXDTI5MDYxMjE3NTU0OFowgZkx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv
MQ0wCwYDVQQKDARPa3RhMRQwEgYDVQQLDAtTU09Qcm92aWRlcjEaMBgGA1UEAwwRbWV0YWJhc2Ut
dmljdG9yaWExHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCJNDIHd05aBXALoQStEvErsnJZDx1PIHTYGDY30SGHad8vXANg+tpThny3
ZMmGx8j3tDDwjsijPa8SQtL8I8GrTKO1h2zqM+3sKrgyLk6fcXnKWBqbFx9gpqz9bRxT76WKYTxV
3t71GtVb8fSfns1fv3u3thsUADDcJmOK65snwirtahie61IDIvoRxMIInu26kw1gCFtOcidoY0yL
RhGgaMjgGYOd2auW5A7bQV9kxePLg8o8rU+KXhTbuHJg0dgW8gVNAv5IKEQQ1VZNTjALR+N6Mca1
p0tuofEVggkA7x9t0O+xWXxUrbSs9C1DxKkxF4xI0z8M/ocqdtwPxNP5AgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAIO5cVa/P50nXuXaMK/klblZ+1MFbJ8Ti86TSPcdnxYO8nbWwQuUwKKuRHf6y5li
7ctaeXhMfyx/rGsYH4TDgzZhpZmGgZmAKGohDH4YxHctqyxNpRPwJe2kIkJN5yEqLUPNwqm2I7Dw
PcmkewOYEf71Y/sBF0/vRJev5n3upo2nW9RzUz9ptAtWn7EoLsN+grcohJpygj7jiJmbicxblNqF
uvuZkzz+X+qt2W/1mbVDyuIwsvUQOeRbpM+xv11dxheLRKt3kB8Gf6kqd8EjBtHmMFL8s4fdHyfM
eRzAWU6exmsx49oEvw5LrBSTJ97ekvVFfrEASyd96sgeV2Nl0No=")

;; make sure we can parse a certificate
(expect
 PublicKey
 (shared/jcert->public-key (shared/certificate-x509 test-certificate-string)))
