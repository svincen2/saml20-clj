(ns saml20-clj.shared-test
  (:require [expectations :refer [expect]]
            [saml20-clj.shared :as shared]))

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
 (shared/read-to-end (shared/str->inputstream test-string))
 test-string)

;; Testing xml parsing from a string.
(expect
 (shared/parse-xml-str test-xml)
 test-xml-response)

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
