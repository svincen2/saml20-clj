(ns saml20-clj.xml
  (:require [saml20-clj.encode-decode :as encode-decode])
  (:import [javax.xml.parsers DocumentBuilder DocumentBuilderFactory]
           org.w3c.dom.Document))

(defn document-builder
  ^DocumentBuilder []
  (.newDocumentBuilder
   (doto (DocumentBuilderFactory/newInstance)
     (.setNamespaceAware true)
     (.setFeature "http://xml.org/sax/features/external-parameter-entities" false)
     (.setFeature "http://apache.org/xml/features/nonvalidating/load-external-dtd" false)
     (.setExpandEntityReferences false))))

(defn str->xmldoc
  "Parse a string into an XML `Document`."
  ^Document [^String s]
  (let [document (document-builder)]
    (with-open [is (java.io.ByteArrayInputStream. (encode-decode/str->bytes s))]
      (.parse document is))))
