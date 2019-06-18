(ns saml20-clj.xml
  (:require [hiccup
             [core :as h.core]
             [page :as h.page]]
            [saml20-clj.shared :as saml-shared])
  (:import [javax.xml.crypto.dsig XMLSignature XMLSignatureFactory]
           javax.xml.crypto.dsig.dom.DOMValidateContext
           javax.xml.crypto.KeySelector
           [javax.xml.parsers DocumentBuilder DocumentBuilderFactory]
           org.apache.xml.security.c14n.Canonicalizer
           [org.w3c.dom Document Node]))

(defn make-xml-string
  "Creates an XML string using hiccup."
  [structure]
  (str
   (h.page/xml-declaration "UTF-8")
   (h.core/html structure)))

(defn singleton-key-selector
  "Always uses a provided key as a selector."
  [jkey]
  (KeySelector/singletonKeySelector jkey))

(defn document-builder
  ^DocumentBuilder []
  (let [doc (DocumentBuilderFactory/newInstance)]
    (.setNamespaceAware doc true)
    (.setFeature doc "http://xml.org/sax/features/external-parameter-entities" false)
    (.setFeature doc "http://apache.org/xml/features/nonvalidating/load-external-dtd" false)
    (.setExpandEntityReferences doc false)
    (.newDocumentBuilder doc)))

(defn xml-signature-factory
  ^XMLSignatureFactory []
  (XMLSignatureFactory/getInstance "DOM"))

(defn str->xmldoc
  ^Document [^String parsable-str]
  (let [document (document-builder)]
    (.parse document (saml-shared/str->inputstream parsable-str))))

(defn xmlsig-from-xmldoc
  [^Document xmldoc]
  (let [nodes (.getElementsByTagNameNS xmldoc XMLSignature/XMLNS "Signature")]
    ;; Zero nodes means that we can't find a XML signature.
    (when (pos? (.getLength nodes))
      ;; Take the first node.
      (.item nodes 0))))

(defn get-dom-context
  ^DOMValidateContext [^KeySelector key-selector, ^Node signature-node]
  (DOMValidateContext. key-selector signature-node))

(defn validate-xml-signature
  "Checks if this XML document's signature is valid using the supplied certificate"
  [xml-string cert-string]
  (let [sig-factory        (xml-signature-factory)
        public-key         (saml-shared/jcert->public-key (saml-shared/certificate-x509 cert-string))
        xmldoc             (str->xmldoc xml-string)
        xml-sig-node       (xmlsig-from-xmldoc xmldoc)
        validate-signature #(let [context   (get-dom-context (singleton-key-selector public-key) xml-sig-node)
                                  signature (.unmarshalXMLSignature sig-factory context)]
                              (.validate signature context))]
    (if xml-sig-node (validate-signature)
        true)))

(defn dom-node->str
  ^String [^Node dom-node]
  (let [canonicalizer (Canonicalizer/getInstance Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)]
    (String. (.canonicalizeSubtree canonicalizer dom-node))))
