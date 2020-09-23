(ns saml20-clj.sp.factories
  (:require [saml20-clj
             [shared :as shared]
             [xml :as saml-xml]])
  (:import javax.xml.crypto.dsig.XMLSignature
           org.apache.xml.security.c14n.Canonicalizer
           org.apache.xml.security.transforms.Transforms
           [org.apache.xml.security.utils Constants ElementProxy]
           org.opensaml.saml.saml2.encryption.Decrypter))

(defn make-saml-signer
  "Create a function for signing SAML requests. Given keystore information, returns a function with the signature

    (f xml-string) -> signature-string"
  [keystore-filename ^String keystore-password key-alias & {:keys [algorithm], :or {algorithm :sha1}}]
  (when keystore-filename
    (ElementProxy/setDefaultPrefix Constants/SignatureSpecNS "")
    (let [ks          (shared/load-key-store keystore-filename keystore-password)
          private-key (.getKey ks key-alias (.toCharArray keystore-password))
          cert        (shared/x509-certificate-from-keystore ks key-alias)
          sig-algo    (if (= (.getAlgorithm private-key) "DSA")
                        (case algorithm
                          :sha256 org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_DSA_SHA256
                          org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_DSA)
                        (case algorithm
                          :sha256 org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_RSA_SHA256
                          org.apache.xml.security.signature.XMLSignature/ALGO_ID_SIGNATURE_RSA))]
      ;; https://svn.apache.org/repos/asf/santuario/xml-security-java/trunk/samples/org/apache/xml/security/samples/signature/CreateSignature.java
      ;; http://stackoverflow.com/questions/2052251/is-there-an-easier-way-to-sign-an-xml-document-in-java
      ;; Also useful: http://www.di-mgt.com.au/xmldsig2.html
      (fn sign-xml-doc [^String xml-string]
        (let [xmldoc        (saml-xml/str->xmldoc xml-string)
              transforms    (doto (Transforms. xmldoc)
                              (.addTransform Transforms/TRANSFORM_ENVELOPED_SIGNATURE)
                              (.addTransform Transforms/TRANSFORM_C14N_EXCL_OMIT_COMMENTS))
              sig           (org.apache.xml.security.signature.XMLSignature. xmldoc nil sig-algo
                                                                             Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
              canonicalizer (Canonicalizer/getInstance Canonicalizer/ALGO_ID_C14N_EXCL_OMIT_COMMENTS)]
          (.. xmldoc
              (getDocumentElement)
              (appendChild (.getElement sig)))
          (doto sig
            (.addDocument "" transforms Constants/ALGO_ID_DIGEST_SHA1)
            (.addKeyInfo cert)
            (.addKeyInfo (.getPublicKey cert))
            (.sign private-key))
          (with-open [os (java.io.ByteArrayOutputStream.)]
            (.canonicalizeSubtree canonicalizer xmldoc os)
            (.toString os "UTF-8")))))))

(defn make-saml-decrypter
  ^org.opensaml.saml.saml2.encryption.Decrypter [^String idp-cert keystore-filename ^String keystore-password ^String key-alias]
  (when keystore-filename
    (let [ks              (shared/load-key-store keystore-filename keystore-password)
          private-key     (.getKey ks key-alias (.toCharArray keystore-password))
          decryption-cred (org.opensaml.security.x509.BasicX509Credential. idp-cert private-key)]
      (org.opensaml.saml.saml2.encryption.Decrypter.
       nil
       (org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver. decryption-cred)
       (org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver.)))))
