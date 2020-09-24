(ns saml20-clj.crypto
  (:require [saml20-clj.coerce :as coerce])
  (:import org.opensaml.xmlsec.signature.support.SignatureConstants))

(def signature-algorithms
  {:dsa   {nil     SignatureConstants/ALGO_ID_SIGNATURE_DSA
           :sha1   SignatureConstants/ALGO_ID_SIGNATURE_DSA_SHA1
           :sha256 SignatureConstants/ALGO_ID_SIGNATURE_DSA_SHA256}
   :rsa   {nil        SignatureConstants/ALGO_ID_SIGNATURE_RSA
           :sha1      SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA1
           :ripemd160 SignatureConstants/ALGO_ID_SIGNATURE_RSA_RIPEMD160
           :sha256    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA256
           :sha224    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA224
           :sha384    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA384
           :sha512    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA512}
   :ecdsa {:sha1   SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA1
           :sha224 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA224
           :sha256 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA256
           :sha384 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA384
           :sha512 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA512}})

(def canonicalization-algorithms
  {:omit-comments      SignatureConstants/ALGO_ID_C14N_OMIT_COMMENTS
   :with-comments      SignatureConstants/ALGO_ID_C14N_WITH_COMMENTS
   :excl-omit-comments SignatureConstants/ALGO_ID_C14N_EXCL_OMIT_COMMENTS
   :excl-with-comments SignatureConstants/ALGO_ID_C14N_EXCL_WITH_COMMENTS})

(defn sign ^org.w3c.dom.Node [credential object & {:keys [signature-algorithm
                                                          canonicalization-algorithm]
                                                   :or   {signature-algorithm        [:rsa :sha256]
                                                          canonicalization-algorithm :excl-omit-comments}}]
  (when-let [object (coerce/->SAMLObject object)]
    (when-let [credential (coerce/->Credential credential)]
      (let [signature (doto (.buildObject (org.opensaml.xmlsec.signature.impl.SignatureBuilder.))
                        (.setSigningCredential credential)
                        (.setSignatureAlgorithm (or (get-in signature-algorithms signature-algorithm)
                                                    (throw (ex-info "No matching signature algorithm"
                                                                    {:algorithm signature-algorithm}))))
                        (.setCanonicalizationAlgorithm (or (get canonicalization-algorithms canonicalization-algorithm)
                                                           (throw (ex-info "No matching canonicalization algorithm"
                                                                           {:algorithm canonicalization-algorithm})))))]
        (.setSignature object signature)
        (let [element (coerce/->Element object)]
          (org.opensaml.xmlsec.signature.support.Signer/signObject signature)
          element)))))

(defn decrypt! [sp-private-key element]
  (when-let [sp-private-key (coerce/->PrivateKey sp-private-key)]
    (when-let [element (coerce/->Element element)]
      (com.onelogin.saml2.util.Util/decryptElement element sp-private-key))))

(defn recursive-decrypt! [sp-private-key element]
  (when-let [sp-private-key (coerce/->PrivateKey sp-private-key)]
    (when-let [element (coerce/->Element element)]
      (when (= (.getNodeName element) "saml:EncryptedAssertion")
        (decrypt! sp-private-key element))
      (doseq [i     (range (.. element getChildNodes getLength))
              :let  [child (.. element getChildNodes (item i))]
              :when (instance? org.w3c.dom.Element child)]
        (recursive-decrypt! sp-private-key child)))))
