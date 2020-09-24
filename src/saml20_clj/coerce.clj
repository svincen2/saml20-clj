(ns saml20-clj.coerce
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [hiccup
             [core :as hiccup]
             [page :as h.page]]
            [saml20-clj
             [encode-decode :as encode-decode]
             [xml :as saml.xml]]))

;; these have to be initialized before using.
;;
;; TODO -- consider putting these in their own respective delays and deref inside relevant functions so init is done
;; when they are called rather than when namespace is evaluated.
(defonce ^:private -init
  (do
    ;; add BouncyCastle as a security provider.
    (java.security.Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.))
    ;; initialize OpenSAML
    (org.opensaml.core.config.InitializationService/initialize)
    ;; verify that OpenSAML has the crypto classes it needs
    (.init (org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer.))
    nil))

(defn keystore
  ^java.security.KeyStore [{:keys [keystore ^String filename ^String password]}]
  (or keystore
      (when (some-> filename io/as-file .exists)
        (with-open [is (io/input-stream filename)]
          (doto (java.security.KeyStore/getInstance "JKS")
            (.load is (.toCharArray password)))))))

(defmulti bytes->PrivateKey
  "Generate a private key from a byte array using the given `algorithm`.

    (bytes->PrivateKey my-byte-array :rsa) ;; -> ..."
  {:arglists '(^java.security.PrivateKey [^bytes key-bytes algorithm])}
  (fn [_ algorithm]
    (keyword algorithm)))

(defmethod bytes->PrivateKey :default
  [^bytes key-bytes algorithm]
  (.generatePrivate (java.security.KeyFactory/getInstance (str/upper-case (name algorithm)), "BC")
                    (java.security.spec.PKCS8EncodedKeySpec. key-bytes)))

(defprotocol CoerceToPrivateKey
  (->PrivateKey
    ^java.security.PrivateKey [this]
    ^java.security.PrivateKey [this ^String algorithm]
    "Coerce something such as a base-64-encoded string or byte array to a `PrivateKey`. This isn't used directly by
 OpenSAML -- the key must be passed as part of an OpenSAML `Credential`. See `->X509Credential`."))

;; I don't think we can use the "class name" of a byte array in `extend-protocol`
(extend-type (Class/forName "[B")
  CoerceToPrivateKey
  (->PrivateKey
    ([this]
     (->PrivateKey this :rsa))
    ([this algorithm]
     (bytes->PrivateKey this algorithm))))

(extend-protocol CoerceToPrivateKey
  nil
  (->PrivateKey
    ([_] nil)
    ([_ _] nil))

  String
  (->PrivateKey
    ([s] (->PrivateKey s :rsa))
    ([s algorithm] (->PrivateKey (encode-decode/base64-credential->bytes s) algorithm)))

  java.security.PrivateKey
  (->PrivateKey
    ([this] this)
    ([this _] this))

  org.opensaml.security.credential.Credential
  (->PrivateKey
    ([this]
     (.getPrivateKey this))
    ([this _]
     (->PrivateKey this)))

  clojure.lang.IPersistentMap
  (->PrivateKey
    ([{^String key-alias :alias, ^String password :password, :as m}]
     (when-let [keystore (keystore m)]
       (when-let [key (.getKey keystore key-alias (.toCharArray password))]
         (assert (instance? java.security.PrivateKey key))
         key)))
    ([this _]
     (->PrivateKey this))))

(defprotocol CoerceToX509Certificate
  (->X509Certificate ^java.security.cert.X509Certificate [this]
    "Coerce something such as a base-64-encoded string or byte array to a `java.security.cert.X509Certificate`. This
 class isn't used directly by OpenSAML; instead, certificate must be coerced to an OpenSAML `Credential`. See
`->X509Credential`."))

(extend-type (Class/forName "[B")
  CoerceToX509Certificate
  (->X509Certificate [this]
    (let [cert-factory (java.security.cert.CertificateFactory/getInstance "X.509")]
      (with-open [is (java.io.ByteArrayInputStream. this)]
        (.generateCertificate cert-factory is)))))

(extend-protocol CoerceToX509Certificate
  nil
  (->X509Certificate [_] nil)

  String
  (->X509Certificate [s]
    (->X509Certificate (encode-decode/base64-credential->bytes s)))

  java.security.cert.X509Certificate
  (->X509Certificate [this] this))

(defprotocol CoerceToX509Credential
  (->X509Credential
    ^org.opensaml.security.x509.X509Credential [this]
    ^org.opensaml.security.x509.X509Credential [public-key private-key]
    "Coerce something such as a byte array or base-64-encoded String to an OpenSAML `Credential`. `public-key` is anything
  that can be coerced to an `X509Certificate`; `private-key`, which is optional, is anything that can be coerced to a
  `PrivateKey`. Typically, you'd use the credential with just the public key for the IdP's credentials, for encrypting
  requests (in combination with SP credentails) or verifying signature(s) in the response. A credential with both
  public and private keys would typically contain *your* public and private keys, for encrypting requests (in
  combination with IdP credentials) or for decrypting encrypted assertions in the response."))

(extend-protocol CoerceToX509Credential
  nil
  (->X509Credential
    ([_] nil)
    ([_ _] nil))

  Object
  (->X509Credential
    ([public-key]
     (->X509Credential public-key nil))
    ([public-key private-key]
     (let [cert (->X509Certificate public-key)]
       (if private-key
         (org.opensaml.security.x509.BasicX509Credential. cert (->PrivateKey private-key))
         (org.opensaml.security.x509.BasicX509Credential. cert)))))

  clojure.lang.IPersistentMap
  (->X509Credential
    ([{^String key-alias :alias, ^String password :password, :as m}]
     (when (and key-alias password)
       (when-let [keystore (keystore m)]
         (org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter. keystore key-alias (.toCharArray password)))))
    ([m private-key]
     (let [credential (->X509Credential m)
           cert       (.getEntityCertificate credential)]
       (->X509Credential cert private-key))))

  clojure.lang.IPersistentVector
  (->X509Credential [[public-key private-key]]
    (->X509Credential public-key private-key)))

(defprotocol SerializeXMLString
  (->xml-string [this]))

(extend-protocol SerializeXMLString
  nil
  (->xml-string [_] nil)

  String
  (->xml-string [this] this)

  clojure.lang.IPersistentVector
  (->xml-string [this]
    (str
     (h.page/xml-declaration "UTF-8")
     (hiccup/html this))))

(defprotocol CoerceToElement
  (->Element ^org.w3c.dom.Element [this]))

(extend-protocol CoerceToElement
  nil
  (->Element [_] nil)

  org.w3c.dom.Element
  (->Element [this] this)

  org.w3c.dom.Document
  (->Element [this]
    (.getDocumentElement this))

  org.opensaml.core.xml.XMLObject
  (->Element [this]
    (->Element (.marshall (.getMarshaller (org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport/getMarshallerFactory)
                                          this)
                          this)))

  String
  (->Element [this]
    (saml.xml/str->xmldoc this))

  ;; hiccup-style xml element
  ;; TODO -- it's a little inefficient to serialize this to a string and then back to an element
  clojure.lang.IPersistentVector
  (->Element [this]
    (->Element (->xml-string this))))

(defprotocol CoerceToSAMLObject
  (->SAMLObject ^org.opensaml.saml.common.SignableSAMLObject [this]))

(extend-protocol CoerceToSAMLObject
  nil
  (->SAMLObject [_] nil)

  org.opensaml.saml.common.SignableSAMLObject
  (->SAMLObject [this] this)

  org.w3c.dom.Element
  (->SAMLObject [this]
    (let [unmarshaller-factory (org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport/getUnmarshallerFactory)
          unmarshaller         (.getUnmarshaller unmarshaller-factory this)]
      (.unmarshall unmarshaller this)))

  org.w3c.dom.Element
  (->SAMLObject [this]
    (let [unmarshaller-factory (org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport/getUnmarshallerFactory)
          unmarshaller         (.getUnmarshaller unmarshaller-factory this)]
      (.unmarshall unmarshaller this)))

  Object
  (->SAMLObject [this]
    (->SAMLObject (->Element this))))

(defprotocol CoerceToResponse
  (->Response ^org.opensaml.saml.saml2.core.Response [this]))

(extend-protocol CoerceToResponse
  nil
  (->Response [_] nil)

  org.opensaml.saml.saml2.core.Response
  (->Response [this] this)

  org.opensaml.saml.common.SignableSAMLObject
  (->Response [this]
    (throw (ex-info (format "Don't know how to coerce a %s to a Response" (.getCanonicalName (class this)))
                    {:object this})))

  Object
  (->Response [this]
    (->Response (->SAMLObject this))))

(defprotocol CoerceToDecrypter
  (->Decrypter ^org.opensaml.saml.saml2.encryption.Decrypter [this]))

(extend-protocol CoerceToDecrypter
  nil
  (->Decrypter [_] nil)

  org.opensaml.saml.saml2.encryption.Decrypter
  (->Decrypter [this] this)

  org.opensaml.security.x509.X509Credential
  (->Decrypter [credential]
    (when (.getPrivateKey credential)
      (org.opensaml.saml.saml2.encryption.Decrypter.
       nil
       (org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver. credential)
       ;; these resolvers are chained together so OpenSAML can look in different places around the assertion to find
       ;; the encryption key.
       (org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver.
        (list (org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver.)
              (org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver.)
              (org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver.)
              (org.opensaml.xmlsec.encryption.support.SimpleKeyInfoReferenceEncryptedKeyResolver.))))))

  Object
  (->Decrypter [this]
    (->Decrypter (->X509Credential this))))
