(ns saml20-clj.sp.response
  "Code for parsing the XML response (as a String)from the IdP to an OpenSAML `Response`, and for basic operations like
  validating the signature and reading assertions."
  (:require [clj-time.coerce :as c.coerce]
            [clojure.tools.logging :as log]
            [saml20-clj
             [shared :as shared]
             [xml :as saml-xml]])
  (:import [org.opensaml.saml.saml2.core Assertion Attribute AttributeStatement Audience AudienceRestriction
            EncryptedAssertion Response SubjectConfirmation]
           org.opensaml.saml.saml2.encryption.Decrypter))

(defn xml-string->saml-resp
  "Parses a SAML response (XML string) from IdP and returns the corresponding (Open)SAML Response object"
  ^Response [^String xml-string]
  (let [xmldoc               (.getDocumentElement (saml-xml/str->xmldoc xml-string))
        unmarshaller-factory (org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport/getUnmarshallerFactory)
        unmarshaller         (.getUnmarshaller unmarshaller-factory xmldoc)]
    (.unmarshall unmarshaller xmldoc)))

(defn parse-saml-resp-status
  "Parses and returns information about the status (i.e. successful or not), the version, addressing info etc. of the
  SAML response

  Check the javadoc of OpenSAML at:

  https://build.shibboleth.net/nexus/service/local/repositories/releases/archive/org/opensaml/opensaml/2.5.3/opensaml-2.5.3-javadoc.jar/!/index.html"
  [^Response saml-resp]
  (let [status (.. saml-resp getStatus getStatusCode getValue)]
    {:inResponseTo (.getInResponseTo saml-resp)
     :status       status
     :success?     (= status org.opensaml.saml.saml2.core.StatusCode/SUCCESS)
     :version      (.. saml-resp getVersion toString)
     :issueInstant (c.coerce/to-timestamp (.getIssueInstant saml-resp))
     :destination  (.getDestination saml-resp)}))

;; http://kevnls.blogspot.gr/2009/07/processing-saml-in-java-using-opensaml.html
;; http://stackoverflow.com/questions/9422545/decrypting-encrypted-assertion-using-saml-2-0-in-java-using-opensaml
(defn parse-saml-assertion
  "Returns the attributes and the 'audiences' for the given SAML assertion"
  [^Assertion assertion]
  (let [statements                (.getAttributeStatements assertion)
        subject                   (.getSubject assertion)
        subject-confirmation-data (.getSubjectConfirmationData ^SubjectConfirmation (first (.getSubjectConfirmations subject)))
        name-id                   (.getNameID subject)
        attrs                     (into {} (for [^AttributeStatement statement statements
                                                 ^Attribute attribute          (.getAttributes statement)]
                                             [(shared/saml2-attr->name (.getName attribute)) ; Or (.getFriendlyName a) ??
                                              (map #(-> ^org.opensaml.core.xml.XMLObject % .getDOM .getTextContent)
                                                   (.getAttributeValues attribute))]))
        audiences                 (for [^AudienceRestriction restriction (-> assertion .getConditions .getAudienceRestrictions)
                                        ^Audience audience               (.getAudiences restriction)]
                                    (.getAudienceURI audience))]
    {:attrs        attrs
     :audiences    audiences
     :name-id      {:value  (some-> name-id .getValue)
                    :format (some-> name-id .getFormat)}
     :confirmation {:in-response-to  (.getInResponseTo subject-confirmation-data)
                    :not-before      (c.coerce/to-timestamp (.getNotBefore subject-confirmation-data))
                    :not-on-or-after (c.coerce/to-timestamp (.getNotOnOrAfter subject-confirmation-data))
                    :recipient       (.getRecipient subject-confirmation-data)}}))

(defn saml-resp->assertions
  "Returns the assertions (encrypted or not) of a SAML Response object"
  [^Response saml-resp ^Decrypter decrypter]
  (let [assertions (concat (.getAssertions saml-resp)
                           (when decrypter
                             (map #(.decrypt decrypter ^EncryptedAssertion %)
                                  (.getEncryptedAssertions saml-resp))))
        props      (map parse-saml-assertion assertions)]
    (assoc (parse-saml-resp-status saml-resp)
           :assertions props)))

(defn validate-saml-response-signature
  "Checks (if exists) the signature of SAML Response given the IdP certificate"
  [^Response saml-resp ^String idp-cert]
  (when-let [signature (.getSignature saml-resp)]
    (let [public-creds (org.opensaml.security.x509.BasicX509Credential. (shared/certificate-x509 idp-cert))]
      (try
        (org.opensaml.xmlsec.signature.support.SignatureValidator/validate signature public-creds)
        true
        (catch org.opensaml.xmlsec.signature.support.SignatureException e
          (log/error e "Signature NOT valid")
          false)))))
