(ns saml20-clj.sp.request
  (:require [clj-time
             [core :as c.time]
             [format :as c.format]]
            [clojure.string :as str]
            [hiccup
             [core :as hiccup]
             [page :as h.page]]
            [ring.util.codec :as codec]
            [saml20-clj
             [coerce :as coerce]
             [encode-decode :as encode-decode]]))

;;; -------------------------------------------- Storing state in memory ---------------------------------------------

;; TODO -- rework all this code so it's not so wacky

(defn ^:deprecated bump-saml-id-timeout!
  "Sets the current time to the provided saml-id in the saml-id-timeouts ref map.
  This function has side-effects."
  [saml-id-timeouts saml-id issue-instant]
  (dosync (alter saml-id-timeouts assoc saml-id issue-instant)))

(defn ^:deprecated next-saml-id!
  "Returns the next available saml id."
  [saml-last-id]
  (swap! saml-last-id inc))

(defn ^:deprecated time-since
  [time-span]
  (c.time/minus (c.time/now) time-span))

(defn ^:deprecated make-timeout-filter-fn
  "Creates a function for clojure.core/filter to keep all dates after
  a given date."
  [timespan]
  (fn [i]
    (c.time/after? (second i) (time-since timespan))))

(defn ^:deprecated prune-timed-out-ids!
  "Given a timeout duration, remove all SAML IDs that are older than now minus the timeout."
  [saml-id-timeouts timeout-duration]
  (let [filter-fn
        (partial filter (make-timeout-filter-fn timeout-duration))]
    (dosync
     (ref-set saml-id-timeouts (into {} (filter-fn @saml-id-timeouts))))))


;;; ----------------------------------------------- Creating requests ------------------------------------------------

;; TODO -- make this parameterized.
(defn metadata ^String [app-name acs-uri certificate-str]
  (coerce/->xml-string
   [:md:EntityDescriptor {:xmlns:md "urn:oasis:names:tc:SAML:2.0:metadata"
                          :ID       (str/replace acs-uri #"[:/]" "_")
                          :entityID app-name}
    [:md:SPSSODescriptor {:AuthnRequestsSigned        "true"
                          :WantAssertionsSigned       "true"
                          :protocolSupportEnumeration "urn:oasis:names:tc:SAML:2.0:protocol"}
     [:md:KeyDescriptor  {:use "signing"}
      [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
       [:ds:X509Data
        [:ds:X509Certificate certificate-str]]]]
     [:md:KeyDescriptor  {:use "encryption"}
      [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
       [:ds:X509Data
        [:ds:X509Certificate certificate-str]]]]
     [:md:SingleLogoutService {:Binding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                               :Location "https://example.org/saml/SingleLogout"}]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"]
     [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"]
     [:md:AssertionConsumerService {:Binding   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                    :Location  acs-uri
                                    :index     "0"
                                    :isDefault "true"}]]]))

(defn create-request
  "Return XML elements that represent a SAML 2.0 auth request."
  [time-issued saml-service-name saml-id acs-url idp-uri]
  (str
    (h.page/xml-declaration "UTF-8")
    (hiccup/html
      [:samlp:AuthnRequest
       {:xmlns:samlp                 "urn:oasis:names:tc:SAML:2.0:protocol"
        :ID                          saml-id
        :Version                     "2.0"
        :IssueInstant                time-issued
        :ProtocolBinding             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        :ProviderName                saml-service-name
        :IsPassive                   false
        :Destination                 idp-uri
        :AssertionConsumerServiceURL acs-url}
       [:saml:Issuer
        {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"}
        saml-service-name]
       ;;[:samlp:NameIDPolicy {:AllowCreate false :Format saml-format}]
       ])))

(defn ^:private secure-random-bytes
  (^bytes [size]
   (let [ba (byte-array size)
         r  (java.security.SecureRandom.)]
     (.nextBytes r ba)
     ba))
  (^bytes []
   (secure-random-bytes 20)))

(defn new-secret-key-spec ^javax.crypto.spec.SecretKeySpec []
  (javax.crypto.spec.SecretKeySpec. (secure-random-bytes) "HmacSHA1"))

;; TODO -- replace "`reate-request-factory` with a simple `request` function that takes the relevant stuff like
;; `secret-key-spec` as an options map and let the application deal with storing it somewhere.
(defn ^:deprecated generate-mutables
  []
  {:saml-id-timeouts (ref {})
   :saml-last-id     (atom 0)
   :secret-key-spec  (new-secret-key-spec)})

(def ^:deprecated ^:private instant-format (c.format/formatters :date-time-no-ms))

(defn- ^:deprecated make-issue-instant
  "Converts a date-time to a SAML 2.0 time string."
  [ii-date]
  (c.format/unparse instant-format ii-date))

(defn ^:deprecated create-request-factory
  "Creates new requests for a particular service, format, and acs-url."
  ([mutables idp-uri saml-service-name acs-url]
   (create-request-factory
    #(str "_" (next-saml-id! (:saml-last-id mutables)))
    (partial bump-saml-id-timeout! (:saml-id-timeouts mutables))
    (:xml-signer mutables)
    idp-uri saml-service-name acs-url))

  ([next-saml-id-fn! bump-saml-id-timeout-fn! xml-signer idp-uri saml-service-name acs-url]
   (fn request-factory []
     (let [current-time  (c.time/now)
           new-saml-id   (next-saml-id-fn!)
           issue-instant (make-issue-instant current-time)
           new-request   (create-request issue-instant
                                         saml-service-name
                                         new-saml-id
                                         acs-url
                                         idp-uri)]
       (bump-saml-id-timeout-fn! new-saml-id current-time)
       (if xml-signer
         (xml-signer new-request)
         new-request)))))

(defn uri-query-str
  ^String [clean-hash]
  (codec/form-encode clean-hash))

(defn get-idp-redirect
  "Return Ring response for HTTP 302 redirect."
  [idp-url saml-request-str relay-state]
  (let [url (str idp-url
                 (if (str/includes? idp-url "?")
                   "&"
                   "?")
                 (let [saml-request-str (encode-decode/str->deflate->base64 saml-request-str)]
                   (uri-query-str
                    {:SAMLRequest saml-request-str, :RelayState relay-state})))]
    {:status  302                       ; found
     :headers {"Location" url}
     :body    ""}))
