(ns saml20-clj.sp.request
  (:require [clj-time.core :as c.time]
            [clojure.string :as str]
            [hiccup
             [core :as hiccup]
             [page :as h.page]]
            [saml20-clj.shared :as shared]))

;;; These next 3 fns are defaults for storing SAML state in memory.
(defn bump-saml-id-timeout!
  "Sets the current time to the provided saml-id in the saml-id-timeouts ref map.
  This function has side-effects."
  [saml-id-timeouts saml-id issue-instant]
  (dosync (alter saml-id-timeouts assoc saml-id issue-instant)))

(defn next-saml-id!
  "Returns the next available saml id."
  [saml-last-id]
  (swap! saml-last-id inc))

(defn prune-timed-out-ids!
  "Given a timeout duration, remove all SAML IDs that are older than now minus the timeout."
  [saml-id-timeouts timeout-duration]
  (let [filter-fn
        (partial filter (shared/make-timeout-filter-fn timeout-duration))]
    (dosync
      (ref-set saml-id-timeouts (into {} (filter-fn @saml-id-timeouts))))))

(defn metadata [app-name acs-uri certificate-str]
  (str
   (h.page/xml-declaration "UTF-8")
   (hiccup/html
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
                                     :isDefault "true"}]]])))

(defn create-request
  "Return XML elements that represent a SAML 2.0 auth request."
  [time-issued saml-format saml-service-name saml-id acs-url idp-uri]
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

(defn generate-mutables
  []
  {:saml-id-timeouts (ref {})
   :saml-last-id     (atom 0)
   :secret-key-spec  (shared/new-secret-key-spec)})

(defn create-request-factory
  "Creates new requests for a particular service, format, and acs-url."
  ([mutables idp-uri saml-format saml-service-name acs-url]
   (create-request-factory
     #(str "_" (next-saml-id! (:saml-last-id mutables)))
     (partial bump-saml-id-timeout! (:saml-id-timeouts mutables))
     (:xml-signer mutables)
     idp-uri saml-format saml-service-name acs-url))

  ([next-saml-id-fn! bump-saml-id-timeout-fn! xml-signer idp-uri saml-format saml-service-name acs-url]
   (fn request-factory []
     (let [current-time  (c.time/now)
           new-saml-id   (next-saml-id-fn!)
           issue-instant (shared/make-issue-instant current-time)
           new-request   (create-request issue-instant
                                         saml-format
                                         saml-service-name
                                         new-saml-id
                                         acs-url
                                         idp-uri)]
       (bump-saml-id-timeout-fn! new-saml-id current-time)
       (if xml-signer
         (xml-signer new-request)
         new-request)))))

(defn get-idp-redirect
  "Return Ring response for HTTP 302 redirect."
  [idp-url saml-request-str relay-state]
  (let [url (str idp-url
                 (if (str/includes? idp-url "?")
                   "&"
                   "?")
                 (let [saml-request-str (shared/str->deflate->base64 saml-request-str)]
                   (shared/uri-query-str
                    {:SAMLRequest saml-request-str, :RelayState relay-state})))]
    {:status  302 ; found
     :headers {"Location" url}
     :body    ""}))
