(ns saml20-clj.sp.response-map
  (:require [clojure
             [xml :as xml]
             [zip :as zip]]
            [clojure.data.zip.xml :as zf]
            [saml20-clj.shared :as shared]))

(def ^:private response-attr-names  [:ID :IssueInstant :InResponseTo])
(def ^:private subject-conf-names   [:Recipient :NotOnOrAfter :InResponseTo])
(def ^:private saml-cond-attr-names [:NotBefore :NotOnOrAfter])

;; NOCOMMIT
(defn- xml->
  ([node k]
   (when-not node
     (throw (ex-info "Cannot traverse XML: XML is nil" {:k k})))
   (zf/xml1-> node k))

  ([node k & more]
   (let [node' (xml-> node k)]
     (when-not node'
       (throw (ex-info (format "No node %s" k) {:node node, :k k})))
     (try
       (apply xml-> node' more)
       (catch Throwable e
         (throw (ex-info (format "Error finding %s" (into [k] more))
                         {:node node, :path (into [k] more)})))))))

(defn- pull-attrs
  [loc attrs]
  (zipmap attrs (map (partial zf/attr loc) attrs)))

(defn response->map
  "Parses and performs final validation of the request. An exception will be thrown if validation fails."
  [saml-resp]
  (try
    (let [saml-status               (xml-> saml-resp :samlp:Status :samlp:StatusCode)
          saml-assertion            (xml-> saml-resp :Assertion)
          saml-subject              (xml-> saml-assertion :Subject)
          saml-issuer               (xml-> saml-assertion :Issuer)
          saml-name-id              (xml-> saml-subject :NameID)
          saml-subject-conf-data    (xml-> saml-subject :SubjectConfirmation :SubjectConfirmationData)
          saml-conditions           (xml-> saml-assertion :Conditions)
          saml-audience-restriction (xml-> saml-conditions :AudienceRestriction :Audience)
          response-attrs            (pull-attrs saml-resp response-attr-names)
          status-str                (zf/attr saml-status :Value)
          issuer                    (zf/text saml-issuer)
          user-identifier           (zf/text saml-name-id)
          user-type                 (zf/attr saml-name-id :Format)
          conditions                (pull-attrs saml-conditions saml-cond-attr-names)
          subject-conf-attrs        (pull-attrs saml-subject-conf-data subject-conf-names)
          acs-audience              (zf/text saml-audience-restriction)]
      {:responding-to   (:InResponseTo response-attrs)
       :response-id     (:ID response-attrs)
       :issued-at       (:IssueInstant response-attrs)
       ;; TODO: Validate that "now" is within saml conditions.
       :success?        (and (shared/saml-successful? status-str)
                             (= (:InResponseTo response-attrs)
                                (:InResponseTo subject-conf-attrs)))
       :user-format     user-type
       :user-identifier user-identifier})
    (catch Throwable e
      (throw (ex-info "Error parsing SAML response" {:response saml-resp} e)))))

(defn parse-saml-response
  "Does everything from parsing the verifying SAML data to returning it in an easy to use map."
  [^String s]
  (let [xml (with-open [is (shared/str->inputstream s)]
              (xml/parse is))]
    (println (zip/xml-zip xml)) ; NOCOMMIT
    (response->map (zip/xml-zip xml))))
