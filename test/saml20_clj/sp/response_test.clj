(ns saml20-clj.sp.response-test
  (:require [clojure.test :refer :all]
            [saml20-clj.sp.response :as response]
            [saml20-clj.test :as test]))

(deftest parse-saml-resp-status-test
  (is (= {:inResponseTo "_1"
          :status       "urn:oasis:names:tc:SAML:2.0:status:Success"
          :success?     true
          :version      "2.0"
          :issueInstant #inst "2018-07-05T18:02:53.000000000-00:00"
          :destination  "http://localhost:3000/auth/sso"}
         (response/parse-saml-resp-status (response/xml-string->saml-resp @test/example-response-unsigned)))))

(deftest saml-resp->assertions-test
  (is (= {:inResponseTo "_1"
          :status       "urn:oasis:names:tc:SAML:2.0:status:Success"
          :success?     true
          :version      "2.0"
          :issueInstant #inst "2018-07-05T18:02:53.000000000-00:00"
          :destination  "http://localhost:3000/auth/sso"
          :assertions   [{:attrs        {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" ["auth0|5b0dd0185d7d1617fd8065b5"]
                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"   ["cam@example.com"]
                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"           ["Cam Saul"]
                                         "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"            ["cam@example.com"]}
                          :audiences    ["ExampleClient"]
                          :name-id      {:value  "auth0|5b0dd0185d7d1617fd8065b5"
                                         :format "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}
                          :confirmation {:in-response-to  "_1"
                                         :not-before      nil
                                         :not-on-or-after #inst "2018-07-05T19:02:53.262000000-00:00"
                                         :recipient       "http://localhost:3000/auth/sso"}}]}
         (response/saml-resp->assertions (response/xml-string->saml-resp @test/example-response-unsigned) nil))))

(deftest validate-saml-response-signature-test
  (testing "Should return false if response doesn't have a signature")
  (testing "Should return false if signature doesn't match the IdP certificate")
  (testing "Should return false if signature doesn't match the message")
  (testing "should return true if the signature matches the message and IdP certificate"))

;; TODO -- validate the conditions before/notonorafter
