(ns saml20-clj.sp.response-test
  (:require [clojure.test :refer :all]
            [saml20-clj.sp.response :as response]
            [saml20-clj.test :as test]))

(deftest response-status-test
  (doseq [{:keys [response], :as response-map} test/responses]
    (testing (test/describe-response-map response-map)
      (is (= {:in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
              :status         "urn:oasis:names:tc:SAML:2.0:status:Success"
              :success?       true
              :version        "2.0"
              :issue-instant  #inst "2014-07-17T01:01:48.000000000-00:00"
              :destination    "http://sp.example.com/demo1/index.php?acs"}
             (response/response-status response))))))

(deftest assertions-test
  (doseq [{:keys [response], :as response-map} test/responses]
    (testing (test/describe-response-map response-map)
      (is (= {:in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
              :status         "urn:oasis:names:tc:SAML:2.0:status:Success"
              :success?       true
              :version        "2.0"
              :issue-instant  #inst "2014-07-17T01:01:48.000000000-00:00"
              :destination    "http://sp.example.com/demo1/index.php?acs"
              :assertions     [{:attrs        {"uid"                  ["test"]
                                               "mail"                 ["test@example.com"]
                                               "eduPersonAffiliation" ["users" "examplerole1"]}
                                :audiences    ["sp.example.com"]
                                :name-id      {:value  "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"
                                               :format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}
                                :confirmation {:in-response-to  "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
                                               :not-before      nil
                                               :not-on-or-after #inst "2024-01-18T06:21:48.000000000-00:00"
                                               :recipient       "http://sp.example.com/demo1/index.php?acs"}}]}
             (response/assertions response [test/sp-cert test/sp-private-key]))))))

(defn- validate-signature
  ([response]
   (validate-signature response test/idp-cert))

  ([response idp-cert sp-cert]
   (response/validate-response-signature
    response
    idp-cert
    sp-cert)))

(deftest validate-response-signature-test
  (testing "unsigned responses should fail\n"
    (doseq [{:keys [response], :as response-map} test/responses
            :when                                (not (test/signed? response-map))]
      (testing (test/describe-response-map response-map)
        (is (= false
               (validate-signature response))))))
  (testing "valid signed responses should pass\n"
    (doseq [{:keys [response] :as response-map} test/responses
            :when                               (test/signed? response-map)]
      (testing (test/describe-response-map response-map)
        (assert (string? response))
        (testing "\nsignature should be valid when checking against IdP cert"
          (is (= true
                 (validate-signature response))))
        (testing "\nsignature should be invalid when checking against the wrong cert"
          (is (= false
                 ;; using SP cert for both instead
                 (validate-signature response test/sp-cert test/sp-cert))))))))
