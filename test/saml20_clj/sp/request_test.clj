(ns saml20-clj.sp.request-test
  (:require [clojure.test :refer :all]
            [java-time :as t]
            [saml20-clj.sp.request :as request]
            [saml20-clj.test :as test]))

(deftest next-saml-id-test
  (testing "test saml next-id: Changing saml last id state."
    (is (= 1
           (request/next-saml-id! (atom 0))))))

(deftest timeout-bump-test
  (testing "test saml timeout-bump: Attempt to bump a stateful saml timeout on a fake request."
    (let [time-now (t/instant)]
      (is (= time-now
             (let [mutable (ref {})
                   saml-id 12345]
               (request/bump-saml-id-timeout! mutable saml-id time-now)
               (get @mutable saml-id)))))))

(deftest prune-timed-out-ids-test
  (testing "test prune timed out ids: Attempt to remove a stale record from a mutable hash."
    (is (= {:count 1, :get-1? false, :get-2? true}
           (let [mutable (ref {1 (t/instant "2013-10-10T00:00:00.000Z")
                               2 (t/instant)})
                 timeout (t/minutes 10)]
             (request/prune-timed-out-ids! mutable timeout)
             {:count  (count @mutable)
              :get-1? (some? (get @mutable 1))
              :get-2? (some? (get @mutable 2))})))))

(deftest get-idp-redirect-test
  (is (= {:status 302
          :headers {"Location" (str "https://idp.example.com"
                                    "?SAMLRequest=C3b09VEIcg0MdQ0OUXD3dw1W8HANcgUA"
                                    "&RelayState=http%3A%2F%2Fsp.example.com%2Fdemo1%2Findex.php%3Facs")}
          :body ""}
         (request/get-idp-redirect test/idp-uri
                                   "SAML REQUEST GOES HERE"
                                   test/target-uri)))
  (testing "Should handle URIs that already have query params in them"
    (is (= {:status 302
            :headers {"Location" (str "https://idp.example.com"
                                      "?x=100"
                                      "&SAMLRequest=C3b09VEIcg0MdQ0OUXD3dw1W8HANcgUA"
                                      "&RelayState=http%3A%2F%2Fsp.example.com%2Fdemo1%2Findex.php%3Facs")}
            :body ""}
           (request/get-idp-redirect (str test/idp-uri "?x=100")
                                     "SAML REQUEST GOES HERE"
                                     test/target-uri)))))
