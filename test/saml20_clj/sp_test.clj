(ns saml20-clj.sp-test
  (:require [clj-time.core :as ctime]
            [expectations :refer [expect]]
            [saml20-clj.sp :as sp]))

;; test saml next-id: Changing saml last id state.
(expect
 1
 (sp/next-saml-id! (atom 0)))


;; test saml timeout-bump: Attempt to bump a stateful saml timeout on a fake request.
(let [time-now (ctime/now)]
  (expect
   time-now
   (let [mutable  (ref {})
         saml-id  12345]
     (sp/bump-saml-id-timeout! mutable saml-id time-now)
     (get @mutable saml-id))))


;; test prune timed out ids: Attempt to remove a stale record from a mutable hash.
(expect
 {:count 1, :get-1? false, :get-2? true}
 (let [mutable (ref {1 (ctime/date-time 2013 10 10)
                     2 (ctime/now)})
       timeout (ctime/minutes 10)]
   (sp/prune-timed-out-ids! mutable timeout)
   {:count  (count @mutable)
    :get-1? (some? (get @mutable 1))
    :get-2? (some? (get @mutable 2))}))
