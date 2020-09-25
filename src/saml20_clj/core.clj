(ns saml20-clj.core
  "Main interface for saml20-clj SP functionality. The core functionality is broken out into several separate
  namespaces, but vars are made available here via Potemkin."
  (:require [potemkin :as p]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.sp
             [request :as request]
             [response :as response]]))

(comment
  coerce/keep-me
  request/keep-me
  response/keep-me)

(p/import-vars
 [coerce
  ->Response
  ->xml-string]

 [request
  idp-redirect-response
  metadata
  request]

 [response
  decrypt-response
  assertions
  validate])
