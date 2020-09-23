(ns saml20-clj.sp
  "Main interface for saml20-clj SP functionality. The core functionality is broken out into several separate
  namespaces, but vars are made available here via Potemkin."
  (:require [potemkin :as p]
            [saml20-clj.sp
             [factories :as factories]
             [request :as request]
             [response :as response]
             [response-map :as response-map]]))

(comment
  factories/keep-me
  request/keep-me
  response/keep-me
  response-map/keep-me)

(p/import-vars
 [factories
  make-saml-decrypter
  make-saml-signer]

 [request
  bump-saml-id-timeout!
  create-request
  create-request-factory
  generate-mutables
  get-idp-redirect
  metadata
  next-saml-id!
  prune-timed-out-ids!]

 [response
  parse-saml-assertion
  parse-saml-resp-status
  saml-resp->assertions
  validate-saml-response-signature
  xml-string->saml-resp]

 [response-map
  parse-saml-response
  response->map])
