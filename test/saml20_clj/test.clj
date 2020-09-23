(ns saml20-clj.test
  "Test utils.")

(def idp-uri      "http://test.idp.metabase.com")
(def redirect-uri "http://localhost:3000/test")

(def cert
  "Test IdP certificate, in base-64."
  (delay (slurp "test/saml20_clj/test/test.cert")))

(def example-response-signed
  (delay (slurp "test/saml20_clj/test/example-response-signed.xml")))

(def example-response-unsigned
  (delay (slurp "test/saml20_clj/test/example-response-unsigned.xml")))

(def example-response-signed-wrong-cert
  (delay (slurp "test/saml20_clj/test/example-response-signed-wrong-cert.xml")))

(def example-response-signed-bad-signature
  (delay (slurp "test/saml20_clj/test/example-response-signed-bad-signature.xml")))
