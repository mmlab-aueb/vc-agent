import vc_agent
import json
from jwcrypto import jwk
from jwcrypto.common import base64url_encode

key_issuer = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_issuer_dict = key_issuer.export(private_key=True, as_dict=True)
print(key_issuer_dict)
key_subject = jwk.JWK.generate(kty='OKP', crv='Ed25519')
key_subject_dict = key_subject.export(private_key=False, as_dict=True)

sofie_credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://mm.aueb.gr/contexts/access_control/v1"
  ],
  "id": "https://www.sofie-iot.eu/credentials/examples/1",
  "type": ["VerifiableCredential"],
  "issuer": "did:nacl:" + key_issuer_dict['x'],
  "issuanceDate": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:nacl:" + key_subject_dict['x'] ,
    "type": ["VCforWOTaccess"],
    "claims": [
      "https://sofie-iot.eu/device1",
      "https://sofie-iot.eu/device2",
      "https://sofie-iot.eu/device3",
    ]
  }
}

verification_method = "did:nacl:" + key_issuer_dict['x']
verification_key = key_issuer_dict['x']
signing_key = key_issuer_dict['d']

singed_credential = vc_agent.issue(sofie_credential, signing_key, verification_method, None, True)
verified = vc_agent.verify(singed_credential, verification_key, None, True)
print(json.dumps(singed_credential, indent=2))
print("Verification Result: ",verified)
access_token = base64url_encode(json.dumps(singed_credential))
print(len(access_token))

filters = [
    ["$.@context[*]", "https://mm.aueb.gr/contexts/access_control/v1"],
    ["$.credentialSubject.claims[*]", "https://sofie-iot.eu/device1"]
  ]
'''
Last filter is equivalent to
["$.credentialSubject.acl[*]", 'http://sofie-iot.eu/device1'],
["$.credentialSubject.acl[?(@.url='http://sofie-iot.eu/device1').method[*]", "GET"]
'''
included = vc_agent.filter(sofie_credential, filters)
print(included)
