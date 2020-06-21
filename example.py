import vc_agent
import json

credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
  ],
  'id': 'did:example:credential:1872',
  'type': ['VerifiableCredential'],
  'issuer': 'did:example:credential-issuer',
  'issuanceDate': '2010-01-01T19:23:24Z',
  'credentialSubject': {
    'id': 'did:example:credential-subject',
  }
}

sofie_credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://mm.aueb.gr/contexts/access_control/v1"
  ],
  "id": "https://www.sofie-iot.eu/credentials/examples/1",
  "type": ["VerifiableCredential"],
  "issuer": "did:nacl:E390CF3B5B93E921C45ED978737D89F61B8CAFF9DE76BFA5F63DA20386BCCA3B",
  "issuanceDate": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:nacl:A490CF3B5B93E921C45ED978737D89F61B8CAFF9DE76BFA5F63DA20386BCCA62",
    "type": ["AllowedURLs"],
    "acl": [
      {
        "url": "http://sofie-iot.eu/device1",
        "methods": ["GET","POST"]
      },
      {
        "url": "http://sofie-iot.eu/device2",
        "methods": ["GET"]
      }
    ]
  }
}

signing_key = {
    'id': 'did:example:credential-issuer#key0',
    'privateKeyHex': '826CB6B9EA7C0752F78F600805F9005ACB66CAA340B0F5CFA6BF41D470D49475',
}

verification_key = {
    'id': 'did:nacl:E390CF3B5B93E921C45ED978737D89F61B8CAFF9DE76BFA5F63DA20386BCCA3B',
    'publicKeyHex': 'E390CF3B5B93E921C45ED978737D89F61B8CAFF9DE76BFA5F63DA20386BCCA3B'
}

singed_credential = vc_agent.issue(credential, signing_key)
print(json.dumps(singed_credential, indent=2))
verified = vc_agent.verify(singed_credential, verification_key)
print("Verification Result: ",verified)

singed_credential = vc_agent.issue(sofie_credential, signing_key)
print(json.dumps(singed_credential, indent=2))
verified = vc_agent.verify(singed_credential, verification_key)
print("Verification Result: ",verified)


filters = [
    ["$.@context[*]", "https://mm.aueb.gr/contexts/access_control/v1"],
    ["$.issuer", "did:nacl:E390CF3B5B93E921C45ED978737D89F61B8CAFF9DE76BFA5F63DA20386BCCA3B"],
    ["$.credentialSubject.acl[*].url", "http://sofie-iot.eu/device1"]
  ]
included = vc_agent.filter(sofie_credential, filters)
print(included)
