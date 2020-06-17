import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import vc_agent

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

key = {
    'id': 'did:example:credential-issuer#key0',
    'privateKeyHex': '826CB6B9EA7C0752F78F600805F9005ACB66CAA340B0F5CFA6BF41D470D49475',
    'publicKeyHex': 'E390CF3B5B93E921C45ED978737D89F61B8CAFF9DE76BFA5F63DA20386BCCA3B'
}

signed_credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "did:example:credential:1872",
  "type": [
    "VerifiableCredential"
  ],
  "issuer": "did:example:credential-issuer",
  "issuanceDate": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:example:credential-subject"
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2020-06-17T20:02:01Z",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..uWAZsFwxJsfTQd8i6Job_uEbrriRTMIOyyDnzz9BaWn1laDAYHRk4FXWaxr9r8yq-0tYxPAQ0T27B1iblZxDBQ",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:example:credential-issuer#key0"
  }
}


credential_invalid_jws = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1"
    ],
    "id": "did:example:credential:1872",
    "type": [
        "VerifiableCredential"
    ],
    "issuer": "did:example:credential-issuer",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject": {
        "id": "did:example:credential-subject"
    },
    "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-06-17T19:57:04Z",
        "verificationMethod": "did:example:credential-issuer#key0",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..iF10AsPUkl-2ASB6KtZLSGGe_FjmcL4oKXOIBP6gPycuQw1RHNUk2Fl-1NYT51mqbPnY5S1O4z_Qt_3f0HibBQ"
    }
}

def test_vc_issue():
    global credential,key
    singed_credential = vc_agent.issue(credential, key)
    assert(singed_credential['proof'] != None)

def test_valid_vc_verify():
    global signed_credential,key
    verified = vc_agent.verify(signed_credential,key)
    assert(verified)

def test_invalid_vc_verify():
    global signed_credential,key
    verified = vc_agent.verify(credential_invalid_jws,key)
    assert(not verified)