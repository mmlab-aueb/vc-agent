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
    'private_key': 'oP-hXjAv1Y96FzGJrJRZ_WdgWgvbx2Y3FBeLOOewZwc',
    'public_key': 'oKNiZl8ri2R3o2wFqky6JjL9gzstTeQk8StM7GJ_bTM'
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
    "@context": "https://w3id.org/security/v2",
    "type": "Ed25519Signature2018",
    "created": "2020-11-19T22:46:28Z",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..J2CyJs_ymFypmbT4lhffUJEGcZIyOaCFvTH1TKV3hVacfiIJFLW-x6ucsFbzsmGNoGrd4S6QmUz_kGGemmfWAg",
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
        "@context": "https://w3id.org/security/v2",
        "type": "Ed25519Signature2018",
        "created": "2020-11-19T22:46:28Z",
        "verificationMethod": "did:example:credential-issuer#key0",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..iF10AsPUkl-2ASB6KtZLSGGe_FjmcL4oKXOIBP6gPycuQw1RHNUk2Fl-1NYT51mqbPnY5S1O4z_Qt_3f0HibBQ"
    }
}

def test_vc_issue():
    global credential,key
    singed_credential = vc_agent.issue(credential, key['private_key'], key['id'])
    assert(singed_credential['proof'] != None)

def test_valid_vc_verify():
    global signed_credential,key
    verified = vc_agent.verify(signed_credential,key['public_key'])
    assert(verified)

def test_invalid_vc_verify():
    global signed_credential,key
    verified = vc_agent.verify(credential_invalid_jws,key['public_key'])
    assert(not verified)