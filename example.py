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

signing_key = {
    'id': 'did:example:credential-issuer#key0',
    'privateKeyHex': '826CB6B9EA7C0752F78F600805F9005ACB66CAA340B0F5CFA6BF41D470D49475',
}

verification_key = {
    'id': 'did:example:credential-issuer#key0',
    'publicKeyHex': 'E390CF3B5B93E921C45ED978737D89F61B8CAFF9DE76BFA5F63DA20386BCCA3B'
}

singed_credential = vc_agent.issue(credential, signing_key)
print(json.dumps(singed_credential, indent=2))
verified = vc_agent.verify(singed_credential, verification_key)
print("Verification Result: ",verified)