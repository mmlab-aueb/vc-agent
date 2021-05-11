import hashlib
import datetime
from pyld import jsonld
from pyld.jsonld import JsonLdProcessor
from jsonpath_ng import jsonpath
from jsonpath_ng.ext import parse
from jwcrypto import jwk, jws
import time



def issue(credential, signing_key, verification_method, documentloader=None, benchmark=False):
    """ It signs a credential using Ed25519Signature2018 JSON-LD Signature

    :param credential: a python dict representing the credential
    :param signing_key:  the signing key encoded in base64url
    :param verification_method:  the signature verification method
    :param documentloader: a custom documentloader

    :return: the credential with the signature appended
    """
    credential = credential.copy()
    jws_header = {"alg": "EdDSA", "b64": False, "crit":["b64"]}
    proof= {
        '@context':'https://w3id.org/security/v2',
        'type': 'Ed25519Signature2018',
        'created': datetime.datetime.utcnow().replace(microsecond=0).isoformat()+'Z',#'2020-06-17T17:51:12Z',
        'verificationMethod': verification_method,
        'proofPurpose': 'assertionMethod'
    }

    normalized_doc   = jsonld.normalize(credential , {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
    normalized_proof = jsonld.normalize(proof, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
    doc_hash         = hashlib.sha256()
    proof_hash       = hashlib.sha256()
    key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'd': signing_key, 'x': ''}
    key_jwk = jwk.JWK(**key_dict)
    start_time = time.time()
    doc_hash.update(normalized_doc.encode('utf-8'))
    proof_hash.update(normalized_proof.encode('utf-8'))
    to_sign       = proof_hash.digest() + doc_hash.digest()
    jwsproof = jws.JWS(to_sign)
    jwsproof.add_signature(key_jwk, None, jws_header, None)
    if benchmark:
        print (f'*** {time.time() - start_time} \t VC signed')
    jwsproof.objects['payload']=''
    proof["jws"]  = jwsproof.serialize(compact=True)
    credential['proof'] = proof
    return credential

def verify(singed_credential, verification_key, documentloader=None, benchmark=False):
    """ It signs a credential using Ed25519Signature2018 JSON-LD Signature

    :param singed_credential: a python dict representing the credential
    :param verification_key:  the verification key encoded in base64url
    :param documentloader: a custom documentloader

    :return: True or False
    """
    singed_credential = singed_credential.copy()
    proof =  singed_credential['proof']
    signature = proof['jws'] 
    del singed_credential['proof']
    del proof['jws']

    normalized_doc   = jsonld.normalize(singed_credential , {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
    normalized_proof = jsonld.normalize(proof, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
    doc_hash         = hashlib.sha256()
    proof_hash       = hashlib.sha256()
    key_dict = {'kty': 'OKP', 'crv': 'Ed25519', 'x': verification_key}
    key_jwk = jwk.JWK(**key_dict)
    start_time = time.time()
    doc_hash.update(normalized_doc.encode('utf-8'))
    proof_hash.update(normalized_proof.encode('utf-8'))
    payload       = proof_hash.digest() + doc_hash.digest()
    claimed_proof = jws.JWS()
    claimed_proof.deserialize(signature)
    claimed_proof.objects['payload'] = payload
    try:
        claimed_proof.verify(key_jwk)
        if benchmark:
            print (f'*** {time.time() - start_time} \t Signature verified')
        return True
    except:
        return False
    
    
def filter(credential, filters):
    """ It verifies if a credential a some particular fields/value pairs

    :param credential: a python dict representing the credential
    :param [filters]:  pairs of  
        a json path query,
        optional, the value, or a list of values to search

    :return: True or False
    """
    
    for filter in filters:
        jsonpath_expr = parse(filter[0])
        found = False
        for match in jsonpath_expr.find(credential):
            if len(filter) == 2 and isinstance(filter[1], list):
                if match.value in filter[1]:
                    found = True
            elif len(filter) == 2:
                if match.value == filter[1]:
                    found = True
            else: #no value is required
                found = True
        if not found:
            return False 
    return True