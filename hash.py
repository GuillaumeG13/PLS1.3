## SHA-256 test with hashlib
## source : https://medium.com/@dwernychukjosh/sha256-encryption-with-python-bf216db497f9
## tested by Guillaume Gay

import hashlib

def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature