## SHA-256 function with hashlib
## source : https://medium.com/@dwernychukjosh/sha256-encryption-with-python-bf216db497f9

import hashlib

def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature