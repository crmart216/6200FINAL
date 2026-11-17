import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
salt = None
info = b"keyGeneration"
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=48,
    salt=salt,
    info=info,
)

info = b"keyRatcheting"
hkdf2 = HKDF(
    algorithm=hashes.SHA256(),
    length=48,
    salt=salt,
    info=info,
)
fullkey = hkdf.derive(b"input key")
messageEnc = fullkey[:16]
nextRatchet = fullkey[16:]
fullkey2 = hkdf2.derive(b"input key")
messageEnc2 = fullkey2[:16]
nextRatchet2 = fullkey2[16:]
print(fullkey)
print(messageEnc)
print(nextRatchet)
print("next key")
print(fullkey2)
print(messageEnc2)
print(nextRatchet2)

