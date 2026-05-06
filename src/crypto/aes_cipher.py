import os
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key: bytes):
        """key: 32 bytes AES-256 key"""
        self.key = key

    def encrypt(self, plaintext: bytes, aad: bytes = None):
        nonce = os.urandom(12)  # 96-bit nonce
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        if aad:
            cipher.update(aad)
            
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        return nonce, ciphertext + tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = None):
        
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[:-16]
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        if aad:
            cipher.update(aad)
            
        plaintext = cipher.decrypt_and_verify(actual_ciphertext, tag)
        return plaintext