from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class aes_cipher:
    used_nonces = set()

    @staticmethod
    def encrypt(message):

        key = get_random_bytes(32) # 256-bit key for AES-256
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        nonce = cipher.nonce # Essential for decryption
        
        return key, nonce, ciphertext, tag

    @staticmethod
    def decrypt(key, nonce, ciphertext, tag):
        try:

            if aes_cipher.is_nonce_valid(nonce):
                print(f"✔️ This nonce : {nonce} is valid!")

            else:
                print("❌ This is an invalid nonce, please use another one")
                return None
        
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext

        except Exception as e:
            print("❌ Decryption failed! Possible tampering or wrong key.")
            return None

    @staticmethod
    def is_nonce_valid(nonce):
        if len(nonce) != 16:
            return False

        if nonce in aes_cipher.used_nonces:
            return False

        aes_cipher.used_nonces.add(nonce)
        return True


if __name__ == "__main__":
    
    message = b"Hello, World!"
    print("=" * 50)
    print("🔐 AES Encryption/Decryption Test")
    print("=" * 50)
    print(f"\nOriginal Message: {message}\n")
    
    result = aes_cipher.encrypt(message)

    if result:
        key, nonce, ciphertext, tag = result
        print(f"\n✅ Encryption Successful!")
        print(f"Key: {key.hex()[:32]}...")
        print(f"Nonce: {nonce.hex()}")
        print(f"Ciphertext: {ciphertext.hex()}")
        
        print("\n" + "-" * 50)
        plaintext = aes_cipher.decrypt(key, nonce, ciphertext, tag)
        
        if plaintext:
            print(f"✅ Decryption Successful!")
            print(f"Decrypted Message: {plaintext}")
            print(f"\n✨ Messages Match: {message == plaintext}")
        print("=" * 50)
