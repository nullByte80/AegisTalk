from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement

class ECDHExchange:
    def __init__(self):
        
        self._private_key = ECC.generate(curve='P-384')
        self.public_key = self._private_key.public_key()

    def get_public_key_bytes(self) -> bytes:
        
        return self.public_key.export_key(format='DER')

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        
        peer_public_key = ECC.import_key(peer_public_key_bytes)
        
        
        shared_secret = key_agreement(
            static_priv=self._private_key,
            static_pub=peer_public_key,
            kdf=lambda x: x
        )
        return shared_secret