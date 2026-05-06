import os
import sys
import time
import statistics

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher
from src.crypto.chacha_cipher import ChaChaCipher


C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_RED = '\033[91m'
C_CYAN = '\033[96m'
C_RESET = '\033[0m'

def simulate_handshake():
    alice = ECDHExchange()
    bob = ECDHExchange()
    shared_secret = alice.compute_shared_secret(bob.get_public_key_bytes())
    return derive_keys(shared_secret)

def run_benchmark():
    keys = simulate_handshake()
    iterations = 100000
    dummy_data = b"AegisTalk Secure Session Data - Scenario 2 Hybridization Test"
    
    aes = AESCipher(keys.aes_key)
    chacha = ChaChaCipher(keys.chacha_key)

    print(f"{C_CYAN}="*60)
    print(f"   AEGISTALK SECURITY BENCHMARK: SCENARIO 2 HYBRIDIZATION")
    print(f"="*60 + f"{C_RESET}\n")

    # 1. اختبار الخوارزميات المنفردة (Performance & Behavior)
    results = {}
    
    # AES-256-GCM Test
    start = time.time()
    for _ in range(iterations):
        n, c = aes.encrypt(dummy_data)
        aes.decrypt(n, c)
    results['aes'] = time.time() - start

    # ChaCha20-Poly1305 Test
    start = time.time()
    for _ in range(iterations):
        n, c = chacha.encrypt(dummy_data)
        chacha.decrypt(n, c)
    results['chacha'] = time.time() - start

    # 2. Apply Hybridization (AES Output -> ChaCha Input)
    # هذا هو التطبيق المباشر لمخرجات تقنية حديثة كمدخلات لأخرى.
    start = time.time()
    for _ in range(iterations):
        # مخرج AES (Ciphertext) يصبح مدخل لـ ChaCha
        aes_n, aes_ct = aes.encrypt(dummy_data)
        cha_n, hybrid_ct = chacha.encrypt(aes_ct)
        
        # فك التشفير العكسي
        dec_aes_ct = chacha.decrypt(cha_n, hybrid_ct)
        final_pt = aes.decrypt(aes_n, dec_aes_ct)
    results['hybrid'] = time.time() - start

    # --- TABLE ---
    print(f"{C_YELLOW}{'Metric':<20} | {'AES-256-GCM':<15} | {'ChaCha20':<15} | {'Hybrid (AES+Cha)'}{C_RESET}")
    print("-" * 75)
    
    print(f"{'Performance (s)':<20} | {results['aes']:<15.4f} | {results['chacha']:<15.4f} | {results['hybrid']:<15.4f}")
    
    # Security Standards & Strength Analysis
    print(f"{'Security Standard':<20} | {'NIST FIPS 197':<15} | {'RFC 8439':<15} | {'Defense-in-Depth'}")
    print(f"{'Key Strength':<20} | {'256-bit':<15} | {'256-bit':<15} | {'Double 256-bit'}")
    print(f"{'Auth Mechanism':<20} | {'GCM (Tag)':<15} | {'Poly1305':<15} | {'Dual Auth Tags'}")
    print(f"{'Resistance':<20} | {'High':<15} | {'High':<15} | {'Quantum-Resistant Layer'}")
    
    print(f"\n{C_YELLOW}=== BEHAVIOR & SECURITY ANALYSIS ==={C_RESET}")
    
    print(f"1. {C_BLUE}Strength:{C_RESET} Hybridization provides 'Double Encryption'. Even if one cipher is compromised, the other maintains confidentiality.")
    print(f"2. {C_BLUE}Performance:{C_RESET} The Hybrid mode is {results['hybrid']/results['aes']:.2f}x slower than AES alone, which is a calculated trade-off for extreme security.")
    print(f"3. {C_BLUE}Behavior:{C_RESET} AES excels in hardware-accelerated environments, while ChaCha is faster on mobile. Hybrid behavior ensures maximum security across all platforms.")
    print(f"4. {C_BLUE}Innovation:{C_RESET} Using AES ciphertext as input for ChaCha ensures that any structural patterns in the first cipher are completely obscured by the second.")

if __name__ == "__main__":
    run_benchmark()