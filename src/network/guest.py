import socket
import os
import threading
import sys

# --- استدعاء ترسانة التشفير ---
from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher
from src.crypto.chacha_cipher import ChaChaCipher

# المتغير السحري: غير القيمة دي لـ 'AES' أو 'CHACHA'
CIPHER_MODE = 'CHACHA' #CIPHER_MODE = 'AES'

cipher_instance = None 

def receive_msg(client, alias):
    global cipher_instance
    while True:
        try:
            encrypted_data = client.recv(4096)
            if not encrypted_data:
                continue
                
            # فصل الـ Nonce (كلاهما يستخدم 12 بايت) وفك التشفير
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            decrypted_msg = cipher_instance.decrypt(nonce, ciphertext).decode('utf-8')
            
            sys.stdout.write(f"\r{decrypted_msg}\n")
            sys.stdout.write(f"[{alias}$>] ")
            sys.stdout.flush()
        except Exception as e:
            print(f"\n[-] DEBUG ERROR: {e}")
            print("[-] Connection closed.")
            client.close()
            os._exit(0)

def start_guest(ip, alias):
    global cipher_instance
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, 1337)) #------------------------------

    # 1. تبادل الاسم
    if client.recv(4096).decode() == "GET_ALIAS":
        client.send(alias.encode())

    print(f"[*] Executing Secure Handshake with Owner...")

    # ==========================================
    # (Secure Handshake) 
    # ==========================================
    dh = ECDHExchange()
    peer_pub_key = client.recv(4096)
    client.send(dh.get_public_key_bytes())
    
    shared_secret = dh.compute_shared_secret(peer_pub_key)
    session_keys = derive_keys(shared_secret)
    
    # التبديل الذكي بين الخوارزميات
    if CIPHER_MODE == 'AES':
        cipher_instance = AESCipher(session_keys.aes_key)
        print(f"[*] Mode: {CIPHER_MODE}")
    else:
        cipher_instance = ChaChaCipher(session_keys.chacha_key)
        print(f"[*] Mode: {CIPHER_MODE}")

    print("\033[92m[+] SECURE connection established! Chat is LIVE.\033[0m")
    # ==========================================

    threading.Thread(target=receive_msg, args=(client, alias)).start()

    while True:
        msg = input(f"[{alias}$>] ")
        if not msg.strip(): continue
        if msg.lower() == '/exit':
            client.close()
            os._exit(0)
            
        formatted_msg = f"{alias}<$>: {msg}"
        
        # التشفير باستخدام النوع المختار
        nonce, ciphertext = cipher_instance.encrypt(formatted_msg.encode('utf-8'))
        client.send(nonce + ciphertext)