import socket
import os
import threading
import sys

# --- استدعاء ترسانة التشفير ---
from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher

aes_cipher = None 

def receive_msg(client, alias):
    global aes_cipher
    while True:
        try:
            encrypted_data = client.recv(4096)
            if not encrypted_data:
                continue
                
            # فصل الـ Nonce وفك التشفير
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            decrypted_msg = aes_cipher.decrypt(nonce, ciphertext).decode('utf-8')
            
            sys.stdout.write(f"\r{decrypted_msg}\n")
            sys.stdout.write(f"[{alias}$>] ")
            sys.stdout.flush()
        except Exception as e:
            print(f"\n[-] DEBUG ERROR: {e}") # السطر ده هيكشفلنا أي مشكلة
            print("[-] Connection closed.")
            client.close()
            os._exit(0)

def start_guest(ip, alias):
    global aes_cipher
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    
    client.connect((ip, 8080)) 

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
    
    # AES
    aes_cipher = AESCipher(session_keys.aes_key)
    print("\033[92m[+] SECURE connection established! Chat is LIVE.\033[0m")
    # ==========================================

    threading.Thread(target=receive_msg, args=(client, alias)).start()

    while True:
        msg = input(f"[{alias}$>] ")
        if msg.lower() == '/exit':
            print("\033[93m[*] Closing session...\033[0m")
            client.close()
            os._exit(0)
            
        formatted_msg = f"{alias}<$>: {msg}"
        
        # التشفير قبل الإرسال
        nonce, ciphertext = aes_cipher.encrypt(formatted_msg.encode('utf-8'))
        client.send(nonce + ciphertext)