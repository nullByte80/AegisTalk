import socket
import threading
import sys
import os

# --- استدعاء ترسانة التشفير ---
from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher
from src.crypto.chacha_cipher import ChaChaCipher

# المتغير السحري: غير القيمة دي لـ 'AES' أو 'CHACHA'
# تأكد إنها نفس القيمة في ملف الـ guest
CIPHER_MODE = 'CHACHA'  #CIPHER_MODE = 'AES'

clients = []
aliases = []
ciphers = {}  # قاموس لتخزين كائن التشفير الخاص بكل ضيف
room_active = False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def broadcast(message_str, _client=None):
    """تشفير وإرسال الرسالة لكل الضيوف بناءً على الـ Mode المختار"""
    for client in clients:
        if client != _client:
            try:
                # بنجيب كائن التشفير (سواء كان AES أو ChaCha)
                cipher = ciphers[client]
                nonce, ciphertext = cipher.encrypt(message_str.encode('utf-8'))
                client.send(nonce + ciphertext)
            except:
                client.close()

def handle_client(client, owner_alias):
    """فك تشفير الرسائل القادمة باستخدام الكائن المخزن للضيف"""
    while True:
        try:
            encrypted_data = client.recv(4096)
            if encrypted_data:
                cipher = ciphers[client]
                
                # الـ Nonce طوله 12 بايت في AES-GCM و ChaCha20-Poly1305
                nonce = encrypted_data[:12]
                ciphertext = encrypted_data[12:]
                
                decrypted_msg = cipher.decrypt(nonce, ciphertext).decode('utf-8')
                
                broadcast(decrypted_msg, client)
                
                sys.stdout.write(f"\r{decrypted_msg}\n") 
                sys.stdout.write(f"[{owner_alias}#>]: ")
                sys.stdout.flush()
        except:
            break

def start_owner(my_alias):
    global room_active
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 1337))
    server.listen()
    
    print(f"[*] IP: {get_local_ip()} | Port: 1337")
    print(f"[*] Cipher Mode: {CIPHER_MODE}")
    print(f"[*] Room active. Waiting for guests...")

    def accept_guests():
        global room_active
        while True:
            client, addr = server.accept()
            
            client.send("GET_ALIAS".encode())
            alias = client.recv(4096).decode()
            
            print(f"\n[*] Executing Secure Handshake with {alias}...")
            
            dh = ECDHExchange()
            client.send(dh.get_public_key_bytes())
            peer_pub_key = client.recv(4096)
            
            shared_secret = dh.compute_shared_secret(peer_pub_key)
            session_keys = derive_keys(shared_secret)
            
            # التبديل الذكي: ننشئ الكائن بناءً على الـ Mode
            if CIPHER_MODE == 'AES':
                ciphers[client] = AESCipher(session_keys.aes_key)
            else:
                ciphers[client] = ChaChaCipher(session_keys.chacha_key)
            
            clients.append(client)
            aliases.append(alias)
            
            print(f"\033[92m[+] SECURE ({CIPHER_MODE}) established with {alias}!\033[0m")
            room_active = True
            
            threading.Thread(target=handle_client, args=(client, my_alias), daemon=True).start()

    threading.Thread(target=accept_guests, daemon=True).start()

    while True:
        try:
            msg = input(f"[{my_alias}#>]")
            if not msg.strip(): continue
            if msg.lower() == '/exit': break
            if room_active:
                formatted_msg = f"{my_alias}<#>: {msg}"
                broadcast(formatted_msg)
        except KeyboardInterrupt:
            break