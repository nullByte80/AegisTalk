import socket
import threading
import sys
import os

# --- استدعاء ترسانة التشفير ---
from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher

clients = []
aliases = []
ciphers = {}  # قاموس بنخزن فيه مفتاح التشفير الخاص بكل ضيف (عشان لو دخل أكتر من ضيف)
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
    """تشفير وإرسال الرسالة لكل الضيوف"""
    for client in clients:
        if client != _client:
            try:
                # بنجيب مفتاح الـ AES الخاص بالضيف ده تحديداً
                aes = ciphers[client]
                # التشفير: بيطلع Nonce (12 byte) والـ Ciphertext
                nonce, ciphertext = aes.encrypt(message_str.encode('utf-8'))
                # دمجهم وإرسالهم
                client.send(nonce + ciphertext)
            except:
                client.close()

def handle_client(client, owner_alias):
    """استقبال الرسايل المشفرة من الضيف، فك تشفيرها، وعرضها"""
    while True:
        try:
            encrypted_data = client.recv(4096)
            if encrypted_data:
                # استدعاء مفتاح الـ AES بتاع الضيف ده
                aes = ciphers[client]
                
                # فصل الـ Nonce عن التشفير
                nonce = encrypted_data[:12]
                ciphertext = encrypted_data[12:]
                
                # فك التشفير
                decrypted_msg = aes.decrypt(nonce, ciphertext).decode('utf-8')
                
                # تمرير الرسالة لباقي الضيوف (لو فيه)
                broadcast(decrypted_msg, client)
                
                # طباعة الرسالة على شاشة الـ Owner
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
    print(f"[*] Room active. Waiting for guests...")

    def accept_guests():
        global room_active
        while True:
            client, addr = server.accept()
            
            # 1. تبادل الأسماء (Plaintext مؤقتاً عشان نتعرف على بعض)
            client.send("GET_ALIAS".encode())
            alias = client.recv(4096).decode()
            
            print(f"\n[*] Executing Secure Handshake with {alias}...")
            
            # ==========================================
            # 🔒 2. المصافحة الآمنة (Secure Handshake) 🔒
            # ==========================================
            dh = ECDHExchange()
            
            # نبعت المفتاح العام بتاعنا للضيف
            client.send(dh.get_public_key_bytes())
            
            # نستقبل المفتاح العام بتاع الضيف
            peer_pub_key = client.recv(4096)
            
            # نحسب السر المشترك ونستخرج مفتاح AES
            shared_secret = dh.compute_shared_secret(peer_pub_key)
            session_keys = derive_keys(shared_secret)
            
            # نخزن الـ AES Cipher للضيف ده في القاموس
            ciphers[client] = AESCipher(session_keys.aes_key)
            # ==========================================
            
            clients.append(client)
            aliases.append(alias)
            
            print(f"\033[92m[+] SECURE connection established with {alias}! Chat is LIVE.\033[0m")
            room_active = True
            
            threading.Thread(target=handle_client, args=(client, my_alias), daemon=True).start()

    threading.Thread(target=accept_guests, daemon=True).start()

    # Owner Chat Loop
    while True:
        try:
            msg = input(f"[{my_alias}#>]")
            if msg.lower() == '/exit': break
            if room_active:
                formatted_msg = f"{my_alias}<#>: {msg}"
                broadcast(formatted_msg) # الدالة دي هتشفر وتبعته
        except KeyboardInterrupt:
            break