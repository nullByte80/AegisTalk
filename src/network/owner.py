import socket
import threading
import sys
import os
import base64
import time

# --- Encryption Toolkit Imports ---
from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher
from src.crypto.chacha_cipher import ChaChaCipher

# Configuration
CIPHER_MODE = 'CHACHA' 
MAX_FILE_SIZE = 5 * 1024 * 1024 # 5MB Limit
PORT = 1337

clients = []
ciphers = {} 
room_active = False

def receive_full_packet(sock):
    raw_size = sock.recv(4)
    if not raw_size: return None
    total_size = int.from_bytes(raw_size, byteorder='big')
    data = b""
    while len(data) < total_size:
        packet = sock.recv(min(total_size - len(data), 4096))
        if not packet: break
        data += packet
    return data

def broadcast(message_bytes, _client=None, is_raw=False):
    for client in clients:
        if client != _client:
            try:
                if not is_raw:
                    cipher = ciphers[client]
                    nonce, ciphertext = cipher.encrypt(message_bytes)
                    payload = nonce + ciphertext
                else:
                    payload = message_bytes
                client.sendall(len(payload).to_bytes(4, 'big') + payload)
            except:
                client.close()
                if client in clients: clients.remove(client)

def handle_client(client, owner_alias):
    while True:
        try:
            data = receive_full_packet(client)
            if data:
                cipher = ciphers[client]
                nonce, ciphertext = data[:12], data[12:]
                decrypted_payload = cipher.decrypt(nonce, ciphertext).decode('utf-8')
                
                if decrypted_payload.startswith("<FILE>|"):
                    _, ext, b64_str = decrypted_payload.split("|")
                    file_data = base64.b64decode(b64_str)
                    save_path = f"received_{int(time.time())}{ext}"
                    with open(save_path, "wb") as f:
                        f.write(file_data)
                    print(f"\n[*] Media received and saved: {save_path}")
                    broadcast(data, _client=client, is_raw=True)
                else:
                    broadcast(decrypted_payload.encode('utf-8'), client)
                    sys.stdout.write(f"\r{decrypted_payload}\n[{owner_alias}#>]: ")
                    sys.stdout.flush()
        except:
            break


def start_owner(my_alias):
    global room_active
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen()
    
    print(f"[*] Server LIVE on port {PORT} | Mode: {CIPHER_MODE}")

    def accept_guests():
        global room_active
        while True:
            client, _ = server.accept()
            client.send("GET_ALIAS".encode())
            alias = client.recv(4096).decode()
            
            dh = ECDHExchange()
            client.send(dh.get_public_key_bytes())
            peer_pub_key = client.recv(4096)
            
            shared_secret = dh.compute_shared_secret(peer_pub_key)
            keys = derive_keys(shared_secret)
            ciphers[client] = AESCipher(keys.aes_key) if CIPHER_MODE == 'AES' else ChaChaCipher(keys.chacha_key)
            
            clients.append(client)
            print(f"[+] Secure session established with {alias}")
            room_active = True
            threading.Thread(target=handle_client, args=(client, my_alias), daemon=True).start()

    threading.Thread(target=accept_guests, daemon=True).start()

    while True:
        try:
            msg = input(f"[{my_alias}#>] ")
            if not msg.strip(): continue
            if msg.lower() == '/exit': break
            
            if msg.startswith("/send "):
                path = msg.split(" ", 1)[1].strip().strip('"')
                if os.path.exists(path) and os.path.getsize(path) <= MAX_FILE_SIZE:
                    with open(path, "rb") as f:
                        b64_data = base64.b64encode(f.read()).decode('utf-8')
                    ext = os.path.splitext(path)[1]
                    payload = f"<FILE>|{ext}|{b64_data}".encode('utf-8')
                    broadcast(payload)
                    print(f"[*] File {path} sent.")
                else:
                    print("[-] File error or size > 5MB.")
            elif room_active:
                broadcast(f"{my_alias}<#>: {msg}".encode('utf-8'))
        except KeyboardInterrupt:
            break