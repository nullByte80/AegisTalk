import socket
import os
import threading
import sys
import base64
import time
from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher
from src.crypto.chacha_cipher import ChaChaCipher

# Configuration
CIPHER_MODE = 'CHACHA' # Must match owner.py
MAX_FILE_SIZE = 5 * 1024 * 1024 # 5MB Limit
cipher_instance = None 

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

def receive_msg(client, alias):
    """Threaded function to handle incoming server traffic"""
    global cipher_instance
    while True:
        try:
            data = receive_full_packet(client)
            if data:
                nonce, ciphertext = data[:12], data[12:]
                decrypted_payload = cipher_instance.decrypt(nonce, ciphertext).decode('utf-8')
                
                # Check if decrypted content follows the file protocol
                if decrypted_payload.startswith("<FILE>|"):
                    _, ext, b64_str = decrypted_payload.split("|")
                    file_data = base64.b64decode(b64_str)
                    
                    # Save the received media file locally
                    save_path = f"received_{int(time.time())}{ext}"
                    with open(save_path, "wb") as f:
                        f.write(file_data)
                        
                    print(f"\n[*] Media received and saved: {save_path}")
                    print(f"[{alias}$>] ", end="", flush=True)
                else:
                    # Display normal text messages
                    sys.stdout.write(f"\r{decrypted_payload}\n[{alias}$>] ")
                    sys.stdout.flush()
        except:
            client.close()
            os._exit(0)

def start_guest(ip, alias):
    """Establish connection and perform secure handshake."""
    global cipher_instance
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, 1337))

    # Identify to the server
    if client.recv(4096).decode() == "GET_ALIAS":
        client.send(alias.encode())

    # --- Secure Handshake (ECDH) ---
    dh = ECDHExchange()
    peer_pub_key = client.recv(4096) # Receive Owner's Public Key
    client.send(dh.get_public_key_bytes()) # Send Guest's Public Key
    
    shared_secret = dh.compute_shared_secret(peer_pub_key)
    keys = derive_keys(shared_secret)
    
    # Initialize cipher based on selected mode
    cipher_instance = AESCipher(keys.aes_key) if CIPHER_MODE == 'AES' else ChaChaCipher(keys.chacha_key)

    print(f"[*] Secure Handshake Complete. Mode: {CIPHER_MODE}")
    threading.Thread(target=receive_msg, args=(client, alias), daemon=True).start()

    # Main Interaction Loop
    while True:
        msg = input(f"[{alias}$>] ")
        if not msg.strip(): continue
        if msg.lower() == '/exit': break
        
        payload = b""
        # File Transmission Command: /send <path>
        if msg.startswith("/send "):
            path = msg.split(" ", 1)[1].strip().strip('"')
            if os.path.exists(path) and os.path.getsize(path) <= MAX_FILE_SIZE:
                with open(path, "rb") as f:
                    b64_data = base64.b64encode(f.read()).decode('utf-8')
                ext = os.path.splitext(path)[1]
                # Format: <FILE>|extension|base64_data
                payload = f"<FILE>|{ext}|{b64_data}".encode('utf-8')
                print(f"[*] Encrypting and sending file: {path}...")
            else:
                print("[-] File error: Not found or exceeds 5MB limit.")
                continue
        else:
            # Standard Text Message
            payload = f"{alias}<$>: {msg}".encode('utf-8')
            
        # Encrypt and prepend the 4-byte size header
        nonce, ciphertext = cipher_instance.encrypt(payload)
        full_payload = nonce + ciphertext
        client.sendall(len(full_payload).to_bytes(4, 'big') + full_payload)