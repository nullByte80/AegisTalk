import socket
import os
import threading
import sys

def receive_msg(client, alias):
    """Continuously listen for incoming messages."""
    while True:
        try:
            msg = client.recv(4096).decode()
            sys.stdout.write(f"\r{msg}\n")
            sys.stdout.write(f"[{alias}$>] ")
            sys.stdout.flush()
            
                
        except:
            print("[-] Connection closed.")
            client.close()
            os._exit(0)

def start_guest(ip, alias):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, 1337))

    # Handle initial alias request
    if client.recv(4096).decode() == "GET_ALIAS":
        client.send(alias.encode())

    threading.Thread(target=receive_msg, args=(client, alias)).start()

    while True:
        msg = input(f"[{alias}$>] ")
        if msg.lower() == '/exit':
            print("\033[93m[*] Closing session...\033[0m")
            client.close()
            os._exit(0)
        client.send(f"{alias}<$>: {msg}".encode())