import socket
import threading
import sys

clients = []
aliases = []
room_active = False

def get_local_ip():
    """Fetch local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def broadcast(message, _client=None):
    """Send to all connected clients."""
    for client in clients:
        if client != _client:
            try:
                client.send(message)
            except:
                client.close()

def handle_client(client, owner_alias):
    """Relay incoming guest messages."""
    while True:
        try:
            msg = client.recv(4096)
            if msg:
                broadcast(msg, client)
                # Print guest message on Owner's screen too
                sys.stdout.write(f"\r{msg.decode()}\n") 
                sys.stdout.write(f"[{owner_alias}#>]: ")
                sys.stdout.flush()
        except:
            break

def start_owner(my_alias):
    global room_active
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Prevent Port-in-use error
    server.bind(('0.0.0.0', 1337))
    server.listen()
    
    print(f"[*] IP: {get_local_ip()} | Port: 1337")
    print(f"[*] Room active. Waiting for guests...")

    def accept_guests():
        global room_active
        while True:
            client, addr = server.accept()
            client.send("GET_ALIAS".encode())
            alias = client.recv(4096).decode()
            
            clients.append(client)
            aliases.append(alias)
            
            print(f"\n[+] {alias} connected! Chat is now LIVE.")
            room_active = True # Auto-activate room
            
            threading.Thread(target=handle_client, args=(client,my_alias), daemon=True).start()

    # Start listener thread
    threading.Thread(target=accept_guests, daemon=True).start()

    # Owner Chat Loop (Keep program alive)
    while True:
        try:
            msg = input(f"[{my_alias}#>]")
            if msg.lower() == '/exit': break
            if room_active:
                formatted_msg = f"{my_alias}<#>: {msg}"
                broadcast(formatted_msg.encode())
        except KeyboardInterrupt:
            break