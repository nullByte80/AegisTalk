"""
mitm_proxy.py
-------------
A Man-In-The-Middle proxy to intercept and log network traffic
between the Owner and the Guest, proving the data is encrypted.
"""

import socket
import threading
import os

# الألوان للطباعة
C_GREEN = '\033[92m'
C_RED = '\033[91m'
C_YELLOW = '\033[93m'
C_RESET = '\033[0m'

def forward_and_log(src_socket, dst_socket, direction_label, color):
    """دالة مسئولة عن استقبال البيانات، طباعتها (مراقبتها)، وتمريرها"""
    while True:
        try:
            data = src_socket.recv(4096)
            if not data:
                break
            
            # 1. طباعة البيانات اللي تم اصطيادها
            print(f"\n{color}[ Intercepted: {direction_label}]{C_RESET}")
            print(f"Size: {len(data)} bytes")
            print(f"Data (Hex): {data.hex()}") # ده اللي هيثبت إنها حروف متلخبطة ومشفرة
            
            # 2. تمرير البيانات للطرف التاني عشان الاتصال ميفصلش
            dst_socket.send(data)
        except Exception as e:
            break

def start_sniffer(listen_port=8080, forward_port=1337):
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.bind(('0.0.0.0', listen_port))
    proxy.listen(1)
    
    os.system('') # Windows colors
    print(f"{C_YELLOW}=== AegisTalk MITM Traffic Sniffer ==={C_RESET}")
    print(f"[*] Proxy listening on port {listen_port}...")
    print(f"[*] Waiting for Guest to connect to Proxy...\n")
    
    guest_conn, addr = proxy.accept()
    print(f"{C_GREEN}[+] Guest connected to Proxy from {addr}{C_RESET}")
    
    # 2. البروكسي بيتصل بالسيرفر الأصلي (الـ Owner)
    print(f"[*] Forwarding traffic to real Owner on port {forward_port}...")
    owner_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        owner_conn.connect(('192.168.1.5', forward_port))
        print(f"{C_GREEN}[+] Connected to real Owner!{C_RESET}\n")
    except Exception as e:
        print(f"{C_RED}[!] Could not connect to Owner. Make sure Owner is running on port {forward_port}.{C_RESET}")
        return

    print(f"{C_RED}===  SNIFFING STARTED: Monitoring Encrypted Packets  ==={C_RESET}")

    # 3. تشغيل 2 Threads عشان نراقب الاتجاهين في نفس الوقت
    t1 = threading.Thread(target=forward_and_log, args=(guest_conn, owner_conn, "Guest -> Owner", C_GREEN))
    t2 = threading.Thread(target=forward_and_log, args=(owner_conn, guest_conn, "Owner -> Guest", C_RED))
    
    t1.start()
    t2.start()
    
    t1.join()
    t2.join()

if __name__ == "__main__":
    start_sniffer()