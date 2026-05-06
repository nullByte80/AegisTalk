import os
import sys
import pyfiglet

# 1. استدعاء ملفات الشبكة (هتحتاج تعديل بسيط فيها عشان ترجع الاتصال)
from src.network.owner import start_owner
from src.network.guest import start_guest

# 2. استدعاء ترسانة التشفير
from src.crypto.dh_exchange import ECDHExchange
from src.crypto.key_derivation import derive_keys
from src.crypto.aes_cipher import AESCipher
from src.crypto.chacha_cipher import ChaChaCipher

# ANSI Colors
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_RESET = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Generate dynamic ASCII banner using pyfiglet."""
    banner = pyfiglet.figlet_format("AegisTalk", font="standard")
    print(f"{C_GREEN}{banner}{C_RESET}")
    print(f"{C_YELLOW}[+] Network Reconnaissance & Secure Chat")
    print(f"[+] Developed by BROs | Phase 3: Hybrid Crypto Ready{C_RESET}\n")

# ==========================================
# المشهد الثاني: المصافحة الآمنة (Handshake)
# ==========================================
def secure_handshake(connection):
    print(f"\n{C_BLUE}[*] Executing ECDH Secure Handshake...{C_RESET}")
    
    # 1. تجهيز المفاتيح
    dh = ECDHExchange()
    my_pub_key = dh.get_public_key_bytes()
    
    # 2. إرسال مفتاحي للطرف التاني (بافتراض أن دالة الإرسال اسمها send)
    connection.send(my_pub_key)
    
    # 3. استقبال مفتاح الطرف التاني (بافتراض أن الاستقبال بـ recv)
    peer_pub_key = connection.recv(2048) 
    
    # 4. استخراج السر المشترك وتوليد مفاتيح التشفير
    shared_secret = dh.compute_shared_secret(peer_pub_key)
    session_keys = derive_keys(shared_secret)
    
    print(f"{C_GREEN}[+] Handshake Complete! (AES/ChaCha/HMAC) Keys Derived.{C_RESET}\n")
    return session_keys

# ==========================================
# المشهد الثالث: الشات المشفر (Chat Loop)
# ==========================================
def secure_chat_loop(connection, session_keys, alias):
    # هنستخدم AES كمثال، وممكن تبدلها بـ ChaCha للمقارنة
    aes = AESCipher(session_keys.aes_key)
    print(f"{C_GREEN}=== Secure Chat Started. Type 'exit' to leave ==={C_RESET}")
    
    while True:
        try:
            msg = input(f"{C_YELLOW}{alias} > {C_RESET}")
            if msg.lower() == 'exit':
                break
            
            # تشفير الرسالة قبل الإرسال
            nonce, ciphertext = aes.encrypt(msg.encode('utf-8'))
            
            # إرسال الـ Nonce + الـ Ciphertext
            connection.send(nonce + ciphertext)
            
        except KeyboardInterrupt:
            break

# ==========================================
# المشهد الأول: واجهة المستخدم والاتصال
# ==========================================
def main():
    clear_screen()
    print_banner()
    
    print(f"{C_BLUE}[1]{C_RESET} Host Aegis Room (Owner)")
    print(f"{C_BLUE}[2]{C_RESET} Join Aegis Room (Guest)")
    print(f"{C_BLUE}[3]{C_RESET} Exit\n")
    
    choice = input(f"{C_YELLOW}AegisTalk > {C_RESET}")
    
    if choice == '1':
        alias = input(f"{C_YELLOW}[?] Your Alias: {C_RESET}") or "Owner"
        
        # 1. الاتصال
        print(f"{C_BLUE}[*] Starting Server and waiting for guest...{C_RESET}")
        conn = start_owner(alias) # لازم دي ترجع كائن الاتصال (socket)
        
        # 2. المصافحة
        keys = secure_handshake(conn)
        
        # 3. الشات
        secure_chat_loop(conn, keys, alias)
        
    elif choice == '2':
        alias = input(f"{C_YELLOW}[?] Your Alias: {C_RESET}") or "Guest"
        ip = input(f"{C_YELLOW}[?] Owner IP (127.0.0.1): {C_RESET}").strip() or "127.0.0.1"
        
        # 1. Connaction
        print(f"{C_BLUE}[*] Connecting to {ip}...{C_RESET}")
        conn = start_guest(ip, alias) # لازم دي ترجع كائن الاتصال (socket)
        
        # 2. HANDSHAKE
        keys = secure_handshake(conn)
        
        # 3. CHAT
        secure_chat_loop(conn, keys, alias)
        
    elif choice == '3':
        sys.exit()

if __name__ == "__main__":
    os.system('') # Windows color support
    main()