import os
import sys
import time
import pyfiglet
from src.network.owner import start_owner
from src.network.guest import start_guest

# ANSI Colors
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_RESET = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    
    """Generate dynamic ASCII banner using pyfiglet."""
    # Using the exact format you requested
    banner = pyfiglet.figlet_format("AegisTalk", font="standard")
    print(f"{C_GREEN}{banner}{C_RESET}")
    print(f"{C_YELLOW}[+] Network Reconnaissance & Secure Chat")
    print(f"[+] Developed by BROs | Phase 3: KDF Ready{C_RESET}\n")

def main():
    clear_screen()
    print_banner()
    
    print(f"{C_BLUE}[1]{C_RESET} Host Aegis Room (Owner)")
    print(f"{C_BLUE}[2]{C_RESET} Join Aegis Room (Guest)")
    print(f"{C_BLUE}[3]{C_RESET} Exit\n")
    
    choice = input(f"{C_YELLOW}AegisTalk > {C_RESET}")
    
    if choice == '1':
        alias = input(f"{C_YELLOW}[?] Your Alias: {C_RESET}") or "Owner"
        start_owner(alias)
        
    elif choice == '2':
        alias = input(f"{C_YELLOW}[?] Your Alias: {C_RESET}") or "Guest"
        ip = input(f"{C_YELLOW}[?] Owner IP (127.0.0.1): {C_RESET}").strip() or "127.0.0.1"
        start_guest(ip, alias)
        
    elif choice == '3':
        sys.exit()

if __name__ == "__main__":
    os.system('') # Windows color support
    main()