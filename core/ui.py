import sys

class UI:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    END = "\033[0m"

def banner():
    print(UI.CYAN + UI.BOLD)
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("        Kryphorix Scanner     ")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + UI.END)

def section(title):
    print(UI.BLUE + f"\n[ {title} ]" + UI.END)

def info(msg):
    print(UI.CYAN + "[*] " + msg + UI.END)

def good(msg):
    print(UI.GREEN + "[+] " + msg + UI.END)

def warn(msg):
    print(UI.YELLOW + "[!] " + msg + UI.END)

def bad(msg):
    print(UI.RED + "[-] " + msg + UI.END)

