import requests, socket
from time import sleep
from core.config_loader import load_config

CFG=load_config()

def safe_request(method,url):
    for _ in range(2):
        try: return requests.request(method,url,timeout=CFG["timeout"],verify=True)
        except: sleep(1)
    return None

def check_port(host,port):
    try:
        socket.create_connection((host,port),timeout=3).close()
        return True
    except:
        return False

