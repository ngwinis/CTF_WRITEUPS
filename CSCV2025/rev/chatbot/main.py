import base64
import json
import time
import random
import os
import sys
import ctypes
from ctypes import CDLL, c_char_p, c_int, c_void_p
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def get_resource_path(name):
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(__file__)
    return os.path.join(base, name)

def load_native_lib(name):
    return CDLL(get_resource_path(name))

# Load native library
if sys.platform == 'win32':
    LIBNAME = 'libnative.dll'
else:
    LIBNAME = 'libnative.so'

lib = None
check_integrity = None
decrypt_flag_file = None
free_mem = None

try:
    lib = load_native_lib(LIBNAME)
    
    # Setup check_integrity function
    check_integrity = lib.check_integrity
    check_integrity.argtypes = [c_char_p]
    check_integrity.restype = c_int
    
    # Setup decrypt_flag_file function
    decrypt_flag_file = lib.decrypt_flag_file
    decrypt_flag_file.argtypes = [c_char_p]
    decrypt_flag_file.restype = c_void_p
    
    # Setup free_mem function
    free_mem = lib.free_mem
    free_mem.argtypes = [c_void_p]
    free_mem.restype = None
    
except Exception as e:
    print("Warning: native lib not loaded:", e)
    lib = None
    check_integrity = None
    decrypt_flag_file = None
    free_mem = None

def run_integrity_or_exit():
    if check_integrity:
        ok = check_integrity(sys.executable.encode())
        if not ok:
            print("[!] Integrity failed or debugger detected. Exiting.")
            sys.exit(1)

# Public key for token verification
PUB_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsJftFGJC6RjAC54aMncA
fjb2xXeRECiwHuz2wC6QynDd93/7XIrqTObeTpfBCSpOKRLhks6/nzZFTTsYdQCj
4roXhWo5lFfH0OTL+164VoKnmUkQ9dppzpmV0Kpk5IQhEyuPYzJfFAlafcHdQvUo
idkqcOPpR7hznJPEuRbPxJod34Bph/u9vePKcQQfe+/l/nn02nbfYWTuGtuEdpHq
Mkktl4WpB50/a5ZqYkW4z0zjFCY5LIPE7mpUNLrZnadBGIaLoVV2lZEBdLt6iLkV
HXIr+xNA9ysE304T0JJ/DwM1OXb4yVrtawbFLBu9otOC+Gu0Set+8OjfQvJ+tlT/
zQIDAQAB
-----END PUBLIC KEY-----"""

public_key = None

try:
    pub_path = get_resource_path('public.pem')
    
    if os.path.exists(pub_path):
        with open(pub_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        public_key = serialization.load_pem_public_key(PUB_PEM.encode())
        
except Exception as e:
    print("Failed loading public key:", e)
    public_key = None

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def b64url_decoder(s):
    s = s + '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

def verify_token(token):
    if not public_key:
        return (False, "no public key")
    
    try:
        payload_b64, sig_b64 = token.strip().split('.', 1)
        payload = b64url_decoder(payload_b64)
        sig = b64url_decoder(sig_b64)
        
        public_key.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
        
        j = json.loads(payload.decode())
        
        if j.get('role') != 'VIP':
            return (False, 'role != VIP')
        
        if j.get('expiry', 0) < int(time.time()):
            return (False, 'expired')
        
        return (True, j)
        
    except Exception as e:
        return (False, str(e))

def sample_token_nonvip():
    payload = json.dumps({"user": "guest", "expiry": int(time.time()) + 3600, "role": "USER"}).encode()
    return b64url_encode(payload)



def main():
    run_integrity_or_exit()
    
    print("=== Bot Chat === \n    1.chat\n    2.showtoken\n    3.upgrade \n    4.quit")
    
    queries = 3
    
    while True:
        cmd = input("> ").strip().lower()
        
        if cmd in ('quit', 'exit'):
            return
        
        elif cmd == 'chat':
            if queries > 0:
                print(random.choice([
                    "Hi", "Demo AI", "Hello!", "How can I assist you?",
                    "I am a chatbot", "What do you want?", "Tell me more",
                    "Interesting", "Go on...", "SIUUUUUU", "I LOVE U",
                    "HACK TO LEARN NOT LEARN TO HACK"
                ]))
                queries -= 1
            else:
                print("Free queries exhausted. Use 'upgrade'")
        
        elif cmd == 'showtoken':
            print("Token current:" + sample_token_nonvip())
        
        elif cmd == 'upgrade':
            run_integrity_or_exit()
            token = input("\nPaste token: ").strip()
            ok, info = verify_token(token)
            
            if ok:
                if decrypt_flag_file is None:
                    print("Native library not available -> cannot decrypt")
                else:
                    flag_path = input("flag.enc").strip()
                    res_ptr = decrypt_flag_file(flag_path.encode())
                    
                    if not res_ptr:
                        print("Native failed to decrypt or error")
                    else:
                        flag_bytes = ctypes.string_at(res_ptr)
                        try:
                            flag = flag_bytes.decode(errors='ignore')
                        except:
                            flag = flag_bytes.decode('utf-8', errors='replace')
                        
                        print("=== VIP VERIFIED ===")
                        print(flag)
                        free_mem(res_ptr)
                        return
            else:
                print("Token invalid:", info)
        
        else:
            print("Unknown. Use chat/showtoken/upgrade/quit")

if __name__ == '__main__':
    main()
