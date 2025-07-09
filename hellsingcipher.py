import os
import json
import struct
import hashlib
import getpass
import platform
import socket
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from tqdm import tqdm

# === COLORS ===
PURPLE = "\033[38;5;105m"  # Soft pastel purple (muted)
RESET = "\033[0m"

PROGRAM_NAME = "Hellsing Academy - Tech Division Cypher v11"
BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITER = 200000
LOG_FILE = None

# === LOGGING ===
def get_timestamp():
    return datetime.now().strftime("%m%d%Y-%H%M%S")

def ensure_log_folder():
    if not os.path.exists("log"):
        os.makedirs("log")

def init_log():
    global LOG_FILE
    ensure_log_folder()
    LOG_FILE = os.path.join("log", f"{PROGRAM_NAME}-{get_timestamp()}.log")
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== {PROGRAM_NAME} Session Log ===\n")
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write(f"User: {getpass.getuser()}\n")
        f.write(f"Host: {socket.gethostname()}\n")
        f.write(f"OS: {platform.system()} {platform.release()} ({platform.version()})\n")
        f.write("==================================\n\n")

def log_action(message):
    if LOG_FILE is None:
        init_log()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")

# === CRYPTO ===
def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    if padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode(), salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def shred_file(path):
    try:
        with open(path, 'ba+', buffering=0) as f:
            length = f.tell()
            f.seek(0)
            f.write(os.urandom(length))
        os.remove(path)
        log_action(f"💣 File shredded: {path}")
    except Exception as e:
        log_action(f"❌ Failed to shred {path}: {str(e)}")

# === MESSAGE ENCRYPTION ===
def encrypt_message(message: str, password: str, output_file: str):
    try:
        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(BLOCK_SIZE)
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        data = message.encode('utf-8')
        padded = pad(data)
        encrypted = cipher.encrypt(padded)

        with open(output_file, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(encrypted)

        log_action(f"🔒 Message encrypted to: {output_file}")
        print(f"✅ Message saved to {output_file}")
    except Exception as e:
        log_action(f"❌ Failed to encrypt message: {str(e)}")
        print("❌ Error encrypting message.")

def decrypt_message(input_file: str, password: str):
    try:
        with open(input_file, 'rb') as f:
            salt = f.read(SALT_SIZE)
            iv = f.read(BLOCK_SIZE)
            encrypted = f.read()

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted))

        message = decrypted.decode('utf-8')
        log_action(f"✅ Message decrypted from: {input_file}")
        print("\n📨 Decrypted Message:\n" + message)
    except Exception as e:
        log_action(f"❌ Failed to decrypt message: {str(e)}")
        print("❌ Error decrypting message.")

# === ENCRYPT ===
def encrypt_file(input_path: str, password: str, delete_original=False):
    try:
        log_action(f"Encrypting file: {input_path}")
        filename = os.path.basename(input_path)
        filesize = os.path.getsize(input_path)
        filehash = sha256_file(input_path)

        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(BLOCK_SIZE)
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        header_dict = {
            "filename": filename,
            "filesize": filesize,
            "sha256": filehash,
            "padded": filesize % BLOCK_SIZE != 0
        }
        header_json = json.dumps(header_dict).encode('utf-8')
        header_len = len(header_json)

        enc_path = input_path + '.enc'
        with open(input_path, 'rb') as fin, open(enc_path, 'wb') as fout:
            fout.write(struct.pack('>I', header_len))
            fout.write(header_json)
            fout.write(salt)
            fout.write(iv)

            with tqdm(total=filesize, unit='B', unit_scale=True, desc=f"Encrypting {filename}") as pbar:
                while True:
                    chunk = fin.read(1024 * 1024)
                    if not chunk:
                        break
                    next_chunk = fin.read(1)
                    if next_chunk:
                        fin.seek(-1, 1)
                        encrypted = cipher.encrypt(chunk)
                    else:
                        encrypted = cipher.encrypt(pad(chunk))
                    fout.write(encrypted)
                    pbar.update(len(chunk))

        if delete_original:
            shred_file(input_path)
        log_action(f"✅ Encrypted: {enc_path}")
        return True

    except Exception as e:
        log_action(f"❌ Failed to encrypt {input_path}: {str(e)}")
        return False

# === DECRYPT ===
def decrypt_file(encrypted_path: str, password: str, delete_encrypted=False):
    try:
        with open(encrypted_path, 'rb') as fin:
            header_len_bytes = fin.read(4)
            header_len = struct.unpack('>I', header_len_bytes)[0]
            header_json = fin.read(header_len)
            header = json.loads(header_json.decode('utf-8'))

            salt = fin.read(SALT_SIZE)
            iv = fin.read(BLOCK_SIZE)
            key = derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)

            dec_path = os.path.join(os.path.dirname(encrypted_path), header['filename'])
            temp_path = dec_path + ".tmp"

            with open(temp_path, 'wb') as fout:
                with tqdm(unit='B', unit_scale=True, desc=f"Decrypting {header['filename']}") as pbar:
                    while True:
                        enc_chunk = fin.read(1024 * 1024)
                        if not enc_chunk:
                            break
                        decrypted = cipher.decrypt(enc_chunk)
                        fout.write(decrypted)
                        pbar.update(len(enc_chunk))

        success = False
        with open(temp_path, 'rb') as f:
            data = f.read()
        try:
            final_data = unpad(data) if header.get("padded", True) else data
            with open(dec_path, 'wb') as real_out:
                real_out.write(final_data)
            os.remove(temp_path)
            success = True
        except Exception:
            try:
                f.close()
                if not os.path.exists(dec_path + ".broken"):
                    os.rename(temp_path, dec_path + ".broken")
                log_action(f"❌ Decryption failed (bad padding): {dec_path}")
            except Exception as e:
                log_action(f"❌ Decryption exception while renaming temp: {str(e)}")
            return False

        if success:
            if sha256_file(dec_path) == header['sha256']:
                log_action(f"✅ Decryption successful: {dec_path}")
                if delete_encrypted:
                    shred_file(encrypted_path)
                print(f"✅ SUCCESS: {dec_path}")
                return True
            else:
                log_action(f"⚠️ Integrity check failed: {dec_path}")
                print(f"⚠️ WARN: Hash mismatch for {dec_path}")
                return False

    except Exception as e:
        log_action(f"❌ Decryption exception: {str(e)}")
        return False

# === FOLDER ===
def encrypt_folder(folder_path, password, delete_original=False):
    total, success, failed = 0, 0, 0
    for root, _, files in os.walk(folder_path):
        for f in files:
            full_path = os.path.join(root, f)
            total += 1
            result = encrypt_file(full_path, password, delete_original)
            success += result
            failed += not result
    print(f"\n📦 Encrypt Folder Summary: Success {success}, Failed {failed}")

def decrypt_folder(folder_path, password, delete_encrypted=False):
    total, success, failed = 0, 0, 0
    for root, _, files in os.walk(folder_path):
        for f in files:
            if not f.endswith('.enc'):
                continue
            full_path = os.path.join(root, f)
            total += 1
            result = decrypt_file(full_path, password, delete_encrypted)
            success += result
            failed += not result
    print(f"\n📦 Decrypt Folder Summary: Success {success}, Failed {failed}")

def prompt_password():
    while True:
        pw1 = getpass.getpass("Password: ")
        pw2 = getpass.getpass("Confirm Password: ")
        if pw1 == pw2:
            return pw1
        else:
            print("❌ Passwords do not match. Please try again.")


# === MENU ===
def menu():
    init_log()
    while True:
        print(PURPLE + r"""
██╗  ██╗███████╗██╗     ██╗     ███████╗██╗███╗   ██╗ ██████╗ 
██║  ██║██╔════╝██║     ██║     ██╔════╝██║████╗  ██║██╔════╝ 
███████║█████╗  ██║     ██║     ███████╗██║██╔██╗ ██║██║  ███╗
██╔══██║██╔══╝  ██║     ██║     ╚════██║██║██║╚██╗██║██║   ██║
██║  ██║███████╗███████╗███████╗███████║██║██║ ╚████║╚██████╔╝
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
 █████╗  ██████╗ █████╗ ██████╗ ███████╗███╗   ███╗██╗   ██╗  
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝████╗ ████║╚██╗ ██╔╝  
███████║██║     ███████║██║  ██║█████╗  ██╔████╔██║ ╚████╔╝   
██╔══██║██║     ██╔══██║██║  ██║██╔══╝  ██║╚██╔╝██║  ╚██╔╝    
██║  ██║╚██████╗██║  ██║██████╔╝███████╗██║ ╚═╝ ██║   ██║     
╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝     ╚═╝   ╚═╝     
████████╗███████╗ ██████╗██╗  ██╗   ██████╗ ██╗██╗   ██╗      
╚══██╔══╝██╔════╝██╔════╝██║  ██║   ██╔══██╗██║██║   ██║      
   ██║   █████╗  ██║     ███████║   ██║  ██║██║██║   ██║      
   ██║   ██╔══╝  ██║     ██╔══██║   ██║  ██║██║╚██╗ ██╔╝      
   ██║   ███████╗╚██████╗██║  ██║██╗██████╔╝██║ ╚████╔╝       
   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═══╝        
       ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗        
      ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗       
█████╗██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝█████╗ 
╚════╝██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗╚════╝ 
      ╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║       
        
🛡️ Welcome to the HellsingCipher Encryption Suite v11.0 🛡️
""" + RESET)
        print("1) Encrypt Message")
        print("2) Decrypt Message")
        print("3) Encrypt File")
        print("4) Decrypt File")
        print("5) Encrypt Folder")
        print("6) Decrypt Folder")
        print("7) Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            msg = input("Message to encrypt: ")
            pw = prompt_password()
            out = input("Output file name (e.g., message.enc): ")
            encrypt_message(msg, pw, out)
        elif choice == '2':
            path = input("Encrypted message file: ")
            pw = getpass.getpass("Password: ")
            decrypt_message(path, pw)
        elif choice == '3':
            path = input("File to encrypt: ")
            pw = prompt_password()
            shred = input("Shred original? (y/n): ").lower() == 'y'
            encrypt_file(path, pw, shred)
        elif choice == '4':
            path = input("File to decrypt: ")
            pw = getpass.getpass("Password: ")
            shred = input("Delete encrypted file after decrypt? (y/n): ").lower() == 'y'
            decrypt_file(path, pw, shred)
        elif choice == '5':
            path = input("Folder to encrypt: ")
            pw = prompt_password()
            shred = input("Shred originals? (y/n): ").lower() == 'y'
            encrypt_folder(path, pw, shred)
        elif choice == '6':
            path = input("Folder to decrypt: ")
            pw = getpass.getpass("Password: ")
            shred = input("Delete encrypted files after decrypt? (y/n): ").lower() == 'y'
            decrypt_folder(path, pw, shred)
        elif choice == '7':
            print("Goodbye, my friend.")
            break
        else:
            print("Invalid.")

if __name__ == "__main__":
    menu()
