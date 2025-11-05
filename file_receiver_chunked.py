import socket
from tqdm import tqdm
from crypto_utils import decrypt_data

HOST = '127.0.0.1'
PORT = 65435
BUFFER_SIZE = 4096

def receive_file(save_path="received_file"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print(f"[+] Connected to host {HOST}:{PORT}")

    all_data = b""
    try:
        while True:
            chunk = s.recv(BUFFER_SIZE)
            if not chunk:
                break
            all_data += chunk
    except Exception as e:
        pass

    decrypted = decrypt_data(all_data)
    with open(save_path, "wb") as f:
        f.write(decrypted)

    print(f"✅ File received and decrypted: {save_path}")
    s.close()

if __name__ == "__main__":
    save_path = input("Enter path to save received file: ")
    receive_file(save_path)
