import socket
from tqdm import tqdm
from crypto_utils import encrypt_data

HOST = '127.0.0.1'
PORT = 65435
BUFFER_SIZE = 4096

def send_file(file_path):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[+] Waiting for connection on {HOST}:{PORT}...")
    conn, addr = s.accept()
    print(f"[+] Connected to {addr}")

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = encrypt_data(data)
    total = len(encrypted_data)

    print(f"📤 Sending file in chunks...")
    for i in tqdm(range(0, total, BUFFER_SIZE)):
        conn.send(encrypted_data[i:i+BUFFER_SIZE])

    print("✅ File sent successfully!")
    conn.close()
    s.close()

if __name__ == "__main__":
    file_path = input("Enter file path to send: ")
    send_file(file_path)
