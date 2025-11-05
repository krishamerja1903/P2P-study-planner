import socket
import os
import tqdm

# --- Configuration ---
HOST = '127.0.0.1'  # local host
PORT = 65437        # change port if already in use
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"

def send_file(filename):
    filesize = os.path.getsize(filename)

    print(f"[+] Starting server on {HOST}:{PORT}")
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(1)
    print("[+] Waiting for connection...")

    client_socket, address = s.accept()
    print(f"[+] Connected to {address}")

    # Send filename and filesize
    client_socket.send(f"{os.path.basename(filename)}{SEPARATOR}{filesize}".encode())

    progress = tqdm.tqdm(range(filesize), f"📤 Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        for _ in progress:
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            client_socket.sendall(bytes_read)
            progress.update(len(bytes_read))

    client_socket.close()
    s.close()
    print("[+] File sent successfully and connection closed ✅")

if __name__ == "__main__":
    file_path = input("Enter full file path to send (e.g., C:\\Users\\krish\\Desktop\\demo.pdf): ").strip()
    if os.path.exists(file_path):
        send_file(file_path)
    else:
        print("❌ File not found! Check the path again.")
