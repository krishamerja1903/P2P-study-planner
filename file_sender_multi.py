import socket
import threading
import os

HOST = "127.0.0.1"
PORT = 65435
BUFFER_SIZE = 4096

clients = []

def handle_client(conn, addr, file_data, file_name):
    try:
        print(f"[+] Sending to {addr} ...")
        conn.send(f"{file_name}|{len(file_data)}".encode())
        conn.recv(2)  # wait for 'OK'
        conn.sendall(file_data)
        print(f"✅ File sent to {addr}")
    except Exception as e:
        print(f"[❌] Error sending to {addr}: {e}")
    finally:
        conn.close()

def start_server(file_path):
    global clients
    if not os.path.exists(file_path):
        print("[!] File not found.")
        return

    with open(file_path, "rb") as f:
        file_data = f.read()
    file_name = os.path.basename(file_path)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    print(f"[+] Waiting for peers to connect on {HOST}:{PORT} ...")
    while True:
        s.settimeout(5)
        try:
            conn, addr = s.accept()
            print(f"[+] {addr} connected.")
            clients.append((conn, addr))
        except socket.timeout:
            break

    input("👉 Press ENTER after all peers connected to start sending...\n")

    print(f"📤 Sending {file_name} to all peers...")
    threads = []
    for conn, addr in clients:
        t = threading.Thread(target=handle_client, args=(conn, addr, file_data, file_name))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("✅ File sent successfully to all peers!")
    s.close()

if __name__ == "__main__":
    file_path = input("Enter file path to send: ").strip()
    start_server(file_path)
