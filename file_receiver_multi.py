import socket
import os

HOST = "127.0.0.1"
PORT = 65435
BUFFER_SIZE = 4096

def receive_file():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print(f"[+] Connected to host {HOST}:{PORT} ...")

    file_info = s.recv(BUFFER_SIZE).decode()
    file_name, file_size = file_info.split("|")
    file_size = int(file_size)

    s.send(b"OK")

    new_name = "received_" + file_name
    with open(new_name, "wb") as f:
        received = 0
        while received < file_size:
            data = s.recv(BUFFER_SIZE)
            if not data:
                break
            f.write(data)
            received += len(data)

    print(f"✅ File received successfully: {new_name}")
    s.close()

if __name__ == "__main__":
    receive_file()
