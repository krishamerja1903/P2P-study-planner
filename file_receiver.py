import socket
import tqdm
import os

# --- Configuration ---
HOST = '127.0.0.1'  # same as sender
PORT = 65437
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"

print(f"[+] Connecting to {HOST}:{PORT} ...")
s = socket.socket()
s.connect((HOST, PORT))
print("[+] Connected to host ✅")

# Receive file info
received = s.recv(BUFFER_SIZE).decode()
filename, filesize = received.split(SEPARATOR)
filename = os.path.basename(filename)
filesize = int(filesize)

# Save file
progress = tqdm.tqdm(range(filesize), f"📥 Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(filename, "wb") as f:
    for _ in progress:
        bytes_read = s.recv(BUFFER_SIZE)
        if not bytes_read:
            break
        f.write(bytes_read)
        progress.update(len(bytes_read))

print(f"[+] File {filename} received successfully ✅")
s.close()
