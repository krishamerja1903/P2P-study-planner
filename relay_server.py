import socket
import threading

HOST = "127.0.0.1"
PORT = 65435  # Base port, fallback if busy
MAX_CONNECTIONS = 10

clients = []
clients_lock = threading.Lock()

def relay_data(src_conn, src_addr):
    try:
        while True:
            data = src_conn.recv(4096)
            if not data:
                break
            with clients_lock:
                for c, a in clients:
                    if c != src_conn:
                        try:
                            c.sendall(data)
                        except:
                            pass
    except:
        pass
    finally:
        with clients_lock:
            clients[:] = [(c, a) for c, a in clients if c != src_conn]
        src_conn.close()
        print(f"[-] {src_addr} disconnected")

def run_server():
    global PORT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Auto-fallback if port is busy
    while True:
        try:
            s.bind((HOST, PORT))
            break
        except OSError:
            PORT += 1  # Try next port

    s.listen(MAX_CONNECTIONS)
    print(f"[+] Relay Server running on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        print(f"[+] Client connected: {addr}")
        with clients_lock:
            clients.append((conn, addr))
        threading.Thread(target=relay_data, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    run_server()
