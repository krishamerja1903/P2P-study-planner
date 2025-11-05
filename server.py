import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 65432
clients = []

def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    try:
        while True:
            data = conn.recv(65536)            # larger buffer
            if not data:
                break
            # Broadcast raw bytes to everyone (including sender)
            broadcast(data, exclude=None)
    except Exception as e:
        print("Client error:", e)
    finally:
        if conn in clients:
            clients.remove(conn)
        conn.close()
        print(f"[-] Disconnected: {addr}")

def broadcast(data_bytes, exclude=None):
    for c in list(clients):
        if c is exclude:
            continue
        try:
            c.sendall(data_bytes)
        except Exception:
            try: clients.remove(c)
            except: pass

def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen()
    print(f"[LISTENING] Server started on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = srv.accept()
            clients.append(conn)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[SERVER SHUTDOWN]")
    finally:
        for c in clients:
            try: c.close()
            except: pass
        srv.close()

if __name__ == "__main__":
    start_server()
