import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 65432

def receive(sock):
    """Continuously receive messages from server"""
    while True:
        try:
            data = sock.recv(1024).decode()
            if not data:
                print("\n[INFO] Server closed the connection.")
                break
            msg = json.loads(data)

            msg_type = msg.get("type")
            payload = msg.get("data")

            if msg_type == "COMMAND":
                print(f"\n🚀 [COMMAND] {payload}")
            else:
                print(f"\n📩 [MESSAGE RECEIVED] {payload}")
        except (ConnectionResetError, OSError):
            print("\n[INFO] Connection lost. Closing client...")
            break
        except json.JSONDecodeError:
            continue

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except Exception as e:
        print(f"[ERROR] Could not connect to server: {e}")
        return

    print("[CONNECTED] to server")

    threading.Thread(target=receive, args=(sock,), daemon=True).start()

    while True:
        try:
            text = input("\nType a message ('start' = command, 'exit' = quit): ").strip()
            if text.lower() == "exit":
                print("[DISCONNECTING]")
                sock.close()
                break
            elif text.lower() == "start":
                msg = {"type": "COMMAND", "data": "SESSION STARTED!"}
            else:
                msg = {"type": "DATA", "data": text}

            sock.sendall(json.dumps(msg).encode())

        except (BrokenPipeError, OSError):
            print("[ERROR] Server disconnected. Exiting client...")
            break

if __name__ == "__main__":
    main()
