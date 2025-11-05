# peer_app.py
import socket, threading, json, os
import tkinter as tk
from tkinter import messagebox

HOST = "127.0.0.1"
PORT = 65500
BUFFER_SIZE = 64*1024
DOWNLOAD_DIR = os.path.join(os.getcwd(), "downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

sock = None
recv_thread = None

def recv_line(s):
    # read until newline and return decoded string (without newline)
    data = b""
    while True:
        ch = s.recv(1)
        if not ch:
            return None
        if ch == b"\n":
            break
        data += ch
    return data.decode()

def listen_loop(s, task_listbox, log_box):
    while True:
        try:
            header = recv_line(s)
            if header is None:
                log_box.insert(tk.END, "[INFO] Connection closed by host\n")
                break
            msg = json.loads(header)
            mtype = msg.get("type")
            if mtype == "PLAN":
                tasks = msg.get("data", [])
                root.after(0, lambda: update_task_listbox(task_listbox, tasks))
                log_box.insert(tk.END, "[RECV] Study plan updated\n")
            elif mtype == "START":
                log_box.insert(tk.END, "[RECV] Session started\n")
                root.after(0, lambda: messagebox.showinfo("Session", "Session started by Host"))
            elif mtype == "FILE_META":
                fname = msg.get("filename")
                fsize = int(msg.get("filesize", 0))
                log_box.insert(tk.END, f"[FILE] Incoming {fname} ({fsize} bytes)\n")
                # now read fsize bytes
                out_path = os.path.join(DOWNLOAD_DIR, fname)
                with open(out_path, "wb") as f:
                    left = fsize
                    while left > 0:
                        chunk = s.recv(min(BUFFER_SIZE, left))
                        if not chunk:
                            break
                        f.write(chunk)
                        left -= len(chunk)
                log_box.insert(tk.END, f"[FILE] Saved: {out_path}\n")
                root.after(0, lambda: messagebox.showinfo("File received", f"Saved: {out_path}"))
            elif mtype == "FILE_END":
                # optional end marker
                pass
        except Exception as e:
            log_box.insert(tk.END, f"[ERR] {e}\n")
            break
    try:
        s.close()
    except:
        pass

def connect_to_host(task_listbox, log_box, btn):
    global sock, recv_thread
    if sock:
        messagebox.showinfo("Already", "Already connected")
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
    except Exception as e:
        messagebox.showerror("Connect", f"Could not connect: {e}")
        return
    sock = s
    btn.config(state=tk.DISABLED)
    log_box.insert(tk.END, "[CONNECTED] to Host\n")
    recv_thread = threading.Thread(target=listen_loop, args=(s, task_listbox, log_box), daemon=True)
    recv_thread.start()

def update_task_listbox(lb, tasks):
    lb.delete(0, tk.END)
    for t in tasks:
        lvl = "High" if t["priority"]==1 else "Medium" if t["priority"]==2 else "Low"
        lb.insert(tk.END, f"{t['task']} ({lvl})")

# ---------- GUI ----------
root = tk.Tk()
root.title("SyncStudy — Peer")
root.geometry("520x480")

tk.Label(root, text="SyncStudy — Peer", font=("Arial",14,"bold")).pack(pady=6)
tk.Label(root, text="Received Tasks:").pack()
task_listbox = tk.Listbox(root, width=60, height=8)
task_listbox.pack(pady=6)

tk.Label(root, text="Connection & File Logs:").pack()
log_box = tk.Text(root, width=70, height=12)
log_box.pack(pady=6)

connect_btn = tk.Button(root, text="Connect to Host", bg="#4CAF50", fg="white",
                        command=lambda: connect_to_host(task_listbox, log_box, connect_btn))
connect_btn.pack(pady=4)

root.protocol("WM_DELETE_WINDOW", lambda: (os._exit(0)))
root.mainloop()
