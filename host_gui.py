import socket
import threading
import json
import tkinter as tk
from tkinter import messagebox, filedialog
import base64
import os

# HOST / SERVER SETTINGS
HOST = "127.0.0.1"
PORT = 65432
clients = []
tasks = []

# --- Simple broadcast helper (sends JSON bytes) ---
def broadcast_json(data):
    try:
        b = json.dumps(data).encode()
        # send to connected peers via server socket? Host GUI acts as server broadcaster via server.py
        # Here host GUI will send to server (server.py) which will broadcast to peers.
        # So host GUI must connect as client to the central server and send JSON bytes.
        if hasattr(host_gui, "sock") and host_gui.sock:
            host_gui.sock.sendall(b)
    except Exception as e:
        log_box.insert(tk.END, f"[ERROR] Could not send: {e}\n")

# -----------------------------
# Connect Host GUI as a client to the central broadcast server
# (This allows Host GUI to send messages that server.py will broadcast)
# -----------------------------
def connect_to_broadcast_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        log_box.insert(tk.END, "[CONNECTED] Host GUI connected to broadcast server.\n")
        # keep receive thread to show any incoming logs (optional)
        threading.Thread(target=receive_thread, args=(s,), daemon=True).start()
        return s
    except Exception as e:
        log_box.insert(tk.END, f"[ERROR] Cannot connect server: {e}\n")
        return None

def receive_thread(sock):
    while True:
        try:
            data = sock.recv(65536)
            if not data:
                break
            # we don't expect many inbound messages to Host GUI but show them
            try:
                msg = json.loads(data.decode())
                log_box.insert(tk.END, f"[IN] {msg}\n")
            except:
                log_box.insert(tk.END, f"[IN-BYTES] {len(data)} bytes\n")
        except:
            break

# -----------------------------
# GUI functions
# -----------------------------
def add_task():
    name = task_entry.get()
    priority = priority_var.get()
    if not name:
        messagebox.showwarning("Input Error", "Enter a task name!")
        return
    tasks.append({"task": name, "priority": priority})
    tasks.sort(key=lambda x: x["priority"])
    update_task_list()
    task_entry.delete(0, tk.END)

def update_task_list():
    task_list.delete(0, tk.END)
    for t in tasks:
        level = "High" if t["priority"] == 1 else "Medium" if t["priority"] == 2 else "Low"
        task_list.insert(tk.END, f"{t['task']} ({level})")

def share_plan():
    if not tasks:
        messagebox.showwarning("No Tasks", "Add some tasks first!")
        return
    msg = {"type":"plan", "data": tasks}
    broadcast_json(msg)
    log_box.insert(tk.END, "[SHARED] Study plan sent to peers.\n")

def start_session():
    msg = {"type":"start", "data":"Session Started!"}
    broadcast_json(msg)
    log_box.insert(tk.END, "[SYNC] Session started for all peers!\n")

# ---------- File sharing ----------
CHUNK_SIZE = 50 * 1024   # 50 KB per chunk (demo-friendly)

def send_file_dialog():
    filepath = filedialog.askopenfilename(title="Select file to send")
    if not filepath:
        return
    threading.Thread(target=send_file, args=(filepath,), daemon=True).start()

def send_file(filepath):
    try:
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE
        log_box.insert(tk.END, f"[FILE] Sending {filename} ({filesize} bytes) in {total_chunks} chunks\n")

        # send FILE_META
        meta = {"type":"FILE_META", "data":{"filename":filename, "filesize":filesize, "total_chunks":total_chunks}}
        broadcast_json(meta)

        with open(filepath, "rb") as f:
            idx = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                idx += 1
                b64 = base64.b64encode(chunk).decode()
                chunk_msg = {"type":"FILE_CHUNK", "data":{"filename":filename, "idx":idx, "chunk":b64}}
                broadcast_json(chunk_msg)
                log_box.insert(tk.END, f"[FILE] Sent chunk {idx}/{total_chunks}\n")
        # send FILE_END
        end_msg = {"type":"FILE_END", "data":{"filename":filename}}
        broadcast_json(end_msg)
        log_box.insert(tk.END, f"[FILE] Completed sending {filename}\n")
    except Exception as e:
        log_box.insert(tk.END, f"[ERROR] File send error: {e}\n")

# -----------------------------
# Build UI
# -----------------------------
root = tk.Tk()
root.title("SyncStudy – Host Panel (FileShare)")
root.geometry("600x520")
root.resizable(False, False)

# Task input UI
tk.Label(root, text="📘 Add New Task").pack(pady=5)
task_entry = tk.Entry(root, width=50)
task_entry.pack(pady=2)
priority_var = tk.IntVar(value=2)
tk.Label(root, text="Priority:").pack()
tk.Radiobutton(root, text="High", variable=priority_var, value=1).pack()
tk.Radiobutton(root, text="Medium", variable=priority_var, value=2).pack()
tk.Radiobutton(root, text="Low", variable=priority_var, value=3).pack()
tk.Button(root, text="Add Task", command=add_task).pack(pady=5)

tk.Label(root, text="📋 Study Tasks").pack()
task_list = tk.Listbox(root, width=70, height=8)
task_list.pack(pady=5)

# action buttons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=6)
tk.Button(btn_frame, text="Share Plan", bg="#4CAF50", fg="white", command=share_plan, width=15).grid(row=0, column=0, padx=6)
tk.Button(btn_frame, text="Start Session", bg="#2196F3", fg="white", command=start_session, width=15).grid(row=0, column=1, padx=6)
tk.Button(btn_frame, text="Send File", bg="#9C27B0", fg="white", command=send_file_dialog, width=15).grid(row=0, column=2, padx=6)

tk.Label(root, text="🔌 Connection & File Logs").pack()
log_box = tk.Text(root, width=80, height=12)
log_box.pack(pady=5)

# connect host GUI to broadcast server (so host can send messages via central server)
host_gui = type("HG", (), {})()   # simple object to hold sock
host_gui.sock = connect_to_broadcast_server()

root.mainloop()
