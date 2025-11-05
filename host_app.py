# host_app.py
import socket, threading, json, os
import tkinter as tk
from tkinter import messagebox, filedialog
import time

HOST = "127.0.0.1"
PORT = 65500            # pick a port not used by other apps
CHUNK_SIZE = 64 * 1024  # 64 KB

clients = []            # list of (conn, addr)
clients_lock = threading.Lock()

# ---------- Networking helpers ----------
def send_json_line(conn, obj):
    b = (json.dumps(obj) + "\n").encode()
    conn.sendall(b)

def broadcast_json(obj):
    with clients_lock:
        for conn, _ in clients:
            try:
                send_json_line(conn, obj)
            except Exception:
                pass

def broadcast_raw_to_client(conn, file_path):
    """Send FILE_META as JSON line then raw bytes"""
    filesize = os.path.getsize(file_path)
    fname = os.path.basename(file_path)
    meta = {"type":"FILE_META", "filename": fname, "filesize": filesize}
    send_json_line(conn, meta)
    # small pause to ensure peer reads meta first
    time.sleep(0.01)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            conn.sendall(chunk)
    # send FILE_END marker (JSON)
    send_json_line(conn, {"type":"FILE_END", "filename": fname})

def broadcast_file(file_path, log_box):
    with clients_lock:
        if not clients:
            log_box.insert(tk.END, "[!] No peers connected.\n")
            return
        log_box.insert(tk.END, f"[FILE] Sending {os.path.basename(file_path)} to {len(clients)} peers...\n")
        threads = []
        for conn, addr in list(clients):
            t = threading.Thread(target=lambda c=conn, a=addr: (broadcast_raw_to_client(c, file_path)), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        log_box.insert(tk.END, "[FILE] Send complete.\n")

def handle_client(conn, addr, log_box):
    log_box.insert(tk.END, f"[+] Connected: {addr}\n")
    try:
        # Keep the connection alive and optionally listen for future messages from peer
        buffer = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            # We ignore incoming messages for now, but could process edits later.
    except Exception:
        pass
    finally:
        with clients_lock:
            for i,(c,a) in enumerate(clients):
                if c is conn:
                    clients.pop(i)
                    break
        try:
            conn.close()
        except:
            pass
        log_box.insert(tk.END, f"[-] Disconnected: {addr}\n")

def server_thread(log_box):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)
    log_box.insert(tk.END, f"[LISTEN] Host listening on {HOST}:{PORT}\n")
    while True:
        try:
            conn, addr = srv.accept()
        except Exception:
            break
        with clients_lock:
            clients.append((conn, addr))
        t = threading.Thread(target=handle_client, args=(conn, addr, log_box), daemon=True)
        t.start()

# ---------- GUI ----------
root = tk.Tk()
root.title("SyncStudy — Host")
root.geometry("620x560")

tasks = []

def add_task():
    name = task_entry.get().strip()
    if not name:
        messagebox.showwarning("Input", "Enter task name")
        return
    pr = priority_var.get()
    tasks.append({"task": name, "priority": pr})
    tasks.sort(key=lambda x: x["priority"])
    update_task_list()
    task_entry.delete(0, tk.END)

def update_task_list():
    task_list.delete(0, tk.END)
    for t in tasks:
        lvl = "High" if t["priority"]==1 else "Medium" if t["priority"]==2 else "Low"
        task_list.insert(tk.END, f"{t['task']} ({lvl})")

def share_plan():
    if not tasks:
        messagebox.showwarning("No tasks", "Add tasks first")
        return
    broadcast_json({"type":"PLAN", "data": tasks})
    log_box.insert(tk.END, "[SHARE] Plan broadcasted to peers.\n")

def start_session():
    broadcast_json({"type":"START", "data":"Session Started"})
    log_box.insert(tk.END, "[SYNC] Session started broadcasted.\n")

def choose_and_send_file():
    path = filedialog.askopenfilename(title="Select file to send")
    if not path:
        return
    # run send in background so GUI doesn't block
    threading.Thread(target=lambda: broadcast_file(path, log_box), daemon=True).start()

# ---------- Widgets ----------
tk.Label(root, text="SyncStudy — Host", font=("Arial", 16, "bold")).pack(pady=6)

frame = tk.Frame(root)
frame.pack(pady=6)

task_entry = tk.Entry(frame, width=40)
task_entry.grid(row=0, column=0, padx=6)

priority_var = tk.IntVar(value=2)
tk.Radiobutton(frame, text="High", variable=priority_var, value=1).grid(row=0,column=1)
tk.Radiobutton(frame, text="Medium", variable=priority_var, value=2).grid(row=0,column=2)
tk.Radiobutton(frame, text="Low", variable=priority_var, value=3).grid(row=0,column=3)

tk.Button(root, text="Add Task", width=12, command=add_task).pack(pady=6)
tk.Label(root, text="Tasks:").pack()
task_list = tk.Listbox(root, width=80, height=8)
task_list.pack(pady=6)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=4)
tk.Button(btn_frame, text="Share Plan", bg="#4CAF50", fg="white", width=12, command=share_plan).grid(row=0,column=0,padx=6)
tk.Button(btn_frame, text="Start Session", bg="#2196F3", fg="white", width=12, command=start_session).grid(row=0,column=1,padx=6)
tk.Button(btn_frame, text="Send File", bg="#9C27B0", fg="white", width=12, command=choose_and_send_file).grid(row=0,column=2,padx=6)

tk.Label(root, text="Connection Logs:").pack(pady=6)
log_box = tk.Text(root, width=80, height=12)
log_box.pack(pady=4)

# start server thread
t_srv = threading.Thread(target=server_thread, args=(log_box,), daemon=True)
t_srv.start()

root.protocol("WM_DELETE_WINDOW", lambda: (os._exit(0)))  # force exit to close sockets
root.mainloop()
