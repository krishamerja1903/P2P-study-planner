import socket
import threading
import json
import tkinter as tk
from tkinter import messagebox
import base64
import os

HOST = "127.0.0.1"
PORT = 65432

tasks = []
# for incoming file assembly: {filename: {total:int, chunks:dict}}
incoming_files = {}
DOWNLOAD_DIR = os.path.join(os.getcwd(), "downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def receive(sock, task_list_box, log_box):
    while True:
        try:
            data = sock.recv(65536)
            if not data:
                log_box.insert(tk.END, "[INFO] Server closed connection.\n")
                break
            try:
                msg = json.loads(data.decode())
            except:
                # If decode fails, skip
                continue

            mtype = msg.get("type")
            payload = msg.get("data")

            if mtype == "plan":
                global tasks
                tasks = payload
                update_task_list(task_list_box)
                log_box.insert(tk.END, "[RECEIVED] Study plan updated.\n")

            elif mtype == "start":
                log_box.insert(tk.END, "[SESSION] Study session started!\n")
                messagebox.showinfo("Session Started", "Study session started!")

            elif mtype == "FILE_META":
                fname = payload.get("filename")
                total = payload.get("total_chunks", 0)
                incoming_files[fname] = {"total": total, "chunks": {}}
                log_box.insert(tk.END, f"[FILE] Incoming {fname}, expecting {total} chunks\n")

            elif mtype == "FILE_CHUNK":
                info = payload
                fname = info.get("filename")
                idx = info.get("idx")
                b64 = info.get("chunk")
                if fname not in incoming_files:
                    incoming_files[fname] = {"total": None, "chunks": {}}
                incoming_files[fname]["chunks"][idx] = b64
                total_known = incoming_files[fname].get("total")
                log_box.insert(tk.END, f"[FILE] Received chunk {idx} for {fname}\n")

            elif mtype == "FILE_END":
                fname = payload.get("filename")
                # assemble file
                entry = incoming_files.get(fname)
                if not entry:
                    log_box.insert(tk.END, f"[FILE] No chunks found for {fname}\n")
                    continue
                chunks = entry["chunks"]
                # write in order
                out_path = os.path.join(DOWNLOAD_DIR, fname)
                with open(out_path, "wb") as out_f:
                    for i in sorted(chunks.keys()):
                        try:
                            out_f.write(base64.b64decode(chunks[i]))
                        except:
                            pass
                log_box.insert(tk.END, f"[FILE] Saved {fname} -> {out_path}\n")
                messagebox.showinfo("File Received", f"Received file: {fname}\nSaved to downloads folder.")
                # cleanup entry
                incoming_files.pop(fname, None)
        except Exception as e:
            log_box.insert(tk.END, f"[ERROR] receive thread: {e}\n")
            break

def connect_to_host(task_list_box, log_box, connect_btn):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except Exception as e:
        messagebox.showerror("Connection Error", f"Could not connect to Host: {e}")
        return None
    log_box.insert(tk.END, "[CONNECTED] Connected to Host.\n")
    connect_btn.config(state=tk.DISABLED)
    threading.Thread(target=receive, args=(sock, task_list_box, log_box), daemon=True).start()
    return sock

def update_task_list(task_list_box):
    task_list_box.delete(0, tk.END)
    for t in tasks:
        level = "High" if t["priority"] == 1 else "Medium" if t["priority"] == 2 else "Low"
        task_list_box.insert(tk.END, f"{t['task']} ({level})")

# ---- UI ----
root = tk.Tk()
root.title("SyncStudy – Peer Panel (FileShare)")
root.geometry("520x480")
root.resizable(False, False)

tk.Label(root, text="📋 Received Study Tasks").pack(pady=5)
task_list_box = tk.Listbox(root, width=60, height=10)
task_list_box.pack(pady=5)

tk.Label(root, text="🔌 Connection & File Logs").pack()
log_box = tk.Text(root, width=70, height=12)
log_box.pack(pady=5)

connect_btn = tk.Button(root, text="Connect to Host", bg="#4CAF50", fg="white",
                        command=lambda: connect_to_host(task_list_box, log_box, connect_btn))
connect_btn.pack(pady=5)

root.mainloop()
