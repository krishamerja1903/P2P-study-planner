import tkinter as tk
from tkinter import messagebox
import json
import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 9999

# ===== networking =====
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connected = False

def try_connect():
    global connected
    try:
        sock.connect((HOST, PORT))
        connected = True
        print("Connected to server")
    except Exception as e:
        connected = False
        print("Could not connect to server:", e)

# Try to connect immediately (if server not up, connection fails)
try_connect()

# ===== GUI =====
root = tk.Tk()
root.title("SyncStudy - GUI Client")
root.geometry("420x520")
root.resizable(False, False)

tasks = []

# ===== UI functions =====
def update_task_list():
    listbox.delete(0, tk.END)
    for t in tasks:
        level = "High" if t["priority"] == 1 else "Medium" if t["priority"] == 2 else "Low"
        listbox.insert(tk.END, f"{t['task']} ({level})")

def add_task():
    task_name = task_entry.get().strip()
    if not task_name:
        messagebox.showwarning("Input Error", "Please enter a task name!")
        return
    priority = priority_var.get()
    tasks.append({"task": task_name, "priority": priority})
    tasks.sort(key=lambda x: x["priority"])
    update_task_list()
    task_entry.delete(0, tk.END)

def share_plan():
    if not connected:
        messagebox.showerror("Not connected", "Client not connected to server. Start server first.")
        return
    try:
        data = json.dumps(tasks)
        sock.sendall(data.encode())
        messagebox.showinfo("Shared", "Study Plan Shared Successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Could not send data: {e}")

def start_session():
    if not connected:
        messagebox.showerror("Not connected", "Client not connected to server. Start server first.")
        return
    try:
        sock.sendall("START_SESSION".encode())
        # Local feedback immediately
        messagebox.showinfo("Session", "Session Started (signal sent).")
    except Exception as e:
        messagebox.showerror("Error", f"Could not send start signal: {e}")

# ===== Listener thread =====
def listen_thread():
    global tasks
    if not connected:
        return
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            try:
                txt = data.decode()
            except:
                continue
            # START_SESSION signal
            if txt == "START_SESSION":
                # show popup in main thread
                root.after(0, lambda: messagebox.showinfo("Session", "📚 SESSION STARTED on all devices!"))
            else:
                # try parse JSON
                try:
                    received = json.loads(txt)
                    if isinstance(received, list):
                        tasks = received
                        # sort safety
                        tasks.sort(key=lambda x: x.get("priority", 999))
                        root.after(0, update_task_list)
                except Exception:
                    # unknown text; ignore or print
                    print("Unknown message:", txt)
    except Exception as e:
        print("Listener stopped:", e)
    finally:
        try:
            sock.close()
        except:
            pass

# Start listener if connected
if connected:
    t = threading.Thread(target=listen_thread, daemon=True)
    t.start()

# ====== Widgets ======
title = tk.Label(root, text="SyncStudy - Study Planner", font=("Arial", 16, "bold"))
title.pack(pady=8)

frame = tk.Frame(root)
frame.pack(pady=5)

task_entry = tk.Entry(frame, width=28, font=("Arial", 12))
task_entry.grid(row=0, column=0, padx=6, pady=6)

priority_var = tk.IntVar(value=2)
prio_frame = tk.Frame(root)
prio_frame.pack()
tk.Radiobutton(prio_frame, text="High", variable=priority_var, value=1).pack(side="left", padx=8)
tk.Radiobutton(prio_frame, text="Medium", variable=priority_var, value=2).pack(side="left", padx=8)
tk.Radiobutton(prio_frame, text="Low", variable=priority_var, value=3).pack(side="left", padx=8)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)
tk.Button(btn_frame, text="Add Task", width=12, command=add_task).grid(row=0, column=0, padx=6)
tk.Button(btn_frame, text="Share Plan", width=12, command=share_plan).grid(row=0, column=1, padx=6)
tk.Button(btn_frame, text="Start Session", width=26, command=start_session, bg="#f39c12").grid(row=1, column=0, columnspan=2, pady=8)

tk.Label(root, text="📋 Task List", font=("Arial", 12, "bold")).pack(pady=6)
listbox = tk.Listbox(root, width=50, height=12)
listbox.pack(pady=4)

# connection status label
status_var = tk.StringVar()
status_var.set("Connected" if connected else "Not connected")
status_label = tk.Label(root, textvariable=status_var, fg="green" if connected else "red")
status_label.pack(pady=4)

root.mainloop()
