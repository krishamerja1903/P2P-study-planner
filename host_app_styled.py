# host_app_styled.py
"""
Full Host app — Jellyfish theme.
Merged features:
- Add/Edit/Delete tasks with priority
- Share plan (encrypted)
- Start/Pause/Resume session
- Chunked encrypted file send (peer reconstructs)
- Accept peer edits (conflict resolution)
- Relay-compatible (tries relay first)
- Peer requests: break_request, add_task, request_plan (Host approves)
- Thread-safe Tk popups (root.after)
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import socket, threading, json, os, time, traceback
from crypto_utils import encrypt_data, decrypt_data, get_key_b64

# ---------- Config ----------
RELAY_HOST = "127.0.0.1"
RELAY_PORT = 65435
USE_RELAY = True           # set False to force direct server mode (for local tests)
DIRECT_HOST = "127.0.0.1"
DIRECT_PORT = 65500
CHUNK_SIZE = 64 * 1024
DOWNLOADS = os.path.join(os.getcwd(), "downloads_host")
os.makedirs(DOWNLOADS, exist_ok=True)

# Colors
BG = "#0b0f19"
PANEL = "#101526"
TEXT = "#d0d8ff"
ACCENT1 = "#ff66cc"
ACCENT2 = "#c77dff"
ACCENT3 = "#ff9f43"

# ---------- Networking helpers ----------
def send_json_line(conn, obj):
    try:
        conn.sendall((json.dumps(obj) + "\n").encode())
    except Exception:
        pass

class HostNetwork:
    def __init__(self, log):
        self.log = log
        self.sock = None   # outgoing socket to relay (or None)
        self.server = None # listening server socket (for direct)
        self.client_conns = []  # for direct mode: list of (conn,addr)
        self.running = False
        self.lock = threading.Lock()

    def log_insert(self, msg):
        def _():
            app.log_box.configure(state=tk.NORMAL)
            app.log_box.insert(tk.END, msg + "\n")
            app.log_box.see(tk.END)
            app.log_box.configure(state=tk.DISABLED)
        app.root.after(0, _)

    def connect_relay(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((RELAY_HOST, RELAY_PORT))
            self.log_insert(f"[NET] Connected to relay {RELAY_HOST}:{RELAY_PORT}")
            return s
        except Exception as e:
            self.log_insert(f"[NET] Relay connect failed: {e}")
            s.close()
            return None

    def start(self):
        if USE_RELAY:
            s = self.connect_relay()
            if s:
                self.sock = s
                threading.Thread(target=self.relay_listener, daemon=True).start()
                return True
            # else fallback to direct
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((DIRECT_HOST, DIRECT_PORT))
            srv.listen(5)
            self.server = srv
            self.running = True
            self.log_insert(f"[LISTEN] Direct host listening on {DIRECT_HOST}:{DIRECT_PORT}")
            threading.Thread(target=self.accept_loop, daemon=True).start()
            return True
        except Exception as e:
            self.log_insert(f"[ERR] Could not start server: {e}")
            return False

    def accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server.accept()
                with self.lock:
                    self.client_conns.append((conn, addr))
                self.log_insert(f"[+] Peer connected: {addr}")
                threading.Thread(target=self.client_receiver, args=(conn, addr), daemon=True).start()
            except Exception:
                break

    def client_receiver(self, conn, addr):
        buffer = b""
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    try:
                        msg = json.loads(line.decode())
                    except Exception:
                        continue
                    self.handle_message(msg, conn, addr)
            except Exception:
                break
        with self.lock:
            self.client_conns = [(c,a) for (c,a) in self.client_conns if c!=conn]
        conn.close()
        self.log_insert(f"[-] Peer disconnected: {addr}")

    def relay_listener(self):
        buffer = b""
        s = self.sock
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n",1)
                    try:
                        msg = json.loads(line.decode())
                    except Exception:
                        continue
                    self.handle_message(msg, s, ("relay",0))
        except Exception as e:
            self.log_insert(f"[NET] Relay listener stopped: {e}")
        finally:
            try: s.close()
            except: pass

    def handle_message(self, msg, conn, addr):
        mtype = msg.get("type")
        if mtype == "EDIT":
            edit = msg.get("data")
            if edit:
                app.apply_peer_edit(edit)
        elif mtype == "REQ_PLAN":
            if USE_RELAY and self.sock is not None:
                app.prompt_and_send_plan(target_conn=self.sock)
            else:
                app.prompt_and_send_plan(target_conn=conn)
        elif mtype == "RESUME_REQ":
            fname = msg.get("filename")
            offset = int(msg.get("offset",0))
            threading.Thread(target=app.handle_resume_request, args=(fname, offset, conn), daemon=True).start()
        elif mtype == "FILE_CHUNK":
            # peer uploading chunks — ignored unless you implement upload-to-host
            self.log_insert(f"[IN] FILE_CHUNK from {addr} (ignored)")
        elif mtype == "peer_request":
            # forward to host to decide (safe UI thread)
            try:
                app.handle_peer_request(msg, conn)
            except Exception as e:
                self.log_insert(f"[ERR] handle_peer_request: {e}")
        else:
            self.log_insert(f"[IN] {msg}")

    def broadcast(self, obj):
        try:
            if USE_RELAY and self.sock:
                send_json_line(self.sock, obj)
            else:
                with self.lock:
                    for c,a in list(self.client_conns):
                        try:
                            send_json_line(c, obj)
                        except:
                            pass
        except Exception as e:
            self.log_insert(f"[ERR] broadcast: {e}")

hostnet = None

# ---------- App GUI & logic ----------
class HostApp:
    def __init__(self, root):
        self.root = root
        app.root = root
        root.configure(bg=BG)
        root.title("SyncStudy — Host (Jellyfish)")
        root.geometry("900x680")

        # data
        self.tasks = []   # list of dicts {task, priority, timestamp}
        self.version = 0
        self.file_store = {}  # filename -> list of bytes chunks (for resume)
        self.down_folder = DOWNLOADS

        # top frame
        top = tk.Frame(root, bg=BG)
        top.pack(fill="x", padx=16, pady=(12,6))
        title = tk.Label(top, text="SyncStudy — Host", fg=TEXT, bg=BG, font=("Segoe UI", 18, "bold"))
        title.pack(side="left")
        key_lbl = tk.Button(top, text="Show Encryption Key", bg=PANEL, fg=TEXT, command=self.show_key, relief=tk.FLAT)
        key_lbl.pack(side="right", padx=6)

        # main frames
        main = tk.Frame(root, bg=BG)
        main.pack(fill="both", expand=True, padx=16, pady=6)

        left = tk.Frame(main, bg=PANEL)
        left.pack(side="left", fill="y", padx=(0,8), pady=6)
        right = tk.Frame(main, bg=BG)
        right.pack(side="right", fill="both", expand=True, pady=6)

        # left: task controls
        left.config(width=360)
        tk.Label(left, text="Add Task", bg=PANEL, fg=TEXT, font=("Segoe UI",12,"bold")).pack(pady=8)
        entry = tk.Entry(left, width=30, bg="#0f1422", fg=TEXT, insertbackground=TEXT)
        entry.pack(pady=6)
        self.task_entry = entry

        pr_frame = tk.Frame(left, bg=PANEL)
        pr_frame.pack(pady=6)
        self.pr_var = tk.IntVar(value=2)
        tk.Radiobutton(pr_frame, text="High", variable=self.pr_var, value=1, bg=PANEL, fg=ACCENT1, selectcolor=PANEL).pack(side="left", padx=6)
        tk.Radiobutton(pr_frame, text="Medium", variable=self.pr_var, value=2, bg=PANEL, fg=ACCENT2, selectcolor=PANEL).pack(side="left", padx=6)
        tk.Radiobutton(pr_frame, text="Low", variable=self.pr_var, value=3, bg=PANEL, fg=ACCENT3, selectcolor=PANEL).pack(side="left", padx=6)

        tk.Button(left, text="Add Task", command=self.add_task, bg=ACCENT2, fg="black", width=20).pack(pady=8)

        tk.Label(left, text="Tasks (Authoritative)", bg=PANEL, fg=TEXT).pack(pady=(10,0))
        lst = tk.Listbox(left, width=45, height=12, bg="#0f1422", fg=TEXT, selectbackground="#25283a")
        lst.pack(pady=6)
        self.task_listbox = lst

        edf = tk.Frame(left, bg=PANEL)
        edf.pack(pady=4)
        tk.Button(edf, text="Edit Selected", command=self.edit_selected, bg="#7a4fff", fg="white", width=12).pack(side="left", padx=6)
        tk.Button(edf, text="Delete Selected", command=self.delete_selected, bg="#ff5f7f", fg="white", width=12).pack(side="left", padx=6)

        tk.Button(left, text="Send File (Chunked & Encrypted)", command=self.choose_and_send_file, bg=ACCENT1, fg="black", width=28).pack(pady=12)

        tk.Button(left, text="Share Plan (Encrypted)", command=self.share_plan, bg=ACCENT2, fg="black", width=28).pack(pady=4)
        tk.Button(left, text="Start Session", command=self.start_session, bg=ACCENT3, fg="black", width=28).pack(pady=4)

        # right: logs & peers
        tk.Label(right, text="Connection & Event Logs", bg=BG, fg=TEXT, font=("Segoe UI",12,"bold")).pack(anchor="w")
        log = tk.Text(right, bg="#0f1422", fg="#cfe9ff", height=18)
        log.pack(fill="both", expand=False, pady=6)
        log.configure(state=tk.DISABLED)
        self.log_box = log
        app.log_box = log

        tk.Label(right, text="Connected Peers (direct mode)", bg=BG, fg=TEXT).pack(anchor="w", pady=(8,0))
        self.peers_box = tk.Listbox(right, bg="#0f1422", fg=TEXT, height=6)
        self.peers_box.pack(fill="x", pady=6)

        # start network
        global hostnet
        hostnet = HostNetwork(self.log_box)
        threading.Thread(target=self._start_network, daemon=True).start()

    def _start_network(self):
        ok = hostnet.start()
        if ok:
            self.log("Network started.")
        else:
            self.log("Network failed to start.")

    def log(self, s):
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, s + "\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def show_key(self):
        try:
            k = get_key_b64()
            messagebox.showinfo("Encryption Key (base64)", k)
        except Exception as e:
            messagebox.showerror("Key", f"Error: {e}")

    def add_task(self):
        name = self.task_entry.get().strip()
        if not name:
            messagebox.showwarning("Input", "Enter task name")
            return
        t = {"task": name, "priority": int(self.pr_var.get()), "timestamp": time.time()}
        self.tasks.append(t)
        self.tasks.sort(key=lambda x: x["priority"])
        self.version += 1
        self.update_task_list()
        self.task_entry.delete(0, tk.END)

    def update_task_list(self):
        self.task_listbox.delete(0, tk.END)
        for t in self.tasks:
            lvl = "High" if t["priority"]==1 else "Medium" if t["priority"]==2 else "Low"
            self.task_listbox.insert(tk.END, f"{t['task']} ({lvl})")

    def edit_selected(self):
        sel = self.task_listbox.curselection()
        if not sel:
            messagebox.showinfo("Edit", "Select a task first")
            return
        idx = sel[0]
        t = self.tasks[idx]
        newname = simpledialog.askstring("Edit Task", "Edit task name:", initialvalue=t["task"], parent=self.root)
        if not newname:
            return
        newprio = simpledialog.askinteger("Priority", "Priority 1=High 2=Med 3=Low", initialvalue=t["priority"], minvalue=1, maxvalue=3, parent=self.root)
        if not newprio:
            return
        t["task"] = newname
        t["priority"] = newprio
        t["timestamp"] = time.time()
        self.tasks.sort(key=lambda x: x["priority"])
        self.version += 1
        self.update_task_list()

    def delete_selected(self):
        sel = self.task_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.tasks.pop(idx)
        self.version += 1
        self.update_task_list()

    def share_plan(self):
        if not self.tasks:
            messagebox.showwarning("No tasks", "Add tasks first")
            return
        payload = json.dumps({"version": self.version, "tasks": self.tasks}).encode()
        enc = encrypt_data(payload)
        hostnet.broadcast({"type":"PLAN", "payload_hex": enc.hex()})
        self.log("[SHARE] Encrypted plan broadcasted.")

    def send_encrypted_plan(self, target_conn=None):
        payload = json.dumps({"version": self.version, "tasks": self.tasks}).encode()
        enc = encrypt_data(payload)
        obj = {"type":"PLAN", "payload_hex": enc.hex()}
        if target_conn is None:
            hostnet.broadcast(obj)
        else:
            send_json_line(target_conn, obj)

    def prompt_and_send_plan(self, target_conn=None):
        """Prompt host to allow sharing, then send encrypted plan to the requesting connection (or via relay)."""
        def ask_and_send():
            allow = messagebox.askyesno("Plan Request", "Peer requested the study plan.\nShare plan?")
            if allow:
                self.send_encrypted_plan(target_conn=target_conn)
                # notify peer
                resp = {"type":"host_response", "action":"plan_shared"}
                if target_conn is None:
                    hostnet.broadcast(resp)
                else:
                    send_json_line(target_conn, resp)
                self.log("[SHARE] Plan approved and sent.")
            else:
                resp = {"type":"host_response", "action":"plan_denied"}
                if target_conn is None:
                    hostnet.broadcast(resp)
                else:
                    send_json_line(target_conn, resp)
                self.log("[SHARE] Plan request denied.")
        try:
            self.root.after(0, ask_and_send)
        except Exception as e:
            self.log(f"[ERR] scheduling plan prompt: {e}")

    def start_session(self):
        hostnet.broadcast({"type":"START", "msg":"SESSION_START"})
        self.log("[SYNC] Session start broadcasted.")

    def choose_and_send_file(self):
        path = filedialog.askopenfilename(title="Select file to send")
        if not path:
            return
        threading.Thread(target=self._send_file_chunked, args=(path,), daemon=True).start()

    def _send_file_chunked(self, path):
        fname = os.path.basename(path)
        filesize = os.path.getsize(path)
        self.file_store[fname] = []
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    enc = encrypt_data(chunk)
                    hexchunk = enc.hex()
                    hostnet.broadcast({"type":"FILE_CHUNK", "filename": fname, "chunk_hex": hexchunk, "final": False})
                    self.file_store[fname].append(chunk)
            hostnet.broadcast({"type":"FILE_CHUNK", "filename": fname, "chunk_hex": "", "final": True})
            self.log(f"[FILE] Sent file {fname} in encrypted chunks.")
        except Exception as e:
            self.log(f"[ERR] file send failed: {e}")

    def handle_resume_request(self, filename, offset, conn):
        chunks = self.file_store.get(filename)
        if not chunks:
            send_json_line(conn, {"type":"ERROR", "msg":"file not found"})
            return
        sent = 0
        try:
            for chunk in chunks:
                if sent >= offset:
                    enc = encrypt_data(chunk)
                    send_json_line(conn, {"type":"FILE_CHUNK", "filename": filename, "chunk_hex": enc.hex(), "final": False})
                sent += len(chunk)
            send_json_line(conn, {"type":"FILE_CHUNK", "filename": filename, "chunk_hex":"", "final": True})
            self.log(f"[RESUME] Sent remaining from offset {offset} for {filename}")
        except Exception as e:
            self.log(f"[ERR] resume send: {e}")

    def apply_peer_edit(self, edit):
        name = edit.get("task")
        found = False
        for t in self.tasks:
            if t.get("task") == name:
                if edit.get("timestamp",0) >= t.get("timestamp",0):
                    t.update(edit)
                found = True
                break
        if not found:
            self.tasks.append(edit)
        self.tasks.sort(key=lambda x: x["priority"])
        self.version += 1
        self.update_task_list()
        self.share_plan()

    # ---------------- NEW: handle_peer_request (thread-safe popups) ----------------
    def handle_peer_request(self, msg, conn):
        try:
            action = msg.get("action")
        except Exception:
            return

        def do_handle():
            try:
                if action == "break_request":
                    duration = simpledialog.askinteger(
                        "Break Request ⏸️",
                        "Peer requested a break.\nEnter duration in minutes:",
                        parent=self.root,
                        minvalue=1, maxvalue=180
                    )
                    if duration is not None:
                        resp = {"type":"host_response", "action":"break_granted", "duration": int(duration)}
                        if USE_RELAY and hostnet.sock:
                            hostnet.broadcast(resp)
                        else:
                            send_json_line(conn, resp)
                        self.log(f"✅ Approved break: {duration} min (sent response).")
                    else:
                        resp = {"type":"host_response", "action":"break_denied"}
                        if USE_RELAY and hostnet.sock:
                            hostnet.broadcast(resp)
                        else:
                            send_json_line(conn, resp)
                        self.log("❌ Break request ignored by Host.")

                elif action == "add_task":
                    details = msg.get("details", {})
                    taskname = details.get("task", "Untitled task")
                    p = simpledialog.askstring(
                        "Task Suggestion 📝",
                        f"Peer suggested task:\n'{taskname}'\nEnter priority (High/Medium/Low):",
                        parent=self.root
                    )
                    if p:
                        p_norm = p.strip().lower()
                        if p_norm.startswith("h"):
                            pr = 1
                            p_label = "High"
                        elif p_norm.startswith("m"):
                            pr = 2
                            p_label = "Medium"
                        else:
                            pr = 3
                            p_label = "Low"
                        t = {"task": taskname, "priority": pr, "timestamp": time.time()}
                        self.tasks.append(t)
                        self.tasks.sort(key=lambda x: x["priority"])
                        self.version += 1
                        self.update_task_list()
                        self.share_plan()
                        resp = {"type":"host_response", "action":"task_added", "task": taskname, "priority": p_label}
                        if USE_RELAY and hostnet.sock:
                            hostnet.broadcast(resp)
                        else:
                            send_json_line(conn, resp)
                        self.log(f"✅ Added peer task '{taskname}' with priority {p_label} and replied to peer.")
                    else:
                        resp = {"type":"host_response", "action":"task_rejected"}
                        if USE_RELAY and hostnet.sock:
                            hostnet.broadcast(resp)
                        else:
                            send_json_line(conn, resp)
                        self.log("❌ Task suggestion skipped by Host.")
                else:
                    self.log(f"[WARN] Unknown peer_request action: {action}")
            except Exception as e:
                tb = traceback.format_exc()
                self.log(f"[ERR] while handling peer_request: {e}\n{tb}")

        try:
            self.root.after(0, do_handle)
        except Exception as e:
            self.log(f"[ERR] scheduling peer_request handler: {e}")

# app holder so hostnet can reference
class AppHolder:
    pass
app = AppHolder()

def run_host_gui():
    root = tk.Tk()
    global app
    app = HostApp(root)
    app.root = root
    root.mainloop()

if __name__ == "__main__":
    run_host_gui()
