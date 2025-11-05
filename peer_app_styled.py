# peer_app_styled.py  (robust decrypting listener + host_response handling)
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import json, os, time, traceback
from crypto_utils import decrypt_data, get_key_b64, encrypt_data

HOST = "127.0.0.1"
PORT = 65435
BUFFER = 8192
DOWNLOADS = os.path.join(os.getcwd(), "downloads")
os.makedirs(DOWNLOADS, exist_ok=True)

class PeerApp:
    def __init__(self, root):
        self.root = root
        root.title("SyncStudy — Peer (Decrypt Fix)")
        root.geometry("840x620")
        root.configure(bg="#121a2f")

        tk.Label(root, text="SyncStudy — Peer", font=("Segoe UI", 18, "bold"), fg="#d8e8ff", bg="#121a2f").pack(pady=8)
        top_frame = tk.Frame(root, bg="#121a2f")
        top_frame.pack(fill="x", padx=12)

        tk.Button(top_frame, text="🔗 Connect", command=self.connect, bg="#c77dff").pack(side="left", padx=6)
        tk.Button(top_frame, text="Show Key (debug)", command=self.show_key, bg="#ff66cc").pack(side="left", padx=6)

        tk.Label(root, text="Logs", bg="#121a2f", fg="#d8e8ff").pack(anchor="w", padx=12, pady=(8,0))
        self.log_box = tk.Text(root, bg="#0f1422", fg="#cfe9ff", height=20)
        self.log_box.pack(fill="both", expand=False, padx=12, pady=6)
        self.log_box.insert(tk.END, "Ready. Click Connect to connect to Host/Relay.\n")

        tk.Label(root, text=f"Downloads: {DOWNLOADS}", bg="#121a2f", fg="#d8e8ff").pack(anchor="w", padx=12)
        tk.Button(root, text="Open downloads folder", command=self.open_downloads, bg="#89cff0").pack(padx=12, pady=(0,12), anchor="w")

        actions = tk.Frame(root, bg="#121a2f")
        actions.pack(pady=6)
        tk.Button(actions, text="📨 Request Plan", command=self.request_plan, bg="#a7e9af").grid(row=0,column=0,padx=6)
        tk.Button(actions, text="➕ Add Local Task", command=self.add_task, bg="#ff9cee").grid(row=0,column=1,padx=6)
        tk.Button(actions, text="☕ Request Break", command=self.request_break, bg="#ffb347").grid(row=0,column=2,padx=6)
        tk.Button(actions, text="📥 Request Resume", command=self.request_resume, bg="#ff9966").grid(row=0,column=3,padx=6)

        self.conn = None
        self.listener_thread = None
        self.file_buffers = {}

    def log(self, txt):
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, txt + "\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def show_key(self):
        try:
            k = get_key_b64()
            self.log(f"[DEBUG] Encryption key (base64) first 12 chars: {k[:12]}...")
            messagebox.showinfo("Encryption key (base64)", f"{k}\n\n(Do NOT share this key.)")
        except Exception as e:
            messagebox.showerror("Key error", str(e))

    def connect(self):
        if self.conn:
            messagebox.showinfo("Info", "Already connected.")
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            self.conn = s
            self.log(f"[NET] Connected to {HOST}:{PORT}")
            self.listener_thread = threading.Thread(target=self.listen_loop, daemon=True)
            self.listener_thread.start()
        except Exception as e:
            self.log(f"[NET] Connect failed: {e}\nEntering demo mode (you can still demo UI).")

    def listen_loop(self):
        buf = b""
        s = self.conn
        while True:
            try:
                data = s.recv(BUFFER)
                if not data:
                    self.log("[NET] Connection closed by remote.")
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    self.process_incoming(line)
            except Exception as e:
                self.log(f"[ERR] Listener exception: {e}")
                break

    def process_incoming(self, raw_bytes):
        # Attempt JSON parse
        try:
            text = raw_bytes.decode(errors="ignore").strip()
            obj = json.loads(text)
            if isinstance(obj, dict) and "payload_hex" in obj:
                hexp = obj.get("payload_hex")
                try:
                    dec = decrypt_data(bytes.fromhex(hexp))
                    try:
                        inner = json.loads(dec.decode())
                        self.log(f"[DECRYPTED PLAN] version:{inner.get('version')} tasks:{len(inner.get('tasks',[]))}")
                        tasks = inner.get("tasks",[])
                        for i,t in enumerate(tasks,1):
                            self.log(f"  {i}. {t.get('task')} (prio {t.get('priority')})")
                    except Exception:
                        self.log(f"[DECRYPTED TEXT]\n{dec.decode(errors='ignore')}")
                except Exception as e:
                    self.log(f"[ERR] decrypting payload_hex: {e}")
            else:
                if isinstance(obj, dict) and obj.get("type") == "host_response":
                    self.handle_host_response(obj)
                elif isinstance(obj, dict) and obj.get("type") == "FILE_CHUNK":
                    self.handle_incoming_file_chunk(obj)
                else:
                    self.log(f"[JSON] {obj}")
            return
        except Exception:
            pass

        # Attempt decrypt raw bytes
        try:
            txt = raw_bytes.strip()
            is_hex_ascii = all(c in b'0123456789abcdefABCDEF' for c in txt) and len(txt) % 2 == 0
            candidate = None
            if is_hex_ascii:
                try:
                    candidate = bytes.fromhex(txt.decode())
                except Exception:
                    candidate = None
            if candidate is None:
                candidate = raw_bytes
            try:
                dec = decrypt_data(candidate)
                try:
                    obj2 = json.loads(dec.decode())
                    if isinstance(obj2, dict) and obj2.get("type") == "host_response":
                        self.handle_host_response(obj2)
                    else:
                        self.log(f"[DECRYPTED] {json.dumps(obj2)[:300]}")
                except Exception:
                    self.log(f"[DECRYPTED TEXT] {dec.decode(errors='ignore')}")
                return
            except Exception as e:
                self.log(f"[ERR] decrypt attempt failed: {e}")
        except Exception as e:
            self.log(f"[ERR] raw decrypt path error: {e}")

        # fallback
        try:
            self.log(f"[RAW] {raw_bytes[:400]!r}")
        except:
            self.log("[RAW] (could not display raw bytes)")

    def handle_host_response(self, data):
        try:
            action = data.get("action")
            if action == "break_granted":
                duration = data.get("duration")
                self.root.after(0, lambda: messagebox.showinfo("Break Approved ☕", f"Host approved a {duration}-minute break!"))
                self.log(f"✅ Break approved for {duration} min.")
            elif action == "break_denied":
                self.root.after(0, lambda: messagebox.showinfo("Break Denied", "Host denied the break request."))
                self.log("❌ Break denied by Host.")
            elif action == "task_added":
                task = data.get("task")
                priority = data.get("priority")
                self.root.after(0, lambda: messagebox.showinfo("Task Approved ✅", f"Host added your task '{task}' ({priority} priority)."))
                self.log(f"✅ Task '{task}' added by Host ({priority}).")
            elif action == "task_rejected":
                self.root.after(0, lambda: messagebox.showinfo("Task Rejected", "Host rejected your task suggestion."))
                self.log("❌ Task suggestion rejected by Host.")
            elif action == "plan_shared":
                self.root.after(0, lambda: messagebox.showinfo("Plan Shared", "Host shared the study plan. Check logs for tasks."))
                self.log("📄 Host shared the plan.")
            elif action == "plan_denied":
                self.root.after(0, lambda: messagebox.showinfo("Plan Denied", "Host denied the plan request."))
                self.log("❌ Host denied plan request.")
            else:
                self.log(f"[HOST_RESP] {data}")
        except Exception as e:
            tb = traceback.format_exc()
            self.log(f"[ERR] handling host_response: {e}\n{tb}")

    def handle_incoming_file_chunk(self, obj):
        try:
            fname = obj.get("filename")
            chunk_hex = obj.get("chunk_hex", "")
            final = obj.get("final", False)
            if fname not in self.file_buffers:
                self.file_buffers[fname] = bytearray()
            if chunk_hex:
                try:
                    dec = decrypt_data(bytes.fromhex(chunk_hex))
                    self.file_buffers[fname].extend(dec)
                except Exception as e:
                    self.log(f"[ERR] decrypting file chunk: {e}")
            if final:
                path = os.path.join(DOWNLOADS, fname)
                with open(path, "wb") as f:
                    f.write(self.file_buffers[fname])
                self.log(f"[FILE] Received and saved {fname} -> {path}")
                del self.file_buffers[fname]
        except Exception as e:
            self.log(f"[ERR] handle_incoming_file_chunk: {e}")

    # ---------- UI actions ----------
    def request_plan(self):
        if not self.conn:
            self.log("[DEMO] Request Plan (demo mode)")
            return
        try:
            payload = {"type":"peer_request", "action":"request_plan"}
            self.conn.sendall((json.dumps(payload) + "\n").encode())
            self.log("[SENT] peer_request: request_plan")
        except Exception as e:
            self.log(f"[ERR] send REQ_PLAN: {e}")

    def request_break(self):
        if not self.conn:
            self.log("[DEMO] Request Break (demo mode)")
            return
        try:
            payload = {"type":"peer_request", "action":"break_request"}
            self.conn.sendall((json.dumps(payload) + "\n").encode())
            self.log("[SENT] peer_request: break_request")
        except Exception as e:
            self.log(f"[ERR] send BREAK_REQ: {e}")

    def add_task(self):
        if not self.conn:
            t = simpledialog.askstring("Task", "Enter local task (demo):")
            if t:
                self.log(f"[LOCAL] {t}")
            return
        t = simpledialog.askstring("Task", "Enter task to propose to host:")
        if not t:
            return
        payload = {"type":"peer_request", "action":"add_task", "details": {"task": t, "timestamp": time.time()}}
        try:
            self.conn.sendall((json.dumps(payload) + "\n").encode())
            self.log(f"[SENT] peer_request: add_task -> {t}")
        except Exception as e:
            self.log(f"[ERR] send edit: {e}")

    def request_resume(self):
        if not self.conn:
            self.log("[DEMO] Request Resume (demo)")
            return
        fname = simpledialog.askstring("Resume", "Filename to resume:")
        if not fname:
            return
        payload = {"type":"RESUME_REQ", "filename": fname, "offset": 0}
        try:
            self.conn.sendall((json.dumps(payload) + "\n").encode())
            self.log(f"[SENT] Resume request for {fname}")
        except Exception as e:
            self.log(f"[ERR] send resume: {e}")

    def send_file(self):
        if not self.conn:
            self.log("[DEMO] Send File (demo)")
            return
        fpath = filedialog.askopenfilename()
        if not fpath:
            return
        fname = os.path.basename(fpath)
        try:
            with open(fpath, "rb") as f:
                while True:
                    chunk = f.read(64*1024)
                    if not chunk:
                        break
                    enc = encrypt_data(chunk)
                    payload = {"type":"FILE_CHUNK", "filename": fname, "chunk_hex": enc.hex(), "final": False}
                    self.conn.sendall((json.dumps(payload) + "\n").encode())
            self.conn.sendall((json.dumps({"type":"FILE_CHUNK","filename":fname,"chunk_hex":"","final":True}) + "\n").encode())
            self.log(f"[SENT] file {fname} (chunked)")
        except Exception as e:
            self.log(f"[ERR] sending file: {e}")

    def open_downloads(self):
        try:
            if os.name == "nt":
                os.startfile(DOWNLOADS)
            else:
                import subprocess
                subprocess.call(["open", DOWNLOADS])
        except Exception as e:
            self.log(f"[ERR] open downloads: {e}")

def run_peer():
    root = tk.Tk()
    app = PeerApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_peer()
