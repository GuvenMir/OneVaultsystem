#!/usr/bin/env python3
"""
vault_onefile.py
Single-file internal text library:
 - CLI, Middle-level GUI (Tkinter), Web (built-in http.server)
 - No external dependencies
 - XOR+Base64 encryption with key.bin
 - Atomic writes, backups, automatic creation/repair of data file
 - Menu allows starting/stopping webserver and choosing host/port
"""

import os
import sys
import json
import base64
import tempfile
import shutil
import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote_plus
from pathlib import Path

# Tkinter is included in standard Python (may not exist on minimal installs)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

# -----------------------
# Config / Filenames
# -----------------------
DATA_FILE = "kutuphane.json"
KEY_FILE = "key.bin"
BACKUP_DIR = "backups"
MAX_BACKUPS = 7

# -----------------------
# Encryption (XOR + base64)
# -----------------------
def ensure_key():
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                k = f.read()
            if k and len(k) >= 8:
                return k
        except Exception:
            pass
    k = os.urandom(32)
    with open(KEY_FILE, "wb") as f:
        f.write(k)
    return k

KEY = ensure_key()

def encrypt(text: str) -> str:
    if text is None:
        return ""
    tb = text.encode("utf-8")
    k = KEY
    enc = bytes([tb[i] ^ k[i % len(k)] for i in range(len(tb))])
    return base64.b64encode(enc).decode("utf-8")

def decrypt(blob: str) -> str:
    if not blob:
        return ""
    try:
        data = base64.b64decode(blob)
        k = KEY
        dec = bytes([data[i] ^ k[i % len(k)] for i in range(len(data))])
        return dec.decode("utf-8")
    except Exception:
        return "[DECRYPT ERROR]"

# -----------------------
# File safety helpers
# -----------------------
def atomic_write(path: str, data: str):
    fd, tmp = tempfile.mkstemp(prefix="._tmp_", dir=".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except: pass

def make_backup():
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        if not os.path.exists(DATA_FILE):
            return
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        dest = os.path.join(BACKUP_DIR, f"kutuphane_{ts}.json")
        shutil.copy2(DATA_FILE, dest)
        backups = sorted(Path(BACKUP_DIR).glob("kutuphane_*.json"), key=os.path.getmtime, reverse=True)
        for old in backups[MAX_BACKUPS:]:
            try: old.unlink()
            except: pass
    except Exception:
        pass

def safe_save_json(obj: dict):
    try:
        make_backup()
        atomic_write(DATA_FILE, json.dumps(obj, ensure_ascii=False, indent=2))
    except Exception:
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

def safe_load_json():
    if not os.path.exists(DATA_FILE):
        safe_save_json({})
        return {}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # If corrupted, back it up and recreate empty
        try:
            make_backup()
        except: pass
        safe_save_json({})
        return {}

# -----------------------
# Vault core
# -----------------------
class Vault:
    def __init__(self):
        self._load()

    def _load(self):
        raw = safe_load_json()
        self.data = raw if isinstance(raw, dict) else {}
        self._recompute_next_id()

    def _recompute_next_id(self):
        ids = [int(k) for k in self.data.keys() if k.isdigit()]
        self.next_id = max(ids) + 1 if ids else 1

    def _now_iso(self):
        return datetime.datetime.utcnow().isoformat() + "Z"

    def add(self, text: str, tags=None):
        tags = list(tags) if tags else []
        id_ = str(self.next_id)
        rec = {
            "text": encrypt(text),
            "tags": tags,
            "created": self._now_iso(),
            "modified": self._now_iso()
        }
        self.data[id_] = rec
        self.next_id += 1
        safe_save_json(self.data)
        return id_

    def get(self, id_):
        rec = self.data.get(str(id_))
        if not rec:
            return None
        return {
            "id": str(id_),
            "text": decrypt(rec.get("text","")),
            "tags": rec.get("tags",[]),
            "created": rec.get("created"),
            "modified": rec.get("modified")
        }

    def list(self, include_decrypted=True):
        out = {}
        for k, v in self.data.items():
            if include_decrypted:
                out[k] = {
                    "text": decrypt(v.get("text","")),
                    "tags": v.get("tags",[]),
                    "created": v.get("created"),
                    "modified": v.get("modified")
                }
            else:
                out[k] = v
        return out

    def delete(self, id_):
        k = str(id_)
        if k in self.data:
            self.data.pop(k)
            safe_save_json(self.data)
            return True
        return False

    def update(self, id_, text=None, tags=None):
        k = str(id_)
        if k not in self.data:
            return False
        if text is not None:
            self.data[k]["text"] = encrypt(text)
        if tags is not None:
            self.data[k]["tags"] = list(tags)
        self.data[k]["modified"] = self._now_iso()
        safe_save_json(self.data)
        return True

    def search(self, q: str, by_tags=False):
        q = q.lower().strip()
        results = []
        for k, v in self.data.items():
            if by_tags:
                tags = [t.lower() for t in v.get("tags",[])]
                if any(q in t for t in tags):
                    results.append(self.get(k))
            else:
                txt = decrypt(v.get("text",""))
                if q in txt.lower():
                    results.append(self.get(k))
        return results

VAULT = Vault()

# -----------------------
# Web server (built-in)
# -----------------------
class SimpleHandler(BaseHTTPRequestHandler):
    def _send(self, code, data, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if isinstance(data, (dict, list)):
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))
        else:
            self.wfile.write(str(data).encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        try:
            if path == "/":
                # Simple web UI
                html = WEB_UI_HTML
                self._send(200, html, ctype="text/html")
            elif path == "/list":
                data = VAULT.list(include_decrypted=True)
                self._send(200, data)
            elif path == "/get":
                id_ = qs.get("id", [""])[0]
                rec = VAULT.get(id_)
                if rec:
                    self._send(200, rec)
                else:
                    self._send(404, {"error":"not found"})
            elif path == "/delete":
                id_ = qs.get("id", [""])[0]
                ok = VAULT.delete(id_)
                self._send(200, {"deleted": ok})
            elif path == "/search":
                q = qs.get("q", [""])[0]
                by_tags = qs.get("tags", ["0"])[0] == "1"
                res = VAULT.search(unquote_plus(q), by_tags=by_tags)
                self._send(200, res)
            elif path == "/add":
                # allow via GET for simplicity: /add?text=...&tags=a,b
                text = qs.get("text", [""])[0]
                tags = qs.get("tags", [""])[0]
                tags_list = [t.strip() for t in tags.split(",")] if tags else []
                id_ = VAULT.add(unquote_plus(text), tags_list)
                self._send(201, {"id": id_})
            else:
                self._send(404, {"error":"unknown endpoint"})
        except Exception as e:
            self._send(500, {"error": str(e)})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''
        try:
            if path == "/add":
                # expect JSON {"text":"...", "tags":["a","b"]}
                try:
                    payload = json.loads(body) if body else {}
                except Exception:
                    payload = {}
                text = payload.get("text", "")
                tags = payload.get("tags", [])
                id_ = VAULT.add(text, tags)
                self._send(201, {"id": id_})
            elif path == "/update":
                try:
                    payload = json.loads(body) if body else {}
                except Exception:
                    payload = {}
                id_ = payload.get("id")
                text = payload.get("text", None)
                tags = payload.get("tags", None)
                ok = VAULT.update(id_, text=text, tags=tags)
                self._send(200, {"updated": ok})
            else:
                self._send(404, {"error":"unknown endpoint"})
        except Exception as e:
            self._send(500, {"error": str(e)})

# Minimal web UI (plain HTML + JS)
WEB_UI_HTML = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Internal Kutuphane</title></head><body>
<h2>Internal Kutuphane - Web UI</h2>
<div>
  <textarea id="txt" rows="4" cols="80" placeholder="Yeni metin..."></textarea><br/>
  <input id="tags" placeholder="tags,comma,separated"/><button onclick="add()">Add</button>
</div>
<hr/>
<div>
  <input id="q" placeholder="search..."/><button onclick="search()">Search</button>
  <label><input type="checkbox" id="bytags"/> search tags</label>
</div>
<div id="results"></div>
<script>
async function add(){
  let text = document.getElementById('txt').value;
  let tags = document.getElementById('tags').value.split(',').map(s=>s.trim()).filter(Boolean);
  let r = await fetch('/add', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text:text, tags:tags})});
  let j = await r.json();
  alert('Added id=' + j.id);
}
async function search(){
  let q = encodeURIComponent(document.getElementById('q').value);
  let bytags = document.getElementById('bytags').checked ? '1' : '0';
  let r = await fetch('/search?q=' + q + '&tags=' + bytags);
  let j = await r.json();
  let out = document.getElementById('results');
  out.innerHTML = '';
  j.forEach(it=>{
    let div = document.createElement('div');
    div.innerHTML = '<b>' + it.id + '</b>: ' + it.text.replace(/\\n/g,' ') + ' <small>(' + (it.tags||[]).join(',') + ')</small>'
      + ' <button onclick="del(\\'' + it.id + '\\')">Del</button>';
    out.appendChild(div);
  });
}
async function del(id){
  if(!confirm('Delete '+id+'?')) return;
  let r = await fetch('/delete?id=' + encodeURIComponent(id));
  let j = await r.json();
  alert('deleted=' + j.deleted);
}
</script>
</body></html>
"""

# Web server runner controlling thread
class WebServerThread:
    def __init__(self):
        self.server = None
        self.thread = None

    def start(self, host="127.0.0.1", port=5000):
        if self.server:
            return False, "Server already running"
        try:
            addr = (host, int(port))
            self.server = HTTPServer(addr, SimpleHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            return True, f"Server started at http://{host}:{port}"
        except Exception as e:
            self.server = None
            return False, str(e)

    def stop(self):
        if not self.server:
            return False, "Not running"
        try:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
        except Exception:
            pass
        self.server = None
        self.thread = None
        return True, "Stopped"

WEB_THREAD = WebServerThread()

# -----------------------
# CLI
# -----------------------
def run_cli():
    v = VAULT
    def menu():
        print("\n--- OneVaultsystem - CLI ---")
        print("\n--- Made by 449 ---")
        print("1) Add")
        print("2) Get by ID")
        print("3) List all")
        print("4) Search text")
        print("5) Search tags")
        print("6) Update")
        print("7) Delete")
        print("8) Start web server")
        print("9) Stop web server")
        print("10) Show server status")
        print("0) Exit")
    while True:
        try:
            menu()
            ch = input("Choice: ").strip()
            if ch == "1":
                txt = input("Text: ")
                tags = input("Tags (comma): ").strip()
                tags_list = [t.strip() for t in tags.split(",")] if tags else []
                id_ = v.add(txt, tags_list)
                print("Added ID =", id_)
            elif ch == "2":
                id_ = input("ID: ").strip()
                rec = v.get(id_)
                if rec:
                    print(json.dumps(rec, ensure_ascii=False, indent=2))
                else:
                    print("Not found")
            elif ch == "3":
                all_ = v.list()
                for k in sorted(all_.keys(), key=lambda x:int(x)):
                    r = all_[k]
                    print(f"{k}: {r['text'][:200]} {'(tags:'+','.join(r['tags'])+')' if r['tags'] else ''}")
            elif ch == "4":
                q = input("Query: ").strip()
                res = v.search(q, by_tags=False)
                for r in res:
                    print(f"{r['id']}: {r['text'][:200]}")
                print(len(res), "results")
            elif ch == "5":
                q = input("Tag query: ").strip()
                res = v.search(q, by_tags=True)
                for r in res:
                    print(f"{r['id']}: {r['text'][:200]} (tags:{','.join(r['tags'])})")
                print(len(res), "results")
            elif ch == "6":
                id_ = input("ID: ").strip()
                txt = input("New text (enter skip): ")
                tags = input("New tags (comma, enter skip): ")
                tags_list = None
                if tags != "":
                    tags_list = [t.strip() for t in tags.split(",")] if tags else []
                ok = v.update(id_, text=None if txt=="" else txt, tags=tags_list)
                print("Updated" if ok else "ID not found")
            elif ch == "7":
                id_ = input("ID to delete: ").strip()
                ok = v.delete(id_)
                print("Deleted" if ok else "ID not found")
            elif ch == "8":
                host = input("Host (default 127.0.0.1): ").strip() or "127.0.0.1"
                port = input("Port (default 5000): ").strip() or "5000"
                ok, msg = WEB_THREAD.start(host=host, port=int(port))
                print(msg)
            elif ch == "9":
                ok, msg = WEB_THREAD.stop()
                print(msg)
            elif ch == "10":
                status = "running" if WEB_THREAD.server else "stopped"
                print("Server status:", status)
            elif ch == "0":
                if WEB_THREAD.server:
                    WEB_THREAD.stop()
                print("Exiting.")
                break
            else:
                print("Invalid selection")
        except KeyboardInterrupt:
            print("\nInterrupted. Exiting.")
            if WEB_THREAD.server:
                WEB_THREAD.stop()
            break
        except Exception as e:
            print("Error:", e)

# -----------------------
# GUI (mid-level)
# -----------------------
def run_gui():
    if not TK_AVAILABLE:
        print("Tkinter not available on this Python build.")
        return

    v = VAULT
    root = tk.Tk()
    root.title("OneVaultsystem - GUI")
    root.geometry("900x600")

    # Frames
    left = ttk.Frame(root, width=300)
    right = ttk.Frame(root)
    left.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=8)
    right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)

    # Left: controls and list
    search_var = tk.StringVar()
    search_entry = ttk.Entry(left, textvariable=search_var)
    search_entry.pack(fill=tk.X, pady=(0,6))

    listbox = tk.Listbox(left, width=40)
    listbox.pack(fill=tk.BOTH, expand=True)

    btn_frame = ttk.Frame(left)
    btn_frame.pack(fill=tk.X, pady=6)
    ttk.Button(btn_frame, text="Add", command=lambda: gui_add()).pack(side=tk.LEFT, padx=2)
    ttk.Button(btn_frame, text="Delete", command=lambda: gui_delete()).pack(side=tk.LEFT, padx=2)
    ttk.Button(btn_frame, text="Refresh", command=lambda: refresh_list()).pack(side=tk.LEFT, padx=2)
    ttk.Button(btn_frame, text="Search", command=lambda: do_search()).pack(side=tk.LEFT, padx=2)

    # Web server controls
    web_frame = ttk.Frame(left)
    web_frame.pack(fill=tk.X, pady=6)
    host_var = tk.StringVar(value="127.0.0.1")
    port_var = tk.StringVar(value="5000")
    ttk.Label(web_frame, text="Host").pack(side=tk.LEFT)
    ttk.Entry(web_frame, textvariable=host_var, width=12).pack(side=tk.LEFT, padx=2)
    ttk.Label(web_frame, text="Port").pack(side=tk.LEFT)
    ttk.Entry(web_frame, textvariable=port_var, width=6).pack(side=tk.LEFT, padx=2)
    server_status_lbl = ttk.Label(web_frame, text="Server: stopped")
    server_status_lbl.pack(side=tk.LEFT, padx=6)
    def start_server():
        host = host_var.get().strip() or "127.0.0.1"
        try:
            port = int(port_var.get().strip() or "5000")
        except:
            messagebox.showerror("Port", "Invalid port")
            return
        ok,msg = WEB_THREAD.start(host=host, port=port)
        server_status_lbl.config(text=f"Server: {'running' if WEB_THREAD.server else 'stopped'}")
        messagebox.showinfo("Web server", msg)
    def stop_server():
        ok,msg = WEB_THREAD.stop()
        server_status_lbl.config(text=f"Server: {'running' if WEB_THREAD.server else 'stopped'}")
        messagebox.showinfo("Web server", msg)
    ttk.Button(web_frame, text="Start", command=start_server).pack(side=tk.LEFT, padx=2)
    ttk.Button(web_frame, text="Stop", command=stop_server).pack(side=tk.LEFT, padx=2)

    # Right: detail/edit
    detail_top = ttk.Frame(right)
    detail_top.pack(fill=tk.X)
    id_label = ttk.Label(detail_top, text="ID: -")
    id_label.pack(side=tk.LEFT)
    tags_entry = ttk.Entry(detail_top)
    tags_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True)

    text_area = tk.Text(right)
    text_area.pack(fill=tk.BOTH, expand=True, pady=6)

    action_frame = ttk.Frame(right)
    action_frame.pack(fill=tk.X)
    ttk.Button(action_frame, text="Save (update)", command=lambda: gui_save()).pack(side=tk.LEFT, padx=2)
    ttk.Button(action_frame, text="New (add)", command=lambda: gui_add()).pack(side=tk.LEFT, padx=2)
    ttk.Button(action_frame, text="Load by ID", command=lambda: gui_load_by_id()).pack(side=tk.LEFT, padx=2)

    # Populate list
    def refresh_list():
        listbox.delete(0, tk.END)
        data = v.list()
        for k in sorted(data.keys(), key=lambda x:int(x)):
            txt = data[k]['text'].replace('\n',' ')
            display = f"{k}: {txt[:80]}"
            listbox.insert(tk.END, display)
    def do_search():
        q = search_var.get().strip()
        if not q:
            refresh_list()
            return
        res = v.search(q, by_tags=False)
        listbox.delete(0, tk.END)
        for r in res:
            display = f"{r['id']}: {r['text'][:80].replace('\\n',' ')}"
            listbox.insert(tk.END, display)
    def gui_add():
        txt = simpledialog.askstring("Add", "Text:")
        if not txt:
            return
        tags = simpledialog.askstring("Tags", "Tags (comma):") or ""
        tags_list = [t.strip() for t in tags.split(",")] if tags else []
        id_ = v.add(txt, tags_list)
        refresh_list()
        messagebox.showinfo("Added", f"ID = {id_}")
    def gui_delete():
        sel = listbox.curselection()
        if not sel:
            messagebox.showwarning("Select", "Select an item first")
            return
        line = listbox.get(sel[0])
        id_ = line.split(":")[0]
        if messagebox.askyesno("Delete", f"Delete ID {id_}?"):
            v.delete(id_)
            refresh_list()
            id_label.config(text="ID: -")
            text_area.delete("1.0", tk.END)
            tags_entry.delete(0, tk.END)
    def gui_save():
        curr = id_label.cget("text").replace("ID: ","").strip()
        if curr == "-" or not curr:
            messagebox.showwarning("No ID", "Load an item or use New to add")
            return
        txt = text_area.get("1.0", tk.END).rstrip("\n")
        tags = tags_entry.get().strip()
        tags_list = [t.strip() for t in tags.split(",")] if tags else []
        ok = v.update(curr, text=txt, tags=tags_list)
        if ok:
            refresh_list()
            messagebox.showinfo("Saved", "Updated")
        else:
            messagebox.showerror("Error", "Update failed")
    def gui_load_by_id():
        id_ = simpledialog.askstring("Load", "ID:")
        if not id_:
            return
        rec = v.get(id_)
        if not rec:
            messagebox.showerror("Not found", "ID not found")
            return
        id_label.config(text=f"ID: {rec['id']}")
        text_area.delete("1.0", tk.END)
        text_area.insert("1.0", rec["text"])
        tags_entry.delete(0, tk.END)
        tags_entry.insert(0, ",".join(rec.get("tags",[])))

    def on_select(evt):
        sel = listbox.curselection()
        if not sel:
            return
        line = listbox.get(sel[0])
        id_ = line.split(":")[0]
        rec = v.get(id_)
        if not rec:
            return
        id_label.config(text=f"ID: {rec['id']}")
        text_area.delete("1.0", tk.END)
        text_area.insert("1.0", rec["text"])
        tags_entry.delete(0, tk.END)
        tags_entry.insert(0, ",".join(rec.get("tags",[])))
    listbox.bind("<<ListboxSelect>>", on_select)

    refresh_list()
    root.mainloop()

# -----------------------
# Entrypoint menu (single file menu)
# -----------------------
def main_menu():
    while True:
        print("\n=== INTERNAL KUTUPHANE ===")
        print("1) CLI")
        print("2) GUI (Tkinter) - medium")
        print("3) Start web server now (choose host/port)")
        print("4) Stop web server")
        print("5) Server status")
        print("0) Exit")
        ch = input("Choose: ").strip()
        if ch == "1":
            run_cli()
        elif ch == "2":
            if not TK_AVAILABLE:
                print("Tkinter not available on this system.")
            else:
                run_gui()
        elif ch == "3":
            host = input("Host (default 127.0.0.1): ").strip() or "127.0.0.1"
            port = input("Port (default 5000): ").strip() or "5000"
            try:
                ok,msg = WEB_THREAD.start(host=host, port=int(port))
                print(msg)
            except Exception as e:
                print("Error starting server:", e)
        elif ch == "4":
            ok,msg = WEB_THREAD.stop()
            print(msg)
        elif ch == "5":
            print("Server is", "running" if WEB_THREAD.server else "stopped")
        elif ch == "0":
            if WEB_THREAD.server:
                WEB_THREAD.stop()
            print("Goodbye.")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    # Ensure required files exist / repaired
    _ = VAULT  # load
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        if WEB_THREAD.server:
            WEB_THREAD.stop()
        sys.exit(0)
