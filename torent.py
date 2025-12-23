import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from PIL import Image, ImageTk
import threading
import io
import sys
import subprocess
import hashlib
import bcrypt
import json
import base64
from datetime import datetime

# ================= CONFIG SUPABASE (À REMPLIR) =================
SUPABASE_URL = "https://lkhapghkcowoaltvgqvs.supabase.co"  # ← À changer
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxraGFwZ2hrY293b2FsdHZncXZzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjY0MjQwMzcsImV4cCI6MjA4MjAwMDAzN30.Aje3qYASZ3gWCaXtUW4984IgHebnbdfWAw7HE3RBsXQ"             # ← À changer
# ==============================================================

base_url = "https://www.warez-torrent1.com"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "apikey": SUPABASE_ANON_KEY,
    "Authorization": f"Bearer {SUPABASE_ANON_KEY}"
}

session = requests.Session()
session.headers.update(headers)

# Fichier local pour stocker les identifiants chiffrés
CREDENTIALS_FILE = "user.dat"

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def encrypt_data(data, password):
    key = hashlib.sha256(password.encode()).digest()
    f = hashlib.sha256
    encrypted = base64.b64encode(f(key + data.encode()).digest()).decode()
    return encrypted

def decrypt_data(encrypted, password):
    try:
        key = hashlib.sha256(password.encode()).digest()
        decrypted = base64.b64decode(encrypted)
        return f(key + decrypted).hexdigest()  # Simple test
    except:
        return None

def save_credentials(username, password_hash):
    data = json.dumps({"username": username, "password_hash": password_hash})
    encrypted = encrypt_data(data, password_hash)
    with open(CREDENTIALS_FILE, "w") as f:
        f.write(encrypted)

def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        return None
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            encrypted = f.read()
        # On ne peut pas déchiffrer sans mot de passe, donc on retourne juste pour login
        return encrypted
    except:
        return None

def register_user(username, password):
    password_hash = hash_password(password)
    response = requests.post(
        f"{SUPABASE_URL}/rest/v1/users",
        headers={**headers, "Prefer": "return=representation"},
        json={"username": username, "password_hash": password_hash}
    )
    if response.status_code in [200, 201]:
        save_credentials(username, password_hash)
        return True
    else:
        messagebox.showerror("Erreur", f"Échec inscription : {response.text}")
        return False

def login_user(username, password):
    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/users",
        headers=headers,
        params={"username": f"eq.{username}"}
    )
    if response.status_code == 200 and response.json():
        user = response.json()[0]
        if check_password(password, user["password_hash"]):
            if user.get("is_ban", False):
                messagebox.showerror("Bloqué", "Votre compte a été bloqué par l'administrateur.")
                sys.exit()
            save_credentials(username, user["password_hash"])
            return username
    messagebox.showerror("Erreur", "Identifiants incorrects")
    return None

def log_search(username, term):
    requests.post(
        f"{SUPABASE_URL}/rest/v1/history",
        headers=headers,
        json={"username": username, "search_term": term}
    )

def check_ban(username):
    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/users",
        headers=headers,
        params={"username": f"eq.{username}", "select": "is_ban"}
    )
    if response.status_code == 200 and response.json():
        return response.json()[0].get("is_ban", False)
    return False

# ================= RESTE DU CODE (inchangé sauf intégration auth) =================

def get_poster_url_from_detail(detail_url, torrent_title):
    try:
        resp = session.get(detail_url, timeout=12)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        for img in soup.find_all('img'):
            src = img.get('src')
            alt = img.get('alt', '').strip()
            if src and src.startswith('https://') and 'zimage.cc' in src and torrent_title in alt:
                return src
        return None
    except:
        return None

def launch_qbittorrent_with_torrent(torrent_path):
    try:
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))

        qbittorrent_exe = os.path.join(base_path, 'qBittorrentPortable', 'App', 'qBittorrent', 'qbittorrent.exe')

        if not os.path.exists(qbittorrent_exe):
            messagebox.showerror("Erreur", "qBittorrent portable non trouvé !")
            return False

        subprocess.Popen([qbittorrent_exe, torrent_path])
        return True
    except Exception as e:
        messagebox.showerror("Erreur lancement", f"Impossible de lancer qBittorrent :\n{e}")
        return False

def download_and_open_torrent(detail_url, title):
    try:
        resp = session.get(detail_url, timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        download_link = None
        for a in soup.find_all('a', href=True):
            text = a.get_text(strip=True).lower()
            href = a['href']
            if "télécharger le torrent" in text or ".torrent" in href or "/get_torrents/" in href:
                download_link = base_url + href if href.startswith('/') else href
                break
        
        if not download_link:
            messagebox.showerror("Erreur", "Lien torrent non trouvé")
            return
        
        torrent_resp = session.get(download_link, timeout=30)
        torrent_resp.raise_for_status()
        
        filename = title[:100].replace('/', '_').replace('\\', '_').replace(' ', '_') + ".torrent"
        cd = torrent_resp.headers.get('Content-Disposition')
        if cd and 'filename=' in cd:
            filename = cd.split('filename=')[1].strip('"\'')
        
        save_path = os.path.join(os.getcwd(), filename)
        with open(save_path, 'wb') as f:
            f.write(torrent_resp.content)
        
        messagebox.showinfo("Succès", f"Torrent téléchargé :\n{os.path.basename(save_path)}")

        launch_qbittorrent_with_torrent(save_path)

    except Exception as e:
        messagebox.showerror("Erreur", f"Échec :\n{e}")

class TorrentGUI:
    def __init__(self, root, username):
        self.root = root
        self.root.title(f"Warez-Torrent Downloader - {username}")
        self.root.geometry("1200x900")
        self.root.configure(bg="#000000")
        self.username = username
        
        style = ttk.Style()
        style.theme_use('clam')

        tk.Label(root, text="Recherche torrent", font=("Arial", 20, "bold"), bg="#000000", fg="white").pack(pady=30)
        
        search_frame = tk.Frame(root, bg="#000000")
        search_frame.pack(pady=10)
        
        self.entry = tk.Entry(search_frame, width=70, font=("Arial", 16), bg="#222222", fg="white", insertbackground="white")
        self.entry.pack(side=tk.LEFT, padx=15)
        self.entry.bind("<Return>", lambda e: self.search())
        self.entry.focus()
        
        tk.Button(search_frame, text="Rechercher", font=("Arial", 16), command=self.search,
                  bg="#4CAF50", fg="white", activebackground="#45a049", padx=30, pady=10).pack(side=tk.LEFT)
        
        results_frame = tk.Frame(root, bg="#000000")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=20)
        
        self.canvas = tk.Canvas(results_frame, bg="#000000", highlightthickness=0)
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#000000")
        
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
        
        self.current_term = ""
        self.current_offset = 0
        self.has_next = False
        self.pagination_frame = None
        
        self.images_refs = []

    def search(self, offset=0):
        term = self.entry.get().strip()
        if not term:
            messagebox.showwarning("Attention", "Entre un nom !")
            return
        
        # Log la recherche dans Supabase
        log_search(self.username, term)
        
        # Vérifie si l'utilisateur est banni (à chaque recherche)
        if check_ban(self.username):
            messagebox.showerror("Bloqué", "Votre compte a été bloqué. L'application va se fermer.")
            self.root.quit()
            return
        
        self.current_term = term
        self.current_offset = offset
        
        for w in self.scrollable_frame.winfo_children():
            w.destroy()
        
        loading = tk.Label(self.scrollable_frame, text="Recherche en cours...", font=("Arial", 18), bg="#000000", fg="white")
        loading.pack(pady=100)
        self.root.update()
        
        threading.Thread(target=self.perform_search, args=(term, offset, loading), daemon=True).start()

    def perform_search(self, term, offset, loading_label):
        if offset == 0:
            url = f"{base_url}/recherche/{quote(term)}"
        else:
            url = f"{base_url}/recherche/{quote(term)}/{offset}"
        
        try:
            resp = session.get(url, timeout=15)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            table = None
            for t in soup.find_all('table'):
                hdrs = [th.get_text(strip=True) for th in t.find_all('th')]
                if "Nom du torrent" in hdrs and "Taille" in hdrs:
                    table = t
                    break
            
            if not table:
                self.root.after(0, lambda: self.show_no_results(loading_label))
                return
            
            results = []
            rows = table.find_all('tr')[1:]
            for row in rows:
                cols = row.find_all('td')
                if len(cols) >= 4:
                    a = cols[0].find('a')
                    if a and a['href'].startswith('/detail/'):
                        results.append({
                            'title': a.get_text(strip=True),
                            'detail_url': base_url + a['href'],
                            'size': cols[1].get_text(strip=True),
                            'seed': cols[2].get_text(strip=True),
                            'leech': cols[3].get_text(strip=True)
                        })
            
            has_next = False
            next_offset = 0
            for a in soup.find_all('a', href=True):
                if a.get_text(strip=True) == "Suivant ►":
                    href = a['href']
                    if href.startswith('/recherche/'):
                        parts = href.split('/')[3:]
                        if parts and parts[0].isdigit():
                            next_offset = int(parts[0])
                            has_next = True
                    break
            
            current_page = (offset // 50) + 1 if len(results) > 0 else 1
            
            self.root.after(0, lambda: self.display_results(results, loading_label, has_next, next_offset, current_page))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erreur", f"Connexion :\n{e}"))

    def show_no_results(self, loading_label):
        loading_label.destroy()
        tk.Label(self.scrollable_frame, text="Aucun résultat", font=("Arial", 18), bg="#000000", fg="white").pack(pady=100)

    def display_results(self, results, loading_label, has_next, next_offset, current_page):
        loading_label.destroy()
        
        self.has_next = has_next
        
        tk.Label(self.scrollable_frame, text=f"{len(results)} résultat(s) - Page {current_page}", 
                 font=("Arial", 18, "bold"), bg="#000000", fg="white").pack(pady=10)
        
        for res in results:
            frame = tk.Frame(self.scrollable_frame, bg="#111111", relief="groove", bd=2, pady=25, padx=20)
            frame.pack(fill=tk.X, padx=50, pady=12)
            
            poster_label = tk.Label(frame, text="Chargement\nposter...", bg="#222222", fg="gray", font=("Arial", 11))
            poster_label.pack(side=tk.LEFT, padx=25)
            
            info_frame = tk.Frame(frame, bg="#111111")
            info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20)
            
            tk.Label(info_frame, text=res['title'], font=("Arial", 15, "bold"), wraplength=650, justify=tk.LEFT, bg="#111111", fg="white").pack(anchor=tk.W)
            tk.Label(info_frame, text=f"Taille : {res['size']} | Seeds : {res['seed']} | Leech : {res['leech']}", 
                     font=("Arial", 13), fg="#aaaaaa", bg="#111111").pack(anchor=tk.W, pady=10)
            
            tk.Button(info_frame, text="Télécharger & Lancer", font=("Arial", 13),
                      bg="#2196F3", fg="white", activebackground="#1976D2", padx=20, pady=10,
                      command=lambda d=res['detail_url'], t=res['title']: download_and_open_torrent(d, t)).pack(anchor=tk.W, pady=12)
            
            threading.Thread(target=self.load_real_poster, args=(res['detail_url'], res['title'], poster_label), daemon=True).start()
        
        if self.pagination_frame:
            self.pagination_frame.destroy()
        
        self.pagination_frame = tk.Frame(self.scrollable_frame, bg="#000000")
        self.pagination_frame.pack(pady=20)
        
        previous_offset = max(0, self.current_offset - 50)
        if self.current_offset > 0:
            tk.Button(self.pagination_frame, text="◄ Précédente", font=("Arial", 12),
                      bg="#333333", fg="white", command=lambda: self.search(previous_offset)).pack(side=tk.LEFT, padx=10)
        
        tk.Label(self.pagination_frame, text=f"Page {current_page}", 
                 font=("Arial", 14), bg="#000000", fg="white").pack(side=tk.LEFT, padx=20)
        
        if has_next:
            tk.Button(self.pagination_frame, text="Suivante ►", font=("Arial", 12),
                      bg="#333333", fg="white", command=lambda: self.search(next_offset)).pack(side=tk.LEFT, padx=10)

    def load_real_poster(self, detail_url, torrent_title, label):
        poster_url = get_poster_url_from_detail(detail_url, torrent_title)
        if poster_url:
            try:
                data = session.get(poster_url, timeout=15).content
                img = Image.open(io.BytesIO(data))
                
                max_width = 250
                if img.width > max_width:
                    ratio = max_width / img.width
                    new_height = int(img.height * ratio)
                    img = img.resize((max_width, new_height), Image.LANCZOS)
                
                photo = ImageTk.PhotoImage(img)
                
                self.root.after(0, lambda: label.config(image=photo, text="", bg="#111111"))
                self.images_refs.append(photo)
            except:
                self.root.after(0, lambda: label.config(text="Image\nindisponible", font=("Arial", 11), fg="red", bg="#111111"))
        else:
            self.root.after(0, lambda: label.config(text="Pas\nd'image", font=("Arial", 11), fg="gray", bg="#111111"))

# ================= AUTHENTIFICATION AU DÉMARRAGE =================
def authenticate():
    if os.path.exists(CREDENTIALS_FILE):
        # Tentative de connexion automatique
        username = simpledialog.askstring("Connexion", "Nom d'utilisateur :", parent=root)
        password = simpledialog.askstring("Connexion", "Mot de passe :", show='*', parent=root)
        if username and password:
            logged = login_user(username, password)
            if logged:
                return logged
    else:
        # Premier démarrage → inscription
        messagebox.showinfo("Bienvenue", "Premier démarrage : crée ton compte")
        username = simpledialog.askstring("Inscription", "Choisis un nom d'utilisateur :", parent=root)
        password = simpledialog.askstring("Inscription", "Choisis un mot de passe :", show='*', parent=root)
        if username and password:
            if register_user(username, password):
                return username
    
    messagebox.showerror("Erreur", "Authentification échouée. Fermeture.")
    sys.exit()

if __name__ == "__main__":
    root = tk.Tk()
    username = authenticate()
    app = TorrentGUI(root, username)
    root.mainloop()