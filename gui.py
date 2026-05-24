import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import requests
import queue
import time
import threading
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation

API_URL = "http://127.0.0.1:5000"

# --- Theme Configurations ---
THEMES = {
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "frame_bg": "#e1e1e1",
        "button_bg": "#e1e1e1",
        "graph_bg": "#f0f0f0",
        "graph_face": "#ffffff",
        "tree_bg": "white",
        "tree_fg": "black",
        "select_bg": "#0078d7",
        "select_fg": "white",
        "header_fg": "black"
    },
    "dark": {
        "bg": "#2b2b2b",
        "fg": "#ffffff",
        "frame_bg": "#333333",
        "button_bg": "#444444",
        "graph_bg": "#2b2b2b",
        "graph_face": "#333333",
        "tree_bg": "#333333",
        "tree_fg": "#ffffff",
        "select_bg": "#555555",
        "select_fg": "white",
        "header_fg": "#ffffff"
    }
}

class IDPSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid IDPS - Signature & AI Engine")
        self.root.geometry("1100x750")
        
        # Theme Setup
        self.current_theme = "light"
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.running = True
        self.queue = queue.Queue()
        
        # --- Metrics for TPM Graph ---
        # Stores the counts for the graph line (Visual)
        self.graph_data = [0] * 60 
        # Stores the raw number of alerts per second for the last 60 seconds (Logic)
        self.alert_buffer = [0] * 60 
        
        self.autoblock_status = False 
        
        self.create_widgets()
        self.apply_theme()
        self.start_polling()

    def create_widgets(self):
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill='both', expand=True)

        # Header
        header_frame = ttk.Frame(self.main_container)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        self.lbl_title = ttk.Label(header_frame, text="🛡️ Network IDPS Monitor", font=('Segoe UI', 14, 'bold'))
        self.lbl_title.pack(side='left', pady=5)

        self.btn_theme = ttk.Button(header_frame, text="🌙 Dark Mode", command=self.toggle_theme)
        self.btn_theme.pack(side='right', pady=5)

        # Tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        dash_frame = ttk.Frame(self.notebook)
        self.notebook.add(dash_frame, text="Live Dashboard")
        self.build_dashboard(dash_frame)
        
        alert_frame = ttk.Frame(self.notebook)
        self.notebook.add(alert_frame, text="Alerts & Logs")
        self.build_alerts(alert_frame)
        
        block_frame = ttk.Frame(self.notebook)
        self.notebook.add(block_frame, text="Firewall / Blocking")
        self.build_blocking(block_frame)

    def toggle_theme(self):
        if self.current_theme == "light":
            self.current_theme = "dark"
            self.btn_theme.config(text="☀️ Light Mode")
        else:
            self.current_theme = "light"
            self.btn_theme.config(text="🌙 Dark Mode")
        self.apply_theme()

    def apply_theme(self):
        t = THEMES[self.current_theme]
        self.root.configure(bg=t["bg"])
        self.style.configure(".", background=t["bg"], foreground=t["fg"])
        self.style.configure("TFrame", background=t["bg"])
        self.style.configure("TLabelframe", background=t["bg"], foreground=t["fg"])
        self.style.configure("TLabelframe.Label", background=t["bg"], foreground=t["fg"])
        self.style.configure("TLabel", background=t["bg"], foreground=t["fg"])
        self.style.configure("TButton", background=t["button_bg"], foreground=t["fg"], borderwidth=1)
        self.style.map("TButton", background=[("active", t["select_bg"])], foreground=[("active", t["select_fg"])])
        self.style.configure("TNotebook", background=t["bg"])
        self.style.configure("TNotebook.Tab", background=t["frame_bg"], foreground=t["fg"], padding=[10, 2])
        self.style.map("TNotebook.Tab", background=[("selected", t["select_bg"])], foreground=[("selected", t["select_fg"])])
        self.style.configure("Treeview", background=t["tree_bg"], foreground=t["tree_fg"], fieldbackground=t["tree_bg"], borderwidth=0)
        self.style.map("Treeview", background=[("selected", t["select_bg"])], foreground=[("selected", t["select_fg"])])
        self.style.configure("Treeview.Heading", background=t["frame_bg"], foreground=t["fg"])

        if hasattr(self, 'fig'):
            self.fig.patch.set_facecolor(t["graph_bg"])
            self.ax.set_facecolor(t["graph_face"])
            color = t["fg"]
            for spine in self.ax.spines.values():
                spine.set_color(color)
            self.ax.tick_params(axis='x', colors=color)
            self.ax.tick_params(axis='y', colors=color)
            self.ax.yaxis.label.set_color(color)
            self.ax.xaxis.label.set_color(color)
            self.ax.title.set_color(color)
            self.canvas.draw()

    def build_dashboard(self, parent):
        ctrl_panel = ttk.LabelFrame(parent, text="Engine Controls", padding=10)
        ctrl_panel.pack(fill='x', pady=5)
        
        ttk.Button(ctrl_panel, text="Start Engine", command=self.start_engine).pack(side='left', padx=5)
        ttk.Button(ctrl_panel, text="Stop Engine", command=self.stop_engine).pack(side='left', padx=5)
        
        self.lbl_status = ttk.Label(ctrl_panel, text="Status: DISCONNECTED", font=('Arial', 10, 'bold'), foreground='grey')
        self.lbl_status.pack(side='right', padx=10)

        stats_panel = ttk.Frame(parent)
        stats_panel.pack(fill='x', pady=10)
        
        self.card_packets = self.create_stat_card(stats_panel, "Total Packets", "0", "blue")
        self.card_alerts = self.create_stat_card(stats_panel, "Threats Detected", "0", "red")
        self.card_blocked = self.create_stat_card(stats_panel, "Blocked IPs", "0", "orange")

        # --- UPDATED GRAPH SECTION ---
        graph_frame = ttk.LabelFrame(parent, text="Threat Metrics", padding=10)
        graph_frame.pack(fill='both', expand=True)
        
        self.fig = Figure(figsize=(5, 3), dpi=100)
        self.ax = self.fig.add_subplot(111)
        # Using a red line to signify threats
        self.line, = self.ax.plot(self.graph_data, color='#d62728', linewidth=2)
        
        self.ax.set_title("Live Threat Rate (Threats per Minute)")
        self.ax.set_ylabel("Threats / Min")
        self.ax.set_ylim(0, 10) # Initial scale
        self.ax.grid(True, linestyle='--', alpha=0.3)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

    def create_stat_card(self, parent, title, value, color):
        frame = ttk.LabelFrame(parent, text=title, padding=10)
        frame.pack(side='left', fill='x', expand=True, padx=5)
        lbl = ttk.Label(frame, text=value, font=('Arial', 20, 'bold'), foreground=color)
        lbl.pack()
        return lbl

    def build_alerts(self, parent):
        cols = ('Time', 'Source', 'Dest', 'Type', 'Action')
        self.tree_alerts = ttk.Treeview(parent, columns=cols, show='headings', height=20)
        for col in cols:
            self.tree_alerts.heading(col, text=col)
            self.tree_alerts.column(col, width=150)
        self.tree_alerts.pack(fill='both', expand=True, padx=5, pady=5)
        
    def build_blocking(self, parent):
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', pady=5)
        
        self.btn_autoblock = ttk.Button(btn_frame, text="Auto-Block: OFF", command=self.toggle_autoblock)
        self.btn_autoblock.pack(side='left', padx=5)
        
        ttk.Button(btn_frame, text="Block IP Manually", command=self.manual_block).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Unblock Selected", command=self.manual_unblock).pack(side='left', padx=5)
        
        cols = ('IP Address', 'Date Added', 'Reason')
        self.tree_blocked = ttk.Treeview(parent, columns=cols, show='headings')
        for col in cols:
            self.tree_blocked.heading(col, text=col)
        self.tree_blocked.pack(fill='both', expand=True, padx=5, pady=5)

    def start_engine(self):
        try: requests.get(f"{API_URL}/start")
        except: messagebox.showerror("Error", "Backend offline")

    def stop_engine(self):
        try: requests.get(f"{API_URL}/stop")
        except: pass

    def manual_block(self):
        ip = simpledialog.askstring("Block IP", "Enter IP to block:")
        if ip: requests.post(f"{API_URL}/blocking/block_ip", json={'ip': ip})

    def manual_unblock(self):
        sel = self.tree_blocked.selection()
        if sel:
            item = self.tree_blocked.item(sel[0])
            ip = item['values'][0]
            requests.post(f"{API_URL}/blocking/unblock_ip", json={'ip': ip})
            
    def toggle_autoblock(self):
        new_state = not self.autoblock_status
        try:
            requests.post(f"{API_URL}/settings/autoblock", json={'enabled': new_state})
        except: pass

    def start_polling(self):
        thread = threading.Thread(target=self.poll_backend)
        thread.daemon = True
        thread.start()
        self.root.after(1000, self.update_gui)

    def poll_backend(self):
        # We track the last count to calculate the 'Delta' (New alerts in this second)
        last_alert_count_total = 0
        
        while self.running:
            try:
                stats = requests.get(f"{API_URL}/stats/counts", timeout=1).json()
                alerts = requests.get(f"{API_URL}/alerts", timeout=1).json()
                blocked = requests.get(f"{API_URL}/blocking/list", timeout=1).json()
                status = requests.get(f"{API_URL}/status", timeout=1).json()
                
                # --- TPM Calculation Logic ---
                current_alert_total = stats['alert_count']
                
                # How many NEW alerts happened since last second?
                if last_alert_count_total == 0:
                    # First run or reset
                    new_alerts_this_sec = 0
                else:
                    new_alerts_this_sec = current_alert_total - last_alert_count_total
                
                # Ensure it doesn't go negative if server restarts
                if new_alerts_this_sec < 0: new_alerts_this_sec = 0
                
                last_alert_count_total = current_alert_total

                self.queue.put({
                    'stats': stats, 
                    'alerts': alerts, 
                    'blocked': blocked,
                    'status': status,
                    'new_alerts': new_alerts_this_sec
                })
            except:
                self.queue.put("ERROR")
            time.sleep(1)

    def update_gui(self):
        try:
            while not self.queue.empty():
                data = self.queue.get_nowait()
                
                if data == "ERROR":
                    self.lbl_status.config(text="Status: BACKEND OFFLINE", foreground='red')
                    continue

                if data['status']['sniffer_active']:
                    self.lbl_status.config(text="Status: MONITORING ACTIVE", foreground='green')
                else:
                    self.lbl_status.config(text="Status: IDLE", foreground='orange')
                
                self.autoblock_status = data['status']['autoblock_on']
                state_text = "ON" if self.autoblock_status else "OFF"
                self.btn_autoblock.config(text=f"Auto-Block: {state_text}")
                
                self.card_packets.config(text=f"{data['stats']['packet_count']}")
                self.card_alerts.config(text=f"{data['stats']['alert_count']}")
                self.card_blocked.config(text=f"{data['stats']['blocked_count']}")

                # --- Update TPM Graph ---
                # 1. Add new alerts (this second) to the 60-second buffer
                self.alert_buffer.append(data['new_alerts'])
                self.alert_buffer.pop(0) # Remove oldest second
                
                # 2. Calculate sum of last 60 seconds = Threats Per Minute
                tpm = sum(self.alert_buffer)
                
                # 3. Update the visual graph line
                self.graph_data.append(tpm)
                self.graph_data.pop(0)
                
                self.line.set_ydata(self.graph_data)
                
                # Dynamic scaling (always at least 10 for visibility)
                max_y = max(10, max(self.graph_data) + 2)
                self.ax.set_ylim(0, max_y)
                self.canvas.draw()
                
                self.tree_alerts.delete(*self.tree_alerts.get_children())
                for a in data['alerts']:
                    self.tree_alerts.insert('', 0, values=(a['timestamp'], a['source_ip'], a['dest_ip'], a['alert_type'], a['action_taken']))
                
                self.tree_blocked.delete(*self.tree_blocked.get_children())
                for b in data['blocked']:
                    self.tree_blocked.insert('', 'end', values=(b['ip_address'], b['date_added'], b['reason']))

        except: pass
        self.root.after(1000, self.update_gui)

if __name__ == "__main__":
    root = tk.Tk()
    app = IDPSApp(root)
    root.mainloop()