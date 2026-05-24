import sqlite3
from datetime import datetime
import os

DB_NAME = "idps_logs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Table for Alerts
    c.execute('''CREATE TABLE IF NOT EXISTS alerts 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  source_ip TEXT, 
                  dest_ip TEXT, 
                  alert_type TEXT, 
                  description TEXT,
                  action_taken TEXT)''')
    
    # Table for Blocked IPs
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  ip_address TEXT UNIQUE, 
                  reason TEXT, 
                  date_added TEXT)''')
    conn.commit()
    conn.close()

def log_alert(src_ip, dst_ip, alert_type, desc, action="LOGGED"):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO alerts (timestamp, source_ip, dest_ip, alert_type, description, action_taken) VALUES (?, ?, ?, ?, ?, ?)",
              (timestamp, src_ip, dst_ip, alert_type, desc, action))
    conn.commit()
    conn.close()

def block_ip_db(ip, reason):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        date_added = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO blocked_ips (ip_address, reason, date_added) VALUES (?, ?, ?)", (ip, reason, date_added))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False # Already blocked

def unblock_ip_db(ip):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips WHERE ip_address=?", (ip,))
    conn.commit()
    conn.close()

def get_recent_alerts(limit=50):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

def get_blocked_list():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM blocked_ips")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows

# Initialize on import
init_db()