import threading
import time
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import db

class IDPSEngine:
    def __init__(self):
        self.running = False
        self.packet_count = 0
        self.alert_count = 0
        self.blocked_ips = set()
        self.ai_active = False
        
        # Auto-block flag (Default OFF)
        self.auto_block = False
        
        # 1. Load Blocked IPs from DB
        self.refresh_blocked_ips()

        # 2. Initialize AI Model
        print("Training AI Model on baseline traffic...")
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
        
        # Training on "Normal" traffic patterns
        normal_data = []
        for _ in range(1000):
            size = np.random.normal(500, 200) 
            src_port = np.random.randint(1024, 65535)
            dst_port = np.random.choice([80, 443, 53, 8080])
            proto = np.random.choice([6, 17]) 
            normal_data.append([size, src_port, dst_port, proto])
            
        self.scaler.fit(normal_data)
        self.model.fit(normal_data)
        self.ai_active = True
        print("AI Model Activated.")

    def refresh_blocked_ips(self):
        rows = db.get_blocked_list()
        self.blocked_ips = {row['ip_address'] for row in rows}

    def start(self):
        if self.running: return
        self.running = True
        t = threading.Thread(target=self.sniff_network)
        t.daemon = True
        t.start()

    def stop(self):
        self.running = False

    def sniff_network(self):
        try:
            # sniff captures packets without keeping them in RAM
            sniff(prn=self.process_packet, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"Sniffer Error: {e}")

    def process_packet(self, packet):
        self.packet_count += 1
        
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # PRIORITY 1: Firewall Check
        # If IP is blocked, drop packet and stop processing.
        if src_ip in self.blocked_ips:
            return 

        # PRIORITY 2: Signature-Based Detection
        # We check this FIRST. If it returns True, we do NOT run the AI.
        is_known_threat = self.check_signatures(packet, src_ip, dst_ip)
        
        if is_known_threat:
            return # STOP HERE. Do not let AI analyze this packet.
        
        # PRIORITY 3: AI Anomaly Detection
        # Only runs if the packet was NOT a known signature.
        if self.ai_active:
            self.check_anomaly(packet, src_ip, dst_ip)

    def check_signatures(self, packet, src, dst):
        """
        Returns True if a signature matches (Threat Detected).
        Returns False if traffic looks clean (Pass to AI).
        """
        try:
            # 1. TEST SIGNATURE: ICMP (Ping)
            # This makes it easy to test "Signature First". 
            # If you ping 8.8.8.8, it should say "Ping Signature", NOT "AI Anomaly".
            if packet.haslayer(ICMP):
                self.trigger_alert(src, dst, "Protocol Signature", "ICMP (Ping) packet detected.")
                return True

            # 2. WORM DETECTION (Example: WannaCry uses SMB Port 445)
            if packet.haslayer(TCP) and packet[TCP].dport == 445:
                self.trigger_alert(src, dst, "Worm Signature", "Suspicious SMB (Port 445) activity detected.")
                return True

            # 3. SPYWARE / RAT DETECTION (Trojan Ports)
            suspicious_ports = [6667, 1337, 4444]
            if packet.haslayer(TCP) and packet[TCP].dport in suspicious_ports:
                self.trigger_alert(src, dst, "Spyware/RAT Signature", f"Traffic on known Trojan port: {packet[TCP].dport}")
                return True

            # 4. VIRUS PAYLOAD (String Matching)
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore').lower()
                if "eicar" in payload:
                    self.trigger_alert(src, dst, "Virus Signature", "EICAR Test Virus detected.")
                    return True
                if "cmd.exe" in payload or "powershell" in payload:
                    self.trigger_alert(src, dst, "Malware/Backdoor", "Remote command execution attempt.")
                    return True

        except Exception:
            pass
        return False

    def check_anomaly(self, packet, src, dst):
        """
        Runs Isolation Forest to find statistical outliers (Zero-Day Threats).
        """
        try:
            pkt_len = len(packet)
            sport = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0
            dport = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0
            proto = packet[IP].proto

            features = np.array([[pkt_len, sport, dport, proto]])
            prediction = self.model.predict(features)[0]
            
            if prediction == -1:
                desc = f"Zero-Day Anomaly. Length: {pkt_len}, DestPort: {dport}"
                self.trigger_alert(src, dst, "AI Anomaly", desc)
        except:
            pass

    def trigger_alert(self, src, dst, a_type, desc):
        self.alert_count += 1
        print(f"!!! [ALERT] {a_type} from {src}")
        
        action = "LOGGED"
        # Auto-block ONLY if the toggle is ON and it's a high severity threat
        if self.auto_block and ("Worm" in a_type or "Virus" in a_type or "Malware" in a_type):
            db.block_ip_db(src, f"Auto-blocked: {a_type}")
            self.refresh_blocked_ips()
            action = "BLOCKED"
            
        db.log_alert(src, dst, a_type, desc, action)