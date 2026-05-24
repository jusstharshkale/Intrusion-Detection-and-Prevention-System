import socket
import time
import os
import sys

# --- HELPER: Find Real IP Address ---
def get_real_ip():
    try:
        # We connect to a public DNS just to see which interface OS uses
        # We don't actually send data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# Target the REAL Interface so Scapy can see it
TARGET_IP = get_real_ip()

def print_header(title):
    print("\n" + "="*60)
    print(f"   🚀 SIMULATION: {title}")
    print("="*60)

def test_worm_signature():
    print_header("WORM ATTACK (WannaCry)")
    print(f"[*] Targeting Real IP: {TARGET_IP}")
    print(f"[*] Sending TCP Packet to Port 445 (SMB)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((TARGET_IP, 445))
        s.close()
        print("   ✅ Packet Sent Successfully")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    print("   👀 Check GUI for: 'Worm Signature'")

def test_spyware_signature():
    print_header("SPYWARE / RAT BEHAVIOR")
    print(f"[*] Targeting Real IP: {TARGET_IP}")
    print(f"[*] Sending TCP Packet to Port 1337 (Trojan)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect_ex((TARGET_IP, 1337))
        s.close()
        print("   ✅ Packet Sent Successfully")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    print("   👀 Check GUI for: 'Spyware/RAT Signature'")

def test_virus_payload():
    print_header("VIRUS PAYLOAD (EICAR)")
    print(f"[*] Targeting Real IP: {TARGET_IP}")
    print(f"[*] Sending UDP Packet with Malicious Payload...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Standard EICAR test string (Safe, but detected by AVs)
        eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        s.sendto(eicar_string, (TARGET_IP, 80))
        print("   ✅ Malicious Payload Sent")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    print("   👀 Check GUI for: 'Virus Signature'")

def test_ai_anomaly():
    print_header("ZERO-DAY ANOMALY (AI Detection)")
    print(f"[*] Targeting Real IP: {TARGET_IP}")
    print(f"[*] Sending OVERSIZED Packet (2KB) to Port 9999...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Generate huge dummy payload (2000 'A's)
        # Normal traffic is usually small; this is a statistical outlier
        huge_payload = b"A" * 2000
        s.sendto(huge_payload, (TARGET_IP, 9999))
        print("   ✅ Anomalous Packet Sent")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    print("   👀 Check GUI for: 'AI Anomaly'")

def main():
    print(f"Detected Network IP: {TARGET_IP}")
    print("WARNING: This script simulates attack patterns on YOUR OWN network.")
    print("Ensure 'launcher.py' is running first.")
    input("Press ENTER to start the simulation sequence...")
    
    test_worm_signature()
    time.sleep(3) # Wait longer for GUI to update
    
    test_spyware_signature()
    time.sleep(3)
    
    test_virus_payload()
    time.sleep(3)
    
    test_ai_anomaly()
    
    print("\n" + "="*60)
    print("   🏁 SIMULATION COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main() 