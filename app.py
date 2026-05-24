from flask import Flask, jsonify, request
import threading
from engine import IDPSEngine
import db

app = Flask(__name__)
idps = IDPSEngine()

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "sniffer_active": idps.running,
        "ai_status": "Active" if idps.ai_active else "Loading...",
        "autoblock_on": idps.auto_block
    })

@app.route('/settings/autoblock', methods=['POST'])
def set_autoblock():
    data = request.json
    idps.auto_block = data.get('enabled', False)
    return jsonify({"status": "success", "enabled": idps.auto_block})

@app.route('/start', methods=['GET'])
def start():
    idps.start()
    return jsonify({"status": "started"})

@app.route('/stop', methods=['GET'])
def stop():
    idps.stop()
    return jsonify({"status": "stopped"})

@app.route('/stats/counts', methods=['GET'])
def stats():
    return jsonify({
        "packet_count": idps.packet_count,
        "alert_count": idps.alert_count,
        "blocked_count": len(idps.blocked_ips)
    })

@app.route('/alerts', methods=['GET'])
def alerts():
    data = db.get_recent_alerts(20)
    return jsonify(data)

@app.route('/blocking/list', methods=['GET'])
def blocked_list():
    return jsonify(db.get_blocked_list())

@app.route('/blocking/block_ip', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')
    if ip:
        db.block_ip_db(ip, "Manual Block")
        idps.refresh_blocked_ips()
        return jsonify({"status": "blocked", "ip": ip})
    return jsonify({"error": "No IP provided"}), 400

@app.route('/blocking/unblock_ip', methods=['POST'])
def unblock_ip():
    data = request.json
    ip = data.get('ip')
    if ip:
        db.unblock_ip_db(ip)
        idps.refresh_blocked_ips()
        return jsonify({"status": "unblocked", "ip": ip})
    return jsonify({"error": "No IP provided"}), 400

if __name__ == '__main__':
    app.run(port=5000, debug=False)