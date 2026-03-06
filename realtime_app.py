from flask import Flask, render_template
from flask_socketio import SocketIO
from datetime import datetime

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# ---------- GLOBAL STATE ----------
state = {
    "total_packets": 0,
    "total_alerts": 0,
    "active_hosts": {}
}
blocked_ips = set()

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/history")
def history():
    try:
        with open("alerts.log", "r") as f:
            logs = f.readlines()
    except:
        logs = []

    return render_template("history.html", logs=logs[::-1])

# ---------- PACKET TELEMETRY ----------
@socketio.on("packet_event")
def handle_packet(data):
    ip = data["src_ip"]
    state["total_packets"] += 1

    if ip not in state["active_hosts"]:
        state["active_hosts"][ip] = {"count": 0, "last_seen": ""}

    state["active_hosts"][ip]["count"] += 1
    state["active_hosts"][ip]["last_seen"] = datetime.now().strftime("%H:%M:%S")

    socketio.emit("traffic_update", state)

# ---------- ALERT EVENTS ----------
@socketio.on("alert_event")
def handle_alert(data):
    state["total_alerts"] += 1

    ip = data.get("ip")
    severity = data.get("severity")

    # ---- BLOCK LOGIC ----
    if severity in ["HIGH", "CRITICAL"] and ip:
        blocked_ips.add(ip)

    socketio.emit("alert_update", data)
    socketio.emit("blocked_update", list(blocked_ips))

@socketio.on("connect")
def connect():
    print("Dashboard connected")

if __name__ == "__main__":
    socketio.run(app, debug=True)
