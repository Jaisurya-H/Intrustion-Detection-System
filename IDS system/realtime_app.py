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

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

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
    socketio.emit("alert_update", data)

@socketio.on("connect")
def connect():
    print("Dashboard connected")

if __name__ == "__main__":
    socketio.run(app, debug=True)
