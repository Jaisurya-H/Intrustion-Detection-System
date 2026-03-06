from flask import Flask, render_template
import os

app = Flask(__name__)

LOG_FILE = "alerts.log"

def read_alerts():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()

@app.route("/")
def dashboard():
    alerts = read_alerts()
    total_alerts = len(alerts)
    recent_alerts = alerts[-10:][::-1]  # last 10 alerts
    return render_template(
        "dashboard.html",
        total_alerts=total_alerts,
        alerts=recent_alerts
    )

if __name__ == "__main__":
    app.run(debug=True)

