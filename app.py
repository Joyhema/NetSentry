
import os
import time
import sqlite3
import hmac
from datetime import datetime

import psutil
from flask import Flask, jsonify, render_template_string, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "netsentry.db")

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static"
)

START_TIME = time.time()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#0b1220">
    <meta name="description" content="NetSentry network monitoring dashboard">
    <title>NetSentry - Network Security Monitor</title>
    <link rel="manifest" href="/static/manifest.json">
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0; padding: 24px; background: #0b1220;
            color: #e5e7eb; font-family: Arial, sans-serif;
        }
        header {
            display: flex; justify-content: space-between;
            align-items: center; flex-wrap: wrap; gap: 12px;
            margin-bottom: 24px;
        }
        h1 { margin: 0; color: #60a5fa; }
        .status { color: #86efac; font-weight: bold; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            gap: 16px;
        }
        .card {
            background: #111c30; border: 1px solid #26354d;
            border-radius: 12px; padding: 20px; min-width: 0;
        }
        .card h2 { font-size: 15px; color: #9ca3af; font-weight: normal; }
        .value { font-size: 28px; font-weight: bold; overflow-wrap: anywhere; }
        section { margin-top: 24px; }
        button {
            border: 0; border-radius: 8px; padding: 10px 14px;
            background: #2563eb; color: white; cursor: pointer;
        }
        button:hover { background: #1d4ed8; }
        .event {
            padding: 12px 0; border-bottom: 1px solid #26354d;
            overflow-wrap: anywhere;
        }
        .muted { color: #9ca3af; }
    </style>
</head>
<body>
<header>
    <div>
        <h1>NetSentry</h1>
        <p class="muted">Network Security Monitor</p>
    </div>
    <div class="status" id="status">Connecting...</div>
</header>
<main>
    <div class="grid">
        <div class="card"><h2>CPU Usage</h2><div class="value" id="cpu">--%</div></div>
        <div class="card"><h2>Memory Usage</h2><div class="value" id="memory">--%</div></div>
        <div class="card"><h2>Disk Usage</h2><div class="value" id="disk">--%</div></div>
        <div class="card"><h2>Packets Sent</h2><div class="value" id="sent">--</div></div>
        <div class="card"><h2>Packets Received</h2><div class="value" id="received">--</div></div>
        <div class="card"><h2>Uptime</h2><div class="value" id="uptime">--</div></div>
    </div>
    <section class="card">
        <h2>Security Events</h2>
        <button onclick="loadEvents()">Refresh Events</button>
        <div id="events" class="muted" aria-live="polite">Loading events...</div>
    </section>
    <section class="card">
        <h2>About NetSentry</h2>
        <p class="muted">
            This prototype displays server system usage and recorded
            security events. Alerts are indicators, not proof of an attack.
            This is not a production-grade intrusion detection system.
        </p>
    </section>
</main>
<script>
async function loadStats() {
    try {
        const response = await fetch("/api/stats");
        if (!response.ok) throw new Error("Stats request failed");
        const data = await response.json();

        document.getElementById("status").textContent = data.status || "Online";
        document.getElementById("cpu").textContent = data.cpu_percent + "%";
        document.getElementById("memory").textContent = data.memory_percent + "%";
        document.getElementById("disk").textContent = data.disk_percent + "%";
        document.getElementById("sent").textContent =
            Number(data.network.packets_sent).toLocaleString();
        document.getElementById("received").textContent =
            Number(data.network.packets_recv).toLocaleString();

        const seconds = Number(data.uptime_seconds) || 0;
        document.getElementById("uptime").textContent =
            Math.floor(seconds / 3600) + "h " +
            Math.floor((seconds % 3600) / 60) + "m";
    } catch (error) {
        document.getElementById("status").textContent = "Connection error";
    }
}

async function loadEvents() {
    const container = document.getElementById("events");
    container.textContent = "Loading events...";
    try {
        const response = await fetch("/api/events");
        if (!response.ok) throw new Error("Events request failed");
        const data = await response.json();
        container.replaceChildren();

        if (!Array.isArray(data) || data.length === 0) {
            container.textContent = "No security events yet.";
            return;
        }

        data.forEach(function(event) {
            const item = document.createElement("div");
            item.className = "event";
            const heading = document.createElement("strong");
            heading.textContent = "[" + (event.severity || "INFO") +
                "] " + (event.event_type || "Security Event");
            const message = document.createElement("div");
            message.textContent = event.message || "No additional details";
            const timestamp = document.createElement("small");
            timestamp.className = "muted";
            timestamp.textContent = event.time || event.timestamp || "";
            item.append(heading, message, timestamp);
            container.appendChild(item);
        });
    } catch (error) {
        container.textContent = "Could not load events.";
    }
}

if ("serviceWorker" in navigator) {
    window.addEventListener("load", function() {
        navigator.serviceWorker.register("/static/sw.js").catch(function(error) {
            console.error("Service worker registration failed:", error);
        });
    });
}
loadStats();
loadEvents();
setInterval(loadStats, 3000);
setInterval(loadEvents, 10000);
</script>
</body>
</html>
"""

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL
            )
        """)
        conn.commit()

def get_system_stats():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    network = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": memory.percent,
        "disk_percent": disk.percent,
        "network": {
            "bytes_sent": network.bytes_sent,
            "bytes_recv": network.bytes_recv,
            "packets_sent": network.packets_sent,
            "packets_recv": network.packets_recv
        },
        "uptime_seconds": int(time.time() - START_TIME),
        "status": "Online"
    }

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/health")
def health():
    return jsonify({"status": "online", "app": "NetSentry"})

@app.route("/api/stats")
def stats():
    return jsonify(get_system_stats())

@app.route("/api/events")
def events():
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, timestamp, event_type, message, severity
            FROM events ORDER BY id DESC LIMIT 50
        """).fetchall()
    result = []
    for row in rows:
        event = dict(row)
        event["time"] = event["timestamp"]
        result.append(event)
    return jsonify(result)

@app.route("/api/agent/events", methods=["POST"])
def receive_agent_event():
    api_key = os.environ.get("AGENT_API_KEY")
    provided_key = request.headers.get("X-API-Key", "")

    if not api_key or not hmac.compare_digest(provided_key, api_key):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    event_type = str(data.get("event_type", "agent_test")).strip()[:50]
    message = str(data.get("message", "Test event received")).strip()[:500]
    severity = str(data.get("severity", "info")).lower()

    if not event_type or not message:
        return jsonify({"error": "event_type and message are required"}), 400
    if severity not in ("info", "low", "medium", "high"):
        return jsonify({"error": "Invalid severity"}), 400

    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO events (timestamp, event_type, message, severity)
            VALUES (?, ?, ?, ?)
        """, (datetime.now().isoformat(), event_type, message, severity))
        conn.commit()

    return jsonify({"success": True, "message": "Event saved"}), 201

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
