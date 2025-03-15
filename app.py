from flask import Flask
from flask_socketio import SocketIO
import random
import time
import eventlet

eventlet.monkey_patch()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Simulated threat data
threat_types = ["Malware", "Phishing", "DDoS", "Ransomware", "Brute Force"]
statuses = ["Pending", "Resolved"]
severity_levels = ["Low", "Medium", "High"]
source_ips = ["192.168.1.1", "203.0.113.42", "10.0.0.5", "45.67.89.10"]

def generate_random_threat():
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "severity": random.choice(severity_levels),
        "source_ip": random.choice(source_ips),
        "type": random.choice(threat_types),
        "status": random.choice(statuses),
        "location": [random.uniform(-90, 90), random.uniform(-180, 180)],  # Random lat/lon
    }

def send_threat_data():
    while True:
        threat = generate_random_threat()
        socketio.emit("new_threat", threat)
        eventlet.sleep(random.randint(3, 7))  # Send threats every 3-7 seconds

@socketio.on("connect")
def on_connect():
    print("Client connected!")

if __name__ == "__main__":
    eventlet.spawn(send_threat_data)
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
