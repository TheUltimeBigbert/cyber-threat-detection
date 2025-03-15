from flask import Flask
from flask_socketio import SocketIO
import random
import time
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Random threat locations
LOCATIONS = [
    {"lat": 37.7749, "lon": -122.4194, "location": "San Francisco, USA"},
    {"lat": 51.5074, "lon": -0.1278, "location": "London, UK"},
    {"lat": 35.6895, "lon": 139.6917, "location": "Tokyo, Japan"},
    {"lat": -33.8688, "lon": 151.2093, "location": "Sydney, Australia"},
    {"lat": 28.6139, "lon": 77.2090, "location": "New Delhi, India"},
]

THREAT_TYPES = ["Malware", "Phishing", "DDoS Attack", "SQL Injection", "Ransomware"]

def generate_threats():
    while True:
        time.sleep(random.randint(5, 15))  # Random time delay
        threat = random.choice(LOCATIONS)
        data = {
            "lat": threat["lat"],
            "lon": threat["lon"],
            "ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            "type": random.choice(THREAT_TYPES),
            "location": threat["location"],
        }
        print(f"New Threat Detected: {data}")  # Log in console
        socketio.emit("new_threat", data)  # Send data to frontend

# Run the background thread
threading.Thread(target=generate_threats, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
