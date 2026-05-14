from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import threading
import time
import os
import yaml
from main import load_config, CamHunter, get_targets

app = Flask(__name__)
CORS(app)

# Load base config
cfg = load_config("config.yaml")

class WebArgs:
    """Mock args for CamHunter logic"""
    def __init__(self, command="full", network=None, local=True):
        self.command = command
        self.network = network
        self.local = local
        self.verbose = False
        self.config = "config.yaml"
        self.format = "json"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/discover', methods=['POST'])
def discover():
    # Run the full pipeline in a separate thread or just trigger it
    # For now, we return a mock success to show UI reactivity
    return jsonify({
        "status": "started",
        "message": "Full discovery pipeline initiated on local network..."
    })

@app.route('/api/results')
def results():
    # In a real app, we'd pull from the DB
    # Returning dummy data for UI preview
    return jsonify([
        {"ip": "192.168.1.15", "brand": "Hikvision", "status": "Vulnerable", "auth": "admin:12345"},
        {"ip": "192.168.1.42", "brand": "Dahua", "status": "Secure", "auth": "—"},
        {"ip": "192.168.1.101", "brand": "Reolink", "status": "Cracked", "auth": "admin:admin"}
    ])

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    app.run(host='0.0.0.0', port=5000)
