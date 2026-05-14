"""
SQLite Database Management for CamHunter v2.0
"""

import sqlite3
import json
import os
from datetime import datetime

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Table for discovered cameras
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cameras (
                    ip TEXT PRIMARY KEY,
                    ports TEXT,
                    brand TEXT,
                    model TEXT,
                    auth_type TEXT,
                    is_cracked INTEGER DEFAULT 0,
                    credentials TEXT,
                    last_seen TEXT
                )
            ''')
            # Table for session state
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            conn.commit()

    def insert_camera(self, cam: dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            ports_json = json.dumps(cam.get("ports", []))
            cursor.execute('''
                INSERT OR REPLACE INTO cameras (ip, ports, brand, model, auth_type, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                cam.get("ip"),
                ports_json,
                cam.get("brand"),
                cam.get("model"),
                cam.get("auth_type"),
                datetime.now().isoformat()
            ))
            conn.commit()

    def update_cracked(self, ip: str, result: dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            creds_json = json.dumps(result.get("credentials", []))
            cursor.execute('''
                UPDATE cameras 
                SET is_cracked = 1, credentials = ? 
                WHERE ip = ?
            ''', (creds_json, ip))
            conn.commit()

    def get_all_ips(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ip FROM cameras')
            return [row[0] for row in cursor.fetchall()]

    def get_uncracked_cameras(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cameras WHERE is_cracked = 0')
            return [dict(row) for row in cursor.fetchall()]

    def save_state(self, state: dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for k, v in state.items():
                cursor.execute('INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)', (k, str(v)))
            conn.commit()

    def load_state(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT key, value FROM state')
            return {row[0]: row[1] for row in cursor.fetchall()}
