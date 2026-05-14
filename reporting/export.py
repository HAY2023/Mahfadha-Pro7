"""
Report Exporting (HTML/JSON) for CamHunter v2.0
"""

import json
import os
from datetime import datetime

class Exporter:
    def __init__(self, cfg: dict, db):
        self.cfg = cfg
        self.db = db
        self.output_dir = cfg["output"]["directory"]
        os.makedirs(self.output_dir, exist_ok=True)

    def export(self, fmt: str = "json", output_path: str = None) -> str:
        if fmt == "json":
            return self._export_json(output_path)
        elif fmt == "html":
            return self._export_html(output_path)
        return ""

    def _export_json(self, path: str = None) -> str:
        if not path:
            path = os.path.join(self.output_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        # Simple export of all data from DB
        import sqlite3
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cameras')
            data = [dict(row) for row in cursor.fetchall()]
            
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return path

    def _export_html(self, path: str = None) -> str:
        if not path:
            path = os.path.join(self.output_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        # Simplified HTML template
        html_template = """
        <html>
        <head>
            <title>CamHunter Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; }}
                table {{ width: 100%; border-collapse: collapse; background: white; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #333; color: white; }}
                .cracked {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>CamHunter Security Audit Report</h1>
            <p>Generated: {date}</p>
            <table>
                <tr>
                    <th>IP</th><th>Brand</th><th>Model</th><th>Status</th><th>Credentials</th>
                </tr>
                {rows}
            </table>
        </body>
        </html>
        """
        
        import sqlite3
        rows_html = ""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cameras')
            for row in cursor.fetchall():
                status = "CRACKED" if row["is_cracked"] else "Secure"
                creds = row["credentials"] if row["is_cracked"] else "—"
                rows_html += f"<tr><td>{row['ip']}</td><td>{row['brand']}</td><td>{row['model']}</td><td class='{status.lower()}'>{status}</td><td>{creds}</td></tr>"
        
        final_html = html_template.format(date=datetime.now().ctime(), rows=rows_html)
        with open(path, "w", encoding="utf-8") as f:
            f.write(final_html)
        return path
