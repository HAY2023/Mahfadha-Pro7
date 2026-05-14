# Mahfadha-Pro7 🛡️
## CamHunter Security Auditor v2.0

Mahfadha-Pro7 (CamHunter) is a powerful, professional-grade security auditing tool designed to scan, fingerprint, and audit IP camera security on local networks. It features a modern web-based GUI for easy management and discovery.

---

### 🌟 HAY-AI PRO Integration
This tool is part of the HAY-AI PRO ecosystem, designed for legendary security performance and ease of use.

### 🚀 Features
- **Network Discovery**: Automatically scan local networks for IP camera devices.
- **Fingerprinting**: Identify camera brands (Hikvision, Dahua, Reolink, etc.) and models.
- **Security Audit**: Check for common vulnerabilities, default credentials, and CVEs.
- **Modern Web UI**: Glassmorphism-inspired interface for monitoring and control.
- **Reporting**: Export findings to JSON/CSV for further analysis.

### 🛠️ Installation & Setup

#### Local Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/HAY2023/Mahfadha-Pro7.git
   cd Mahfadha-Pro7
   ```

2. **Install Dependencies**:
   Ensure you have Python 3.8+ and `nmap` installed on your system.
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   python web_app.py
   ```
   Open your browser at `http://127.0.0.1:5000`.

#### Docker Deployment (Ready-to-use)
You can run this application anywhere using Docker:
```bash
docker build -t mahfadha-pro7 .
docker run -p 5000:5000 mahfadha-pro7
```

---

### 📂 Project Structure
- `web_app.py`: Main Flask entry point.
- `scanner/`: Core scanning logic (Network, ONVIF, RTSP, SNMP).
- `auth/`: Brute-force and credential management.
- `reporting/`: Database and export utilities.
- `templates/`: Frontend HTML/CSS/JS.

---

### ⚖️ Disclaimer
This tool is for educational and authorized security auditing purposes only. Unauthorized access to computer systems is illegal.

---

### 👨‍💻 Author
Developed by **HAY2023** 🚀
