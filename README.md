# MALWIZE MALWARE ANALYSIS PLATFORM

## 🚀 Complete Installation & User Manual

---

**Version:** 1.0  
**Date:** July 2025  
**Platform:** Linux/Unix Systems & Windows 11  
**Author:** Malwize Development Team  

---

## 📑 Table of Contents

1. [System Requirements](#system-requirements)
2. [Linux Installation](#linux-installation)
3. [Windows 11 Installation](#windows-11-installation)
4. [Python Environment Setup](#python-environment-setup)
5. [Dependencies Installation](#dependencies-installation)
6. [API Configuration](#api-configuration)
7. [Backend Installation](#backend-installation)
8. [Frontend Installation](#frontend-installation)
9. [Server Management](#server-management)
10. [Usage Examples](#usage-examples)
11. [Troubleshooting](#troubleshooting)
12. [Security Considerations](#security-considerations)
13. [Maintenance](#maintenance)
14. [Project Structure & Cleanup](#appendix-a-project-structure--cleanup)

---

## 1. 🖥️ System Requirements

### Minimum
- **OS:** Linux (Ubuntu 18.04+, CentOS 7+), Windows 11 (WSL2 or native Python)
- **Python:** 3.8+
- **RAM:** 4GB (8GB recommended)
- **Storage:** 10GB+

### Recommended
- **OS:** Ubuntu 20.04+ / Windows 11 (WSL2 Ubuntu)
- **Python:** 3.9+
- **RAM:** 16GB
- **Storage:** 50GB SSD

---

## 2. 🐧 Linux Installation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential python3-dev python3-pip python3-venv curl wget git unzip
sudo apt install -y libssl-dev libffi-dev zlib1g-dev libbz2-dev libxml2-dev libxslt-dev libsqlite3-dev
python3 --version
pip3 --version
```

---

## 3. 🪟 Windows 11 Installation

### Using WSL2 (Recommended)
```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
Restart-Computer
wsl --install
wsl --set-default-version 2
wsl --install -d Ubuntu
wsl
```
Then follow the Linux steps above inside Ubuntu.

### Native Windows
- Install [Python 3.9+](https://www.python.org/downloads/) (add to PATH)
- Install [Git for Windows](https://git-scm.com/download/win)
- Install Visual Studio Build Tools (C++ workload)
- (Optional) Install [Chocolatey](https://chocolatey.org/install)

---

## 4. 🐍 Python Environment Setup

### Linux/WSL2
```bash
mkdir -p ~/malwize && cd ~/malwize
git clone <your-repo-url> .
python3 -m venv venv
source venv/bin/activate
which python
which pip
```

### Windows
```cmd
mkdir C:\malwize && cd C:\malwize
git clone <your-repo-url> .
python -m venv venv
venv\Scripts\activate
where python
where pip
```

Upgrade pip and setuptools:
```bash
pip install --upgrade pip setuptools wheel
```

---

## 5. 📦 Dependencies Installation

```bash
pip install -r requirements.txt
# Or manually:
pip install fastapi uvicorn[standard] httpx aiohttp requests pandas numpy cryptography pycryptodome python-multipart structlog
```

---

## 6. 🔑 API Configuration

Create and edit `api_keys.txt`:
```bash
touch api_keys.txt
# Add your API keys in the following format:
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```
Set permissions:
```bash
chmod 600 api_keys.txt
```

---

## 7. 🛠️ Backend Installation

Verify structure:
```bash
ls -la
ls -la scanner_api.py
python -c "import scanner_api; print('Backend modules loaded successfully')"
```
Start backend:
```bash
uvicorn scanner_api:app --reload --host 0.0.0.0 --port 8000
```

---

## 8. 🌐 Frontend Installation

Verify files:
```bash
ls -la pages/
```
Start frontend:
```bash
python3 pages/robust_server.py
```
Access: [http://localhost:8080](http://localhost:8080)

---

## 9. 🖥️ Server Management

### Linux/WSL2
```bash
./start_servers.sh
./check_status.sh
./stop_servers.sh
```

### Windows
```cmd
start_servers.bat
check_status.bat
stop_servers.bat
```

---

## 10. 🧑‍💻 Usage Examples

```bash
curl -X POST "http://localhost:8000/upload/hashes_txt/" -F "file=@hashes.txt"
curl -X GET "http://localhost:8000/docs"
```

---

## 11. 🛠️ Troubleshooting

- **Port in use:**
  ```bash
  sudo lsof -i :8000
  sudo pkill -f uvicorn
  ```
- **Python issues:**
  ```bash
  pip install -r requirements.txt --force-reinstall
  ```
- **API key issues:**
  ```bash
  cat api_keys.txt
  ```
- **Virtual environment issues:**
  ```bash
  deactivate
  rm -rf venv
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```

---

## 12. 🔒 Security Considerations

- Never commit API keys to version control
- Use environment variables in production
- Rotate API keys regularly
- Use HTTPS in production
- Configure firewall rules
- Set file permissions:
  ```bash
  chmod 600 api_keys.txt
  chmod 755 *.sh
  chmod 644 *.py
  ```

---

## 13. 🛡️ Maintenance

- Regularly update system and dependencies:
  ```bash
  sudo apt update && sudo apt upgrade
  pip install -r requirements.txt --upgrade
  git pull origin main
  ```
- Log management:
  ```bash
  tail -f /var/log/syslog | grep malwize
  ```
- Backup:
  ```bash
  tar -czf malwize_backup_$(date +%Y%m%d).tar.gz api_keys.txt requirements.txt scanner_api.py selenium_qa_test.py pages/ test_artifacts/
  ```

---

## 📁 Project Structure

```
Api/
├── scanner_api.py              # Main FastAPI backend
├── api_keys.txt                # API configuration
├── requirements.txt            # Python dependencies
├── Malwize_Installation_Guide.docx  # This installation guide
├── selenium_qa_test.py         # QA testing script
├── start_servers.sh            # Server management (Linux/WSL2)
├── check_status.sh             # Status checking (Linux/WSL2)
├── pages/                      # Frontend application
│   ├── index.html
│   ├── upload.html
│   ├── hash_input.html
│   ├── spreadsheet.html
│   ├── results.html
│   ├── log.html
│   ├── dashboard.html
│   ├── style.css
│   ├── script.js
│   ├── robust_server.py
│   └── favicon.ico
└── test_artifacts/             # QA test results
    ├── qa_*.png
    └── manager_*.png
```

---

## 📦 Dependencies

**Core:**
```
fastapi, uvicorn[standard], httpx, aiohttp, requests, pandas, numpy, python-multipart, structlog, cryptography, pycryptodome, python-dotenv
```
**Dev:**
```
pytest, black, flake8, mypy
```

---

## 📚 More Info

- For API docs, visit: [http://localhost:8000/docs](http://localhost:8000/docs)
- For support, see the installation guide or contact the Malwize Development Team.

---

© 2025 Malwize Development Team. All rights reserved.