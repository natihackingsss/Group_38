# 🛡️ Windows Hygiene Auditor (Group 38)

A **Windows hygiene auditing tool** built by **Group 38**.  
The tool provides system administrators and security-conscious users with an easy way to **audit Windows systems** for common misconfigurations, weak security practices, and outdated components.  

This tool helps system administrators, cybersecurity students, and IT professionals quickly assess the security posture of Windows systems and generate professional audit reports.

---

📜 Table of Contents
- [✨ Overview](#-overview)
- [🚀 Features](#-features)
- [📊 Reporting](#-reporting)
- [🖥️ Tech Stack](#-tech-stack)
- [📁 Project Structure](#-project-structure)
- [⚙️ Installation](#-installation)
- [🖥️ Usage](#-usage)
- [🔮 Roadmap](#-roadmap)



### ✨️Overview

The Windows Hygiene Auditor is a Python-based auditing tool that scans Windows systems for common security weaknesses and system hygiene issues.
It provides a graphical interface, real-time scanning, and detailed reports to help users:

 - Identify weak security settings before attackers do.

 - Comply with security policies and standards.

 - Maintain a secure and well-configured Windows environment.

Whether you're a student, sysadmin, or security enthusiast — this tool makes Windows auditing simple, powerful, and professional.


### 🚀 Features
- ✅ **System Hygiene Checks**  
  - Firewall status  
  - Antivirus presence & status  
  - Windows updates status  
  - Outdated system checks  

- 🌐 **Web Server Detection**  
  - Identify if local web servers (IIS, Apache, Nginx, etc.) are running  
  - Highlight potential risks of unauthorized services  

- 🔑 **Password & Account Security**  
  - Basic password strength checks  
  - Detection of accounts with weak or default passwords  
  - Check for inactive/disabled accounts  

### 📊 **Reporting**  
  - Export audit results in **HTML** or **PDF** format  
  - Clean, easy-to-read structure with summary and detailed findings  

---

### 🖥️ Tech Stack
- **Python 3**  
- **CustomTkinter** (for GUI)  
- **ReportLab / WeasyPrint** (for PDF reports)  
- **HTML templates** (for report generation)  

---

### 📂 Project Structure (simplified)
```
src/ # Source code (GUI, checks, reporting)
assets/ # Icons, images, styles
requirements.txt
README.md
```

### 🛠️ Prerequisites
- Windows OS (Tested on Windows 10/11)
- Python 3.8 or higher
- PowerShell enabled
- Internet connection (for password breach check feature)

### ⚡ Installation
```bash
git clone https://github.com/natihackingsss/Group_38
cd Group_38
pip install -r requirements.txt
python src/main.py
```
### 📑 Usage
  - Launch the application.
  - Select which hygiene checks to perform.
  - Run the scan and view results in the GUI.
  - Export results as HTML or PDF.

### 🔮 Roadmap
🚧 Planned for future versions:

- [ ] Auto-fix common issues (e.g., enable firewall, disable Guest account)

- [ ] Email report feature for admins

- [ ] Remote machine scanning (via WinRM/SSH)

- [ ] Web dashboard (Flask/FastAPI) for central monitoring

- [ ] AI-powered recommendations based on scan results
