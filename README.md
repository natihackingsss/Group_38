# 🛡️ Windows Hygiene Auditor (Group 38)

A **Windows hygiene auditing tool** built by **Group 38**.  
The tool provides system administrators and security-conscious users with an easy way to **audit Windows systems** for common misconfigurations, weak security practices, and outdated components.  

It comes with a **graphical interface (CustomTkinter)** and can generate **detailed reports (HTML/PDF)** for record-keeping or compliance checks.  

---

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

- 📊 **Reporting**  
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
