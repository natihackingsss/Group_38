"""
🛡️ Windows Hygiene Auditor (Group 38)

Description:
    A Windows hygiene auditing tool with a graphical interface built using CustomTkinter.
    The tool performs system hygiene checks, detects local web servers, evaluates password
    and account security, and generates detailed audit reports in HTML/PDF format.

Authors:
    Group 38 (Contributors: [We will add name later])

Version:
    1.0.0

Usage:
    Run the main entry point to launch the GUI:
        python src/main.py
"""

# ===== Imports =====
import customtkinter as ctk

# ===== Basic window =====
def App():
    # Set the app's appearance & theme
    ctk.set_appearance_mode("System")  # Use system default (Light/Dark)
    ctk.set_default_color_theme("blue")  # Blue theme

    # Create main window
    app = ctk.CTk()
    app.title("Windows Hygiene Auditor - Group 38")
    app.geometry("750x520")
    app.resizable(False,False)

    # Title
    title = ctk.CTkLabel(app, text="🛡️ Windows Hygiene Auditor", font=("Arial", 28, "bold"))
    title.pack(pady=15)

    # Create tabs (larger size, bigger font)
    tabs = ctk.CTkTabview(app, width=700, height=420)
    tabs.pack(pady=10, padx=10, fill="both", expand=True)

    # Make tab button font bigger
    tabs._segmented_button.configure(font=("Arial", 15, "bold"), height=40)

    # Add tab sections
    tabs.add("System Hygiene")
    tabs.add("Web Servers")
    tabs.add("Password Security")
    tabs.add("Reports")

    # ===== System Hygiene Tab =====
    hygiene_label = ctk.CTkLabel(tabs.tab("System Hygiene"), text="Check Firewall, Antivirus, and Updates", font=("Arial", 16))
    hygiene_label.pack(pady=15)

    run_hygiene_btn = ctk.CTkButton(tabs.tab("System Hygiene"), text="Run Hygiene Audit", command=lambda: print("System Hygiene Audit Started"))
    run_hygiene_btn.pack(pady=10)

    # ===== Web Servers Tab =====
    web_label = ctk.CTkLabel(tabs.tab("Web Servers"), text="Scan for Running Web Servers", font=("Arial", 16))
    web_label.pack(pady=15)

    web_btn = ctk.CTkButton(tabs.tab("Web Servers"), text="Detect Web Servers", command=lambda: print("Web Server Detection Started"))
    web_btn.pack(pady=10)

    # ===== Password Security Tab =====
    pass_label = ctk.CTkLabel(tabs.tab("Password Security"), text="Evaluate Account Security", font=("Arial", 16))
    pass_label.pack(pady=15)

    pass_btn = ctk.CTkButton(tabs.tab("Password Security"), text="Run Password Audit", command=lambda: print("Password Audit Started"))
    pass_btn.pack(pady=10)

    # ===== Reports Tab =====
    report_label = ctk.CTkLabel(tabs.tab("Reports"), text="Generate Audit Reports", font=("Arial", 16))
    report_label.pack(pady=15)

    html_btn = ctk.CTkButton(tabs.tab("Reports"), text="Export as HTML", command=lambda: print("HTML Report Generated"))
    html_btn.pack(pady=5)

    pdf_btn = ctk.CTkButton(tabs.tab("Reports"), text="Export as PDF", command=lambda: print("PDF Report Generated"))
    pdf_btn.pack(pady=5)

    app.mainloop()

if __name__ == "__main__":
    App()
