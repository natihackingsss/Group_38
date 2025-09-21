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

import traceback
import threading
import customtkinter as ctk
from tkinter import messagebox

# Import our security checks
from windows_security_checks import WindowsSecurity


def App():
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")

    app = ctk.CTk()
    app.title("Windows Hygiene Auditor - Group 38")
    app.geometry("750x520")
    app.resizable(False, False)

    title = ctk.CTkLabel(app, text="🛡️ Windows Hygiene Auditor", font=("Arial", 28, "bold"))
    title.pack(pady=15)

    tabs = ctk.CTkTabview(app, width=700, height=420)
    tabs.pack(pady=10, padx=10, fill="both", expand=True)

    try:
        if hasattr(tabs, "_segmented_button"):
            tabs._segmented_button.configure(font=("Arial", 15, "bold"), height=40)
    except Exception:
        traceback.print_exc()

    tabs.add("System Hygiene")
    tabs.add("Web Servers")
    tabs.add("Password Security")
    tabs.add("Reports")

    # ===== System Hygiene Tab =====
    hygiene_frame = tabs.tab("System Hygiene")
    hygiene_label = ctk.CTkLabel(hygiene_frame, text="Check Firewall, Antivirus, Updates, and Disk Usage", font=("Arial", 16))
    hygiene_label.pack(pady=15)

    result_box = ctk.CTkTextbox(hygiene_frame, width=650, height=220)
    result_box.pack(pady=10)

    def run_hygiene_audit_thread():
        try:
            ws = WindowsSecurity()
            av = ws.Enabled_AV()
            updates = ws.Check_Updates()
            version, version_status = ws.Check_Windows_Version()
            startup = ws.Check_StartUp_Programs()
            firewall = ws.Check_Network_Firewall()
            disk = ws.Scan_Disk_Usage()

            result_text = (
                f"Antivirus: {av}\n\n"
                f"Updates: {updates}\n\n"
                f"Windows Version: {version} ({version_status})\n\n"
                f"Startup Programs: {startup}\n\n"
                f"Firewall: {firewall}\n\n"
                f"Disk Usage: {disk['Used_GB']:.2f} GB used / {disk['Total_GB']:.2f} GB total\n"
                f"Free Space: {disk['Free_GB']:.2f} GB\n"
                f"Disk Safety: {disk['Safety_Status']}"
            )

            def update_ui():
                result_box.delete("1.0", "end")
                result_box.insert("1.0", result_text)

            app.after(0, update_ui)

        except Exception as e:
            app.after(0, lambda: messagebox.showerror("Error", f"Failed to run hygiene audit:\n{e}"))

    def run_hygiene_audit():
        threading.Thread(target=run_hygiene_audit_thread, daemon=True).start()

    run_hygiene_btn = ctk.CTkButton(hygiene_frame, text="Run Hygiene Audit", command=run_hygiene_audit)
    run_hygiene_btn.pack(pady=10)

    # ===== Web Servers Tab =====
    web_frame = tabs.tab("Web Servers")
    web_label = ctk.CTkLabel(web_frame, text="Scan for Running Web Servers", font=("Arial", 16))
    web_label.pack(pady=15)

    web_btn = ctk.CTkButton(web_frame, text="Detect Web Servers", command=lambda: messagebox.showinfo("Web Servers", "Detection not yet implemented"))
    web_btn.pack(pady=10)

    # ===== Password Security Tab =====
    pass_frame = tabs.tab("Password Security")
    pass_label = ctk.CTkLabel(pass_frame, text="Evaluate Account Security", font=("Arial", 16))
    pass_label.pack(pady=15)

    pass_btn = ctk.CTkButton(pass_frame, text="Run Password Audit", command=lambda: messagebox.showinfo("Password Audit", "Audit not yet implemented"))
    pass_btn.pack(pady=10)

    # ===== Reports Tab =====
    reports_frame = tabs.tab("Reports")
    report_label = ctk.CTkLabel(reports_frame, text="Generate Audit Reports", font=("Arial", 16))
    report_label.pack(pady=15)

    html_btn = ctk.CTkButton(reports_frame, text="Export as HTML", command=lambda: messagebox.showinfo("Reports", "HTML export not yet implemented"))
    html_btn.pack(pady=5)

    pdf_btn = ctk.CTkButton(reports_frame, text="Export as PDF", command=lambda: messagebox.showinfo("Reports", "PDF export not yet implemented"))
    pdf_btn.pack(pady=5)

    app.mainloop()


if __name__ == "__main__":
    App()
