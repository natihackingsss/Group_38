"""
🛡️ Windows Hygiene Auditor (Group 38)

Description:
    A Windows hygiene auditing tool with a graphical interface built using CustomTkinter.
    The tool performs system hygiene checks, detects local web servers, evaluates password 
    and account security, and generates detailed audit reports in HTML/PDF format.

Authors:
    Group 38 (Contributors: [add names here])

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
	# Set the apps apperance & theme
	ctk.set_appearance_mode("System") # We will use the systems default theme
	ctk.set_default_color_theme("blue") # We will use a blue color theme (We might change it in the future)

	# Creating widnow
	app = ctk.CTk() # Basically initializes Custom Tkinter
	app.title("Windows Hygiene Auditor - Group 38") # Sets the window title (might change it later)
	app.geometry("600x400") # Make the window 600 width by 400 height

	# Adding a temporary title
	title = ctk.CTkLabel(app, text="Welcome to Windows Hygiene Auditor!", font=("Arial", 16)) # Creates the title
	title.pack(pady=20) # Render the title

	# Make a dummy button (We will add functionality later)
	dummy_button = ctk.CTkButton(app, text="Run Audit", command=lambda: print("Audit Started!")) # Makes the dummy button
	dummy_button.pack(pady=10) # Rendering the button

	app.mainloop()

if __name__ == "__main__":
	App()
