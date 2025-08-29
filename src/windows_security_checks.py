"""

Handles windows security scanner

"""

import wmi # We can use this to query system info
import subprocess
import sys
import json

class WindowsSecurity:
    def Enabled_AV(self):
        results = []
        try:
            cmd = [
                "powershell",
                "-Command",
                "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"
            ]
            win_def_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            defender_enabled = win_def_result.stdout.strip() == "True"
            results.append({
                "name": "Windows Defender",
                "enabled": defender_enabled
            })
        except Exception:
            results.append({
                "name": "Windows Defender",
                "enabled": None  # Failed to check
            })

        try:
            wmi_obj = wmi.WMI(namespace="root\\SecurityCenter2")
            av_products = wmi_obj.AntiVirusProduct()

            for av in av_products:
                if av.displayName.lower() == "windows defender":
                    # Skip Defender since we already checked it
                    continue
                state = av.productState
                enabled = (state >> 16) & 0x10  # Might not be 100% accurate
                results.append({
                    "name": av.displayName,
                    "enabled": bool(enabled)
                })
        except Exception:
            pass  # If WMI fails, just ignore other AVs

        return {"antivirus": results}
        

    def Check_Updates(self):
        try:
            # We can use powershell to do this too
            cmd = [
                "powershell",
                "-Command",
                "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates | Select-Object -ExpandProperty Title"
            ]
            version_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            updates = [line.strip() for line in version_result.stdout.splitlines() if line.strip()]
            return {"Pending updates" : updates}
        except Exception:
            return {"Pending updates" : None} # Failed to check

    def Check_Windows_Version(self):
        win_version = sys.getwindowsversion()
        win_major, win_minor = win_version.major, win_version.minor

        if win_major < 10:
            # If the windows version is less than 10 it is automatically vulnerable
            # This is because of the EternalBlue (MS17-010) vulnerablity found in windows version XP, 7, 8, 8.1
            return f"{win_major}.{win_minor}", "Vulnerable"
        else:
            return f"{win_major}.{win_minor}", "Safe"
    
    def Check_StartUp_Programs(self):
        # We can use powershell to check this as well
        result = {}
        cmd = [
            "powershell",
            "-Command",
            "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command | ConvertTo-Json"
        ]
        startup_result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            programs = json.loads(startup_result.stdout)
        except json.JSONDecodeError:
            return {"error" : "Unable to parse powershell output."}

        # These are directorys/programs that are trusted by the program
        safe = [
            "Windows", "Program Files", "Program Files (x86)", "Microsoft", "system32", "ProgramData"
        ]

        if isinstance(programs, dict):
            programs = [programs] # Converts the dictionary to a list

        for prog in programs:
            name = prog.get("Name", "").strip()
            paths = prog.get("Command", "").strip()

            is_safe = any(safe_prog in paths for safe_prog in safe) # Returns true if safe is in the path
            result[name] = "Safe" if is_safe else "Suspicious"

        return result
