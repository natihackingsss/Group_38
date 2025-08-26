"""

Handles windows security scanner

"""

import wmi # We can use this to query system info
import subprocess

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
