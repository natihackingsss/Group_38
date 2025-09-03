"""
Owner : yumna-ux
Module: Web Vulnerability Scanner

Description:
This module is responsible for analyzing open ports discovered during the 
port scanning phase. Its main objectives are:

  1. Detecting active web servers (HTTP/HTTPS) on the target system.
  2. Identifying and flagging ports commonly associated with malicious activity.

The results from this module provide valuable insights into potential 
security risks related to exposed services.
"""

import requests

class WebVulnerabilityScan:
    def __init__(self, Target: str):
        """
        Initialize the web vulnerability scanner.

        Args:
            Target (str): The target system's IP address or domain name.
        """
        self.URL = Target
        self.web_ports = [80, 443]  # Standard web server ports
        self.malicious_ports = [6666, 12345, 31337]  # Example of commonly misused ports

    def PortScanner(self, open_ports: list):
        """
        Analyze open ports obtained from the port scanning phase.

        Args:
            open_ports (list): A list of open port numbers on the target system.

        Returns:
            tuple:
                - web_servers (list): Tuples of (port, url) where web servers are detected.
                - suspicious_ports (list): Ports flagged as potentially malicious.
        """
        web_servers = []
        suspicious_ports = []

        for port in open_ports:
            # --- Web server detection ---
            if port in self.web_ports:
                # Use http:// for port 80, https:// for 443
                url = f"http://{self.URL}:{port}" if port != 443 else f"https://{self.URL}"
                try:
                    response = requests.get(url, timeout=3)
                    if response.status_code < 400:
                        web_servers.append((port, url))
                except requests.RequestException:
                    # Port open but no valid HTTP/HTTPS response
                    pass

            # --- Malicious port detection ---
            if port in self.malicious_ports:
                suspicious_ports.append(port)

        return web_servers, suspicious_ports


# Example standalone run (for demonstration purposes)
if __name__ == "__main__":
    # ⚡ In real use: 'open_ports' should come from the port scanning component
    open_ports = [22, 80, 443, 6666]

    scanner = WebVulnerabilityScan("127.0.0.1")
    web_servers, suspicious_ports = scanner.PortScanner(open_ports)

    print("\n=== Web Vulnerability Scan Results ===")
    if web_servers:
        print("Detected Web Servers:")
        for port, url in web_servers:
            print(f" - Port {port}: {url}")
    else:
        print("No active web servers detected.")

    if suspicious_ports:
        print("\nSuspicious/Malicious Ports Detected:")
        for port in suspicious_ports:
            print(f" - Port {port}")
    else:
        print("\nNo malicious ports detected.")

        
