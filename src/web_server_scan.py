"""
Owner : yumna-ux
Module: Web Vulnerability Analyzer

Description:
This module is responsible for analyzing open ports discovered during the 
port scanning phase. Its main objectives are:

  1. Detecting active web servers (HTTP/HTTPS) on the target system.
  2. Identifying and flagging ports commonly associated with malicious activity.

The results from this module provide valuable insights into potential 
security risks related to exposed services.
"""

import requests
import socket
import json
import datetime
from typing import List, Tuple, Dict, Optional

class WebVulnerabilityAnalyzer:
    def __init__(self, Target: str, safe_and_common_ports: Optional[List[int]] = None):
        """
        Initialize the web vulnerability analyzer.

        Args:
            target (str): IP or hostname of the scanned host.
            safe_and_common_ports (list, optional): custom list of common/safe ports.
        """
        self.target = Target
        self.safe_and_common_ports = safe_and_common_ports or [
            20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139,
            143, 389, 443, 445, 465, 587, 593, 636, 993, 995, 1433, 3306, 5432,
            27017, 3389, 5985, 5986, 3268, 3269, 5357
        ]
        self.common_web_ports = [80, 443, 8080, 8000, 8443] 
        self.known_malicious_ports = {4444, 6666, 31337, 12345, 2323}


    def _tcp_banner(self, port: int, timeout: float = 1.0) -> Optional[str]:
        try:
         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((self.target, port))
                try:
                    data = s.recv(1024)
                    if data:
                        return data.decode(errors="ignore").strip()
                except socket.timeout:
                    return None
        except Exception:
            return None
        return None

    def _http_probe(self, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[requests.Response]]:
        schemes = ["http"]
        if port in (443, 8443):
            schemes.insert(0, "https")
        for scheme in schemes:
            url = f"{scheme}://{self.target}"
            if not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
                url = f"{scheme}://{self.target}:{port}"
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
                if resp.status_code < 400:
                    return True, resp
            except requests.RequestException:
                continue
        return False, None
      
    def _fingerprint_service(self, port: int, http_response: Optional[requests.Response], banner: Optional[str]) -> str:
        if http_response:
            server_hdr = http_response.headers.get("Server")
            if server_hdr:
                return server_hdr.split(" ")[0]
            body = (http_response.text or "").lower()
            if "<title>apache" in body or "powered by apache" in body:
                return "Apache"
            if "nginx" in body:
                return "nginx"
            if "iis" in body or "microsoft-iis" in body:
                return "Microsoft-IIS"
        if banner:
            low = banner.lower()
            if "ssh" in low:
                return "ssh"
            if "smtp" in low:
                return "smtp"
            if "ftp" in low:
                return "ftp"
            if "mysql" in low:
                return "mysql"
            if "postgres" in low or "postgresql" in low:
                return "postgresql"
            return banner.strip().splitlines()[0][:120]
        return "unknown"

    def _classify_risk(self, port: int, fingerprint: str, is_web: bool) -> str:
        if port in self.known_malicious_ports:
            return "High"
        if is_web and port not in (80, 443):
            if fingerprint == "unknown":
                return "High"
            return "Medium"
        if port not in self.safe_and_common_ports:
            if fingerprint and any(t in fingerprint.lower() for t in ("meterpreter", "reverse", "bind", "nc", "ncat", "bash")):
                return "High"
            return "Medium"
        return "Low"
      
    def analyze_ports(self, open_ports: List[int]) -> Dict:
        results = {
            "target": self.target,
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {"total_open": len(open_ports), "web_servers": 0, "high_risk": 0},
            "ports": []
        }
        for port in sorted(set(open_ports)):
            port_entry = {
                "port": port,
                "is_web": False,
                "http_url": None,
                "http_status": None,
                "banner": None,
                "fingerprint": None,
                "risk": None
            }
            is_web = False
            http_url = None
            http_status = None
            http_resp = None
            if port in self.common_web_ports or port in (80, 443):
                is_web, http_resp = self._http_probe(port)
                if is_web and http_resp:
                    http_url = http_resp.url
                    http_status = http_resp.status_code
            banner = self._tcp_banner(port)
            fingerprint = self._fingerprint_service(port, http_resp, banner)
            risk = self._classify_risk(port, fingerprint, is_web)
            port_entry.update({
                "is_web": bool(is_web),
                "http_url": http_url,
                "http_status": http_status,
                "banner": banner,
                "fingerprint": fingerprint,
                "risk": risk
            })
            if is_web:
                results["summary"]["web_servers"] += 1
            if risk == "High":
                results["summary"]["high_risk"] += 1
            results["ports"].append(port_entry)
        return results
   
    def generate_json_report(self, analysis_result: Dict) -> str:
        return json.dumps(analysis_result, indent=2, sort_keys=False)

if __name__ == "__main__":
    analyzer = WebVulnerabilityAnalyzer("127.0.0.1")
    open_ports = [22, 80, 443, 6666] 
    analysis = analyzer.analyze_ports(open_ports)
    print("=== JSON Report ===")
    print(analyzer.generate_json_report(analysis))
