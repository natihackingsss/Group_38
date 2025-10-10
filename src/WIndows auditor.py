"""
Windows Hygiene Auditor
Single-file prototype (Python)

Usage:
- Run on Windows (tested on Windows 10+)
- `python windows_hygiene_auditor.py`

Dependencies (recommended):
- Python 3.8+
- psutil (pip install psutil)
- wmi (pip install WMI)
- weasyprint (optional, for PDF export) or use wkhtmltopdf as fallback

This file contains:
- Scanner: performs a set of checks (firewall, AV, updates, web servers, accounts)
- Reporter: exports results to HTML and (optionally) PDF
- GUI (Tkinter): simple interface to run scan and view/export results

This is a prototype and intentionally conservative about destructive operations.
Customize checks and add detection heuristics as needed for production.

"""

import sys
import os
import platform
import subprocess
import json
import tempfile
import datetime
from threading import Thread
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

# Optional/third-party imports
try:
    import psutil
except Exception:
    psutil = None

try:
    import wmi
except Exception:
    wmi = None

# GUI (Tkinter is in stdlib)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception:
    tk = None


# ----------------------------
# Data structures
# ----------------------------

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # 'Low','Medium','High','Info'
    description: str
    recommendation: str
    technical: Dict[str, Any] = None


class ScanResult:
    def __init__(self):
        self.timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
        self.host = platform.node()
        self.os = platform.platform()
        self.findings: List[Finding] = []

    def add(self, finding: Finding):
        self.findings.append(finding)

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'host': self.host,
            'os': self.os,
            'findings': [asdict(f) for f in self.findings]
        }


# ----------------------------
# Scanner: collection of checks
# ----------------------------

class Scanner:
    def __init__(self):
        # Initialize WMI, etc. if available
        self.c_wmi = None
        if wmi is not None:
            try:
                self.c_wmi = wmi.WMI()
            except Exception:
                self.c_wmi = None

    def run_full_scan(self) -> ScanResult:
        result = ScanResult()
        # Each check returns None or Finding(s)
        checks = [
            self.check_firewall,
            self.check_antivirus,
            self.check_windows_update,
            self.check_outdated_system_components,
            self.detect_local_web_servers,
            self.check_accounts_basic,
            self.check_default_ports_open,
        ]

        for check in checks:
            try:
                out = check()
                if out is None:
                    continue
                if isinstance(out, list):
                    for f in out:
                        result.add(f)
                else:
                    result.add(out)
            except Exception as e:
                result.add(Finding(
                    id=f'error-{check.__name__}',
                    title=f'Error running {check.__name__}',
                    severity='Info',
                    description=f'Check raised an exception: {e}',
                    recommendation='Review logs and try running this check manually.',
                    technical={'exception': str(e)}
                ))
        return result

    # ------------------ Checks ------------------
    def check_firewall(self):
        """Check Windows Firewall status via netsh. Returns a Finding."""
        if platform.system() != 'Windows':
            return Finding(
                id='fw-not-windows',
                title='Firewall check skipped (non-Windows)',
                severity='Info',
                description='Firewall check only implemented for Windows in this prototype.',
                recommendation='Run on a Windows host to evaluate firewall status.'
            )

        try:
            # Query netsh advfirewall for profile states
            proc = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True, check=False)
            output = proc.stdout + proc.stderr
            # Simple heuristics: look for "State ON" or "State OFF"
            if 'State ON' in output or 'ON' in output:
                # Might still be off for some profiles; inspect more carefully
                if 'State OFF' in output:
                    desc = 'Windows Firewall is enabled for some profiles but disabled for others.'
                    sev = 'Medium'
                else:
                    desc = 'Windows Firewall appears to be enabled.'
                    sev = 'Low'
            else:
                desc = 'Windows Firewall appears to be disabled.'
                sev = 'High'

            return Finding(
                id='firewall-01',
                title='Windows Firewall status',
                severity=sev,
                description=desc,
                recommendation='Enable Windows Firewall for all profiles and review allowed rules.',
                technical={'raw_output': output[:2000]}
            )
        except Exception as e:
            return Finding(
                id='firewall-error',
                title='Firewall check error',
                severity='Info',
                description=f'Failed to query firewall: {e}',
                recommendation='Run netsh advfirewall show allprofiles manually to investigate.',
                technical={'exception': str(e)}
            )

    def check_antivirus(self):
        """Attempt to detect installed antivirus via WMI SecurityCenter2 if available."""
        if platform.system() != 'Windows':
            return Finding(
                id='av-not-windows',
                title='Antivirus check skipped (non-Windows)',
                severity='Info',
                description='Antivirus check implemented for Windows only in this prototype.',
                recommendation='Run on Windows to evaluate antivirus presence.'
            )

        try:
            av_products = []
            # WMI SecurityCenter2 class only available on Windows 8+/Server2012+ in certain contexts
            if self.c_wmi is not None:
                try:
                    for av in self.c_wmi.query('SELECT * FROM AntiVirusProduct'):
                        av_products.append({'displayName': getattr(av, 'displayName', str(av)), 'productState': getattr(av, 'productState', None)})
                except Exception:
                    # Many systems restrict this WMI namespace; fallback heuristics
                    av_products = []

            # Fallback: look for common AV processes
            common_procs = ['MsMpEng.exe', 'NortonSecurity.exe', 'avp.exe', 'Mcshield.exe', 'avgui.exe']
            running = []
            if psutil is not None:
                for p in psutil.process_iter(attrs=['name']):
                    name = p.info.get('name')
                    if name in common_procs:
                        running.append(name)

            if av_products or running:
                desc = f'Detected antivirus products: WMI={av_products} processes={running}'
                sev = 'Low'
            else:
                desc = 'No antivirus product detected by heuristics. This may be a false positive on corporate-managed systems.'
                sev = 'High'

            return Finding(
                id='antivirus-01',
                title='Antivirus presence & status',
                severity=sev,
                description=desc,
                recommendation='Install a supported antivirus or verify endpoint protection status with your admin.',
                technical={'wmi': av_products, 'processes': running}
            )
        except Exception as e:
            return Finding(
                id='antivirus-error',
                title='Antivirus check error',
                severity='Info',
                description=f'Failed to detect antivirus: {e}',
                recommendation='Inspect system for endpoint protection solutions manually.',
                technical={'exception': str(e)}
            )

    def check_windows_update(self):
        """Check Windows Update service state via sc query/wmic or WMI. Prototype-level."""
        if platform.system() != 'Windows':
            return Finding(
                id='wu-not-windows',
                title='Windows Update check skipped (non-Windows)',
                severity='Info',
                description='Windows Update check implemented for Windows only in this prototype.',
                recommendation='Run on Windows to evaluate update configuration.'
            )

        try:
            # Query service state using sc
            proc = subprocess.run(['sc', 'query', 'wuauserv'], capture_output=True, text=True, check=False)
            out = proc.stdout + proc.stderr
            if 'RUNNING' in out:
                desc = 'Windows Update service (wuauserv) is running.'
                sev = 'Low'
            elif 'STOPPED' in out:
                desc = 'Windows Update service (wuauserv) is stopped.'
                sev = 'Medium'
            else:
                desc = 'Unable to determine Windows Update service state.'
                sev = 'Info'

            return Finding(
                id='windows-update-01',
                title='Windows Update service status',
                severity=sev,
                description=desc,
                recommendation='Ensure Windows Update service is running and managed by your update policy.',
                technical={'raw_output': out[:2000]}
            )
        except Exception as e:
            return Finding(
                id='windows-update-error',
                title='Windows Update check error',
                severity='Info',
                description=f'Failed to query Windows Update service: {e}',
                recommendation='Check Windows Update settings and services manually.',
                technical={'exception': str(e)}
            )

    def check_outdated_system_components(self):
        """Simple placeholder: flag if OS build is older than a rough threshold (not authoritative)."""
        try:
            ver = platform.version()
            release = platform.release()
            # Conservative heuristic: if release is 7 or 8, mark outdated
            if release in ('7', '8', '8.1'):
                desc = f'Operating system appears old ({release} / {ver}).'
                sev = 'High'
            else:
                desc = f'Operating system: {release} ({ver}). No obvious obsolescence detected by simple heuristic.'
                sev = 'Low'

            return Finding(
                id='outdated-01',
                title='Outdated system check (heuristic)',
                severity=sev,
                description=desc,
                recommendation='If running an older Windows version, plan upgrades and ensure security updates are applied.'
            )
        except Exception as e:
            return Finding(
                id='outdated-error',
                title='Outdated check error',
                severity='Info',
                description=f'Failed to inspect OS version: {e}',
                recommendation='Check OS version manually.',
                technical={'exception': str(e)}
            )

    def detect_local_web_servers(self):
        """Detect common web servers by listening processes and open ports (80,443,8080...)."""
        findings = []
        interesting_ports = [80, 443, 8080, 8000, 8888]

        try:
            listeners = []
            if psutil is not None:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.laddr and conn.status == psutil.CONN_LISTEN:
                        port = conn.laddr.port
                        if port in interesting_ports:
                            try:
                                proc = psutil.Process(conn.pid) if conn.pid else None
                                pname = proc.name() if proc else 'unknown'
                            except Exception:
                                pname = 'unknown'
                            listeners.append({'port': port, 'process': pname, 'pid': conn.pid})

            if listeners:
                for l in listeners:
                    findings.append(Finding(
                        id=f'web-{l["port"]}',
                        title=f'Local web server detected on port {l["port"]}',
                        severity='Medium',
                        description=f'Process {l["process"]} (pid {l["pid"]}) is listening on port {l["port"]}.',
                        recommendation='Verify whether this service should be running and restrict access if unnecessary.',
                        technical=l
                    ))
            else:
                findings.append(Finding(
                    id='web-none',
                    title='No local web servers detected (simple scan)',
                    severity='Low',
                    description='No processes were found listening on common HTTP(S) ports during the scan.',
                    recommendation='If you are expecting local web services, run a deeper port/service scan.'
                ))

            return findings
        except Exception as e:
            return Finding(
                id='web-detect-error',
                title='Web server detection error',
                severity='Info',
                description=f'Failed to detect web servers: {e}',
                recommendation='Run netstat -abn or equivalent to inspect listening services.',
                technical={'exception': str(e)}
            )

    def check_accounts_basic(self):
        """Basic detection for disabled/inactive accounts. Very simplified.
        On Windows this should ideally use Win32 API or net user parsing.
        """
        findings = []
        if platform.system() != 'Windows':
            return Finding(
                id='acct-nonwin',
                title='Account checks skipped (non-Windows)',
                severity='Info',
                description='Account checks implemented for Windows only in this prototype.',
                recommendation='Run on a Windows host for account enumeration checks.'
            )

        try:
            # Use `net user` parsing as a simple cross-edition approach
            proc = subprocess.run(['net', 'user'], capture_output=True, text=True, check=False)
            out = proc.stdout + proc.stderr
            # Parse usernames from `net user` output - crude approach
            lines = out.splitlines()
            users = []
            for line in lines:
                # net user output lists user names in columns after some header lines
                if line.strip() and not line.strip().startswith('User accounts') and '---' not in line:
                    parts = line.split()
                    for p in parts:
                        # Ignore column headers like 'The command completed successfully.'
                        if p and p.lower() not in ('the', 'command', 'completed', 'successfully.'):
                            users.append(p.strip())
            # Deduplicate
            users = sorted(list(set(users)))

            # For prototype, flag built-in admin and guest presence (common weak default accounts)
            for u in users:
                if u.lower() in ('guest',):
                    findings.append(Finding(
                        id=f'account-{u}',
                        title=f'Default account present: {u}',
                        severity='Medium',
                        description=f'Account {u} exists and may be enabled by default on some systems.',
                        recommendation='Disable or rename guest/default accounts if not required and enforce strong passwords.'
                    ))

            if not findings:
                findings.append(Finding(
                    id='accounts-ok',
                    title='Basic account checks — no obvious defaults detected',
                    severity='Low',
                    description=f'Enumerated {len(users)} users; no immediate default account issues flagged by this heuristic.',
                    recommendation='Perform a deeper review of accounts and password policies.'
                ))

            return findings
        except Exception as e:
            return Finding(
                id='accounts-error',
                title='Account check error',
                severity='Info',
                description=f'Failed to enumerate accounts: {e}',
                recommendation='Run `net user` or use PowerShell Get-LocalUser to inspect accounts manually.',
                technical={'exception': str(e)}
            )

    def check_default_ports_open(self):
        """Check for common exposed services via listening ports. Overlaps with detect_local_web_servers."""
        try:
            open_ports = []
            if psutil is not None:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == psutil.CONN_LISTEN and conn.laddr:
                        open_ports.append(conn.laddr.port)
            open_ports = sorted(list(set(open_ports)))[:50]
            if open_ports:
                return Finding(
                    id='open-ports-01',
                    title='Open/listening ports detected',
                    severity='Medium',
                    description=f'Listening ports: {open_ports}',
                    recommendation='Restrict services to localhost where possible and firewall-filter listening ports.',
                    technical={'ports': open_ports}
                )
            else:
                return Finding(
                    id='open-ports-none',
                    title='No listening TCP/UDP ports detected (simple scan)',
                    severity='Low',
                    description='No listening ports detected by psutil during the scan.',
                    recommendation='Run a network scan (nmap) externally for a thorough assessment.'
                )
        except Exception as e:
            return Finding(
                id='open-ports-error',
                title='Open ports check error',
                severity='Info',
                description=f'Failed to inspect network connections: {e}',
                recommendation='Run netstat -abn or use psutil/netstat tools to inspect network listeners.',
                technical={'exception': str(e)}
            )


# ----------------------------
# Reporter: HTML & PDF
# ----------------------------

class Reporter:
    HTML_TEMPLATE = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Windows Hygiene Auditor Report - {host}</title>
        <style>
          body {{ font-family: Arial, sans-serif; padding: 20px; }}
          h1 {{ border-bottom: 1px solid #ddd; }}
          .finding {{ margin-bottom: 16px; padding: 12px; border-radius: 6px; box-shadow: 0 0 0 1px #eee inset; }}
          .sev-High {{ border-left: 6px solid #e53e3e; }}
          .sev-Medium {{ border-left: 6px solid #dd6b20; }}
          .sev-Low {{ border-left: 6px solid #38a169; }}
          .sev-Info {{ border-left: 6px solid #3182ce; }}
          pre { background:#f8f8f8; padding:8px; overflow:auto; }
        </style>
      </head>
      <body>
        <h1>Windows Hygiene Auditor Report - {host}</h1>
        <p><strong>Host:</strong> {host} &nbsp;|&nbsp; <strong>OS:</strong> {os} &nbsp;|&nbsp; <strong>Generated:</strong> {time}</p>
        <h2>Summary</h2>
        <p>Total findings: {count}</p>
        <h2>Findings</h2>
        {findings_html}
      </body>
    </html>
    """

    def __init__(self, scan_result: ScanResult):
        self.result = scan_result

    def _render_findings(self) -> str:
        parts = []
        for f in self.result.findings:
            tech = ''
            if f.technical:
                try:
                    tech = f"<pre>{json.dumps(f.technical, indent=2)}</pre>"
                except Exception:
                    tech = f"<pre>{str(f.technical)}</pre>"
            parts.append(f"""
            <div class="finding sev-{f.severity}">
              <h3>{f.title} <small>({f.severity})</small></h3>
              <p>{f.description}</p>
              <p><strong>Recommendation:</strong> {f.recommendation}</p>
              {tech}
            </div>
            """)
        return '\n'.join(parts)

    def to_html(self) -> str:
        html = self.HTML_TEMPLATE.format(
            host=self.result.host,
            os=self.result.os,
            time=self.result.timestamp,
            count=len(self.result.findings),
            findings_html=self._render_findings()
        )
        return html

    def save_html(self, path: str):
        html = self.to_html()
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

    def save_pdf(self, path: str):
        html = self.to_html()
        # Try weasyprint if installed
        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(path)
            return True
        except Exception as e:
            # Fallback: write HTML and suggest external conversion
            tmp = path + '.html'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(html)
            raise RuntimeError(f'PDF export failed (weasyprint missing or error). Generated HTML at {tmp}. Original error: {e}')


# ----------------------------
# GUI
# ----------------------------

class AuditorGUI:
    def __init__(self, master):
        self.master = master
        master.title('Windows Hygiene Auditor')
        master.geometry('900x600')

        # Controls frame
        ctrl = tk.Frame(master)
        ctrl.pack(fill=tk.X, padx=8, pady=8)

        self.scan_btn = tk.Button(ctrl, text='Run Full Scan', command=self._on_run_scan)
        self.scan_btn.pack(side=tk.LEFT)

        self.export_html_btn = tk.Button(ctrl, text='Export HTML', command=self._on_export_html, state=tk.DISABLED)
        self.export_html_btn.pack(side=tk.LEFT, padx=6)

        self.export_pdf_btn = tk.Button(ctrl, text='Export PDF', command=self._on_export_pdf, state=tk.DISABLED)
        self.export_pdf_btn.pack(side=tk.LEFT)

        self.status_lbl = tk.Label(ctrl, text='Idle')
        self.status_lbl.pack(side=tk.RIGHT)

        # Treeview for findings
        cols = ('severity', 'title', 'recommendation')
        self.tree = ttk.Treeview(master, columns=cols, show='headings')
        self.tree.heading('severity', text='Severity')
        self.tree.heading('title', text='Title')
        self.tree.heading('recommendation', text='Recommendation')
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.scanner = Scanner()
        self.scan_result = None

    def _on_run_scan(self):
        self.scan_btn.config(state=tk.DISABLED)
        self.status_lbl.config(text='Scanning...')
        t = Thread(target=self._run_scan_background, daemon=True)
        t.start()

    def _run_scan_background(self):
        try:
            res = self.scanner.run_full_scan()
            self.scan_result = res
            self._populate_tree()
            self.status_lbl.config(text=f'Scan complete — {len(res.findings)} findings')
            self.export_html_btn.config(state=tk.NORMAL)
            self.export_pdf_btn.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror('Scan Error', str(e))
            self.status_lbl.config(text='Error')
        finally:
            self.scan_btn.config(state=tk.NORMAL)

    def _populate_tree(self):
        # Clear
        for i in self.tree.get_children():
            self.tree.delete(i)
        # Insert items
        for f in self.scan_result.findings:
            self.tree.insert('', tk.END, values=(f.severity, f.title, f.recommendation))

    def _on_export_html(self):
        if not self.scan_result:
            return
        path = filedialog.asksaveasfilename(defaultextension='.html', filetypes=[('HTML files', '*.html')])
        if not path:
            return
        try:
            rep = Reporter(self.scan_result)
            rep.save_html(path)
            messagebox.showinfo('Export Complete', f'HTML report saved to {path}')
        except Exception as e:
            messagebox.showerror('Export Error', str(e))

    def _on_export_pdf(self):
        if not self.scan_result:
            return
        path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF files', '*.pdf')])
        if not path:
            return
        try:
            rep = Reporter(self.scan_result)
            rep.save_pdf(path)
            messagebox.showinfo('Export Complete', f'PDF report saved to {path}')
        except Exception as e:
            messagebox.showerror('Export Error', str(e))


# ----------------------------
# CLI fallback
# ----------------------------

def run_cli():
    print('Windows Hygiene Auditor - CLI mode')
    sc = Scanner()
    res = sc.run_full_scan()
    rep = Reporter(res)
    outdir = os.getcwd()
    name = f'hygiene-report-{res.host}-{datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")}.html'
    path = os.path.join(outdir, name)
    rep.save_html(path)
    print(f'Report saved to {path}')


# ----------------------------
# Entrypoint
# ----------------------------

if __name__ == '__main__':
    if platform.system() != 'Windows':
        print('Warning: this tool is designed for Windows and some checks will be skipped or limited.')

    if tk is None:
        print('Tkinter not available — running CLI mode')
        run_cli()
        sys.exit(0)

    root = tk.Tk()
    app = AuditorGUI(root)
    root.mainloop()
