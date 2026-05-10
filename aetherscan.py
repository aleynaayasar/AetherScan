import json
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

try:
    from scapy.all import ARP, Ether, srp, conf
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
except ImportError:
    print("[!] Missing dependencies. Please run: pip install scapy rich")
    sys.exit(1)

console = Console()

@dataclass
class PortInfo:
    port: int
    service: str
    risk_level: str
    advisory: str

@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "Unknown"
    open_ports: list[PortInfo] = field(default_factory=list)
    risk_score: int = 0

PORT_DB = {
    21: ("FTP", "HIGH", "File Transfer Protocol is operating in plain text. Credentials and data can be easily intercepted using packet sniffers. Immediate mitigation: Disable FTP and migrate to SFTP or FTPS."),
    22: ("SSH", "MEDIUM", "Secure Shell is open for remote access. While encrypted, it is highly susceptible to brute-force dictionary attacks if weak passwords are used. Recommendation: Disable password authentication and enforce Public Key Infrastructure (PKI) keys."),
    23: ("Telnet", "CRITICAL", "CRITICAL VULNERABILITY! Telnet transmits all data, including usernames and passwords, in clear text. This provides zero cryptographic protection. Immediate action required: Terminate this service immediately and replace with SSH."),
    80: ("HTTP", "MEDIUM", "Unencrypted web traffic detected. Vulnerable to Man-in-the-Middle (MitM) attacks and session hijacking. Recommendation: Enforce HTTP Strict Transport Security (HSTS) and redirect all traffic to HTTPS port 443."),
    443: ("HTTPS", "LOW", "Standard encrypted web traffic. Ensure that the SSL/TLS certificates are valid, up-to-date, and configured to reject legacy protocols like TLS 1.0/1.1 to maintain cryptographic integrity."),
    445: ("SMB", "CRITICAL", "CRITICAL RISK! Server Message Block is exposed. This port is notorious for being the primary attack vector for ransomware (e.g., WannaCry, NotPetya) and worm propagation. Isolate from the public internet immediately and apply the latest OS security patches."),
    3389: ("RDP", "CRITICAL", "CRITICAL RISK! Remote Desktop Protocol is exposed to the network. This is the #1 target for automated brute-force botnets and ransomware operators. Mitigation: Place behind a secure VPN, implement strict firewall rules, and enforce Multi-Factor Authentication (MFA).")
}

class AetherCore:
    @staticmethod
    def get_local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return f"{'.'.join(ip.split('.')[:-1])}.0/24"
        finally: s.close()

    def scan(self, network):
        conf.verb = 0
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=0)
        return [Device(ip=r.psrc, mac=r.hwsrc) for _, r in ans]

    def analyze(self, device):
        total_risk = 0
        for port, (svc, risk, adv) in PORT_DB.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                if s.connect_ex((device.ip, port)) == 0:
                    device.open_ports.append(PortInfo(port, svc, risk, adv))
                    risk_map = {"LOW": 5, "MEDIUM": 15, "HIGH": 35, "CRITICAL": 55}
                    total_risk += risk_map.get(risk, 10)
        device.risk_score = min(total_risk, 100)
        return device

class AetherReporter:
    @staticmethod
    def generate(devices):
        json_data = json.dumps([asdict(d) for d in devices])
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AETHER SCAN</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@300;400;900&display=swap');
        :root {{ --bg: #050505; --surface: #0a0a0a; --accent: #00FF41; --danger: #FF3E3E; --warning: #FFEA00; --border: #1a1a1a; }}
        body {{ background: var(--bg); color: #eee; font-family: 'Outfit', sans-serif; padding: 3rem; background-image: radial-gradient(circle at 2px 2px, #1a1a1a 1px, transparent 0); background-size: 40px 40px; position: relative; min-height: 100vh; }}
        .header-container {{ text-align: center; margin-bottom: 4rem; position: relative; }}
        h1 {{ font-family: 'JetBrains Mono', monospace; font-size: 4.5rem; text-transform: uppercase; letter-spacing: 10px; color: var(--accent); margin: 0; text-shadow: 0 0 20px rgba(0, 255, 65, 0.4); }}
        .header-line {{ width: 200px; height: 3px; background: var(--accent); margin: 15px auto; box-shadow: 0 0 10px var(--accent); }}
        .sub-header {{ color: #666; font-family: 'JetBrains Mono', monospace; letter-spacing: 3px; font-size: 0.9rem; text-transform: uppercase; }}
        .signature {{ position: absolute; bottom: 20px; right: 20px; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #555; text-transform: uppercase; letter-spacing: 2px; z-index: 1000; background: rgba(5,5,5,0.8); padding: 5px 10px; border: 1px solid #222; }}
        .signature span {{ color: var(--accent); font-weight: bold; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 2rem; margin-bottom: 4rem; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); padding: 2rem; position: relative; }}
        .stat-card::after {{ content: ""; position: absolute; bottom: 0; right: 0; width: 20px; height: 20px; border-right: 2px solid var(--accent); border-bottom: 2px solid var(--accent); }}
        .card {{ background: var(--surface); border: 1px solid var(--border); padding: 2rem; margin-bottom: 1.5rem; }}
        .ip {{ font-family: 'JetBrains Mono'; color: var(--accent); font-size: 1.5rem; display: flex; justify-content: space-between; align-items: center; }}
        .risk-bar-container {{ margin: 1.5rem 0; }}
        .risk-label {{ font-size: 0.8rem; color: #888; font-family: 'JetBrains Mono'; margin-bottom: 5px; }}
        .risk-bar {{ height: 4px; background: #222; width: 100%; }}
        .risk-fill {{ height: 100%; transition: 1s; }}
        .port {{ display: inline-block; padding: 4px 12px; border: 1px solid var(--border); font-family: 'JetBrains Mono'; font-size: 0.75rem; margin-right: 10px; background: rgba(255,255,255,0.02); margin-bottom: 5px; }}
        .critical {{ border-color: var(--danger); color: var(--danger); }}
        .advisory-list {{ margin-top: 1rem; border-top: 1px dashed var(--border); padding-top: 1rem; font-size: 0.85rem; color: #aaa; line-height: 1.6; }}
        .advisory-item {{ margin-bottom: 0.8rem; }}
        .advisory-item strong {{ color: var(--text); font-family: 'JetBrains Mono'; }}
        .secure-text {{ color: #666; font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; }}
    </style>
</head>
<body>
    <div class="header-container">
        <h1>AETHER SCAN</h1>
        <div class="header-line"></div>
        <div class="sub-header">NETWORK AUDIT LOG // {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
    </div>
    <div class="stats-grid" id="stats"></div>
    <div id="root"></div>
    <div class="signature">designed by <span>Aleyna Yaşar</span></div>
    <script>
        const data = {json_data};
        const criticalCount = data.filter(d => d.risk_score > 50).length;
        
        document.getElementById('stats').innerHTML = `
            <div class="stat-card"><div style="color:#666; font-size:0.8rem;">TOTAL_NODES</div><div style="font-size:3rem; font-weight:900;">${{data.length}}</div></div>
            <div class="stat-card"><div style="color:#666; font-size:0.8rem;">THREAT_LEVEL</div><div style="font-size:3rem; font-weight:900; color:${{criticalCount > 0 ? 'var(--danger)' : 'var(--accent)'}}">${{criticalCount > 0 ? 'HIGH' : 'LOW'}}</div></div>
        `;
        
        document.getElementById('root').innerHTML = data.map(d => `
            <div class="card">
                <div class="ip">
                    <span>${{d.ip}}</span>
                    <span style="font-size:0.8rem; color:#444;">MAC: ${{d.mac}}</span>
                </div>
                <div class="risk-bar-container">
                    <div class="risk-label">RISK_SCORE: ${{d.risk_score}}%</div>
                    <div class="risk-bar">
                        <div class="risk-fill" style="width:${{d.risk_score}}%; background:${{d.risk_score > 50 ? 'var(--danger)' : 'var(--accent)'}}"></div>
                    </div>
                </div>
                <div>
                    ${{d.open_ports.length === 0 ? '<span class="secure-text">STATUS: SECURE // NO OPEN PORTS DETECTED.</span>' : ''}}
                    ${{d.open_ports.map(p => `<span class="port ${{p.risk_level === 'CRITICAL' ? 'critical' : ''}}">${{p.port}}/${{p.service}}</span>`).join('')}}
                </div>
                ${{d.open_ports.length > 0 ? `
                <div class="advisory-list">
                    ${{d.open_ports.map(p => `
                        <div class="advisory-item">
                            <strong class="${{p.risk_level === 'CRITICAL' ? 'critical' : ''}}">[PORT ${{p.port}}]</strong> ${{p.advisory}}
                        </div>
                    `).join('')}}
                </div>
                ` : ''}}
            </div>
        `).join('');
    </script>
</body>
</html>"""
        with open("aetherscan_report.html", "w", encoding="utf-8") as f:
            f.write(html_content)

if __name__ == "__main__":
    core = AetherCore()
    net = core.get_local_ip()
    console.print(Panel(f"[bold green]AETHER SCAN v1.0[/bold green]\nTarget Network: {net}", border_style="cyan"))
    
    found = core.scan(net)
    final_list = []

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), BarColumn()) as prog:
        task = prog.add_task("Analyzing nodes...", total=len(found))
        for d in found:
            final_list.append(core.analyze(d))
            prog.advance(task)

    AetherReporter.generate(final_list)
    console.print("\n[bold green]✔ MISSION ACCOMPLISHED. 'aetherscan_report.html' generated successfully.[/bold green]")