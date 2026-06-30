import threading
import time
from urllib.parse import urlparse

from rich.console import Console

from omni_vapt.cve import CVEDatabase

console = Console()


class VaptCore:
    def __init__(self, target, cve_db=None):
        self.target = target
        self.cve_db = cve_db or CVEDatabase()
        self.report = {"network": [], "web": []}

    def _get_network_target(self):
        parsed = urlparse(self.target)
        if parsed.hostname:
            return parsed.hostname
        return self.target.strip()

    def _normalize_target_url(self):
        target = self.target.strip()
        if target.startswith(("http://", "https://")):
            return target if target.endswith('/') else target + '/'
        return f"http://{target}/"

    def _format_cve_summary(self, cves, product, version):
        if not cves:
            return f"No known CVEs for {product} {version}"
        summary_parts = [f"{cve['cve_id']} (CVSS: {cve.get('cvss_score', 'N/A')})" for cve in cves[:5]]
        return " | ".join(summary_parts)

    def network_vuln_scan(self):
        network_target = self._get_network_target()
        console.print(f"[cyan][*][/cyan] Analyzing network services for [bold]{network_target}[/bold]...")
        try:
            import nmap
            nm = nmap.PortScanner()
            nm.scan(network_target, arguments='-sV')
        except Exception as exc:
            console.print(f"[red][!] nmap scan failed for {network_target}: {exc}[/red]")
            return
        raw_services = []
        try:
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service = nm[host][proto][port]
                        product = service.get('product') or service.get('name')
                        version = service.get('version') or 'unknown'
                        if product:
                            raw_services.append((host, port, product, version))
        except Exception as exc:
            console.print(f"[red][!] Error parsing nmap results: {exc}[/red]")
            return

        unique_services = {}
        for host, port, product, version in raw_services:
            key = (product, version)
            if key not in unique_services:
                unique_services[key] = []
            unique_services[key].append((host, port))

        cve_cache = {}
        for (product, version), _ in unique_services.items():
            try:
                cves = self.cve_db.search_cves(product, version)
                cve_cache[(product, version)] = cves
                time.sleep(0.5)
            except Exception as exc:
                console.print(f"[yellow][!] CVE lookup failed for {product} {version}: {exc}[/yellow]")
                cve_cache[(product, version)] = []

        for (product, version), host_ports in unique_services.items():
            cves = cve_cache.get((product, version), [])
            cve_data = self._format_cve_summary(cves, product, version)
            severity = 'low'
            if cves:
                max_score = max([c.get('cvss_score', 0) for c in cves], default=0)
                if max_score >= 9:
                    severity = 'critical'
                elif max_score >= 7:
                    severity = 'high'
                elif max_score >= 4:
                    severity = 'medium'
            for host, port in host_ports:
                self.report['network'].append({
                    'host': host,
                    'port': port,
                    'service': product,
                    'version': version,
                    'vulns': cve_data,
                    'type': 'network_service',
                    'verified': False,
                    'severity': severity,
                    'cves': [c['cve_id'] for c in cves[:5]]
                })

    def web_directory_fuzz(self):
        console.print(f"[cyan][*][/cyan] Fuzzing web directories on [bold]{self.target}[/bold]...")
        base_url = self._normalize_target_url()
        wordlist = ['admin', 'config', 'db', 'backup', 'v1', 'api', 'backup.zip', 'db.sql', '.git']
        for path in wordlist:
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                import requests
                res = requests.get(url, timeout=3)
                if res.status_code == 200:
                    self.report['web'].append({
                        'url': url,
                        'status': 'EXPOSED',
                        'type': 'web_path',
                        'verified': False,
                        'evidence': f'HTTP {res.status_code} returned',
                        'severity': 'high',
                    })
            except Exception:
                continue

    def web_security_headers(self):
        console.print(f"[cyan][*][/cyan] Checking web security headers on [bold]{self.target}[/bold]...")
        url = self._normalize_target_url()
        try:
            import requests
            response = requests.get(url, timeout=5)
            headers = response.headers
            missing = [h for h in ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"] if h not in headers]
            result = {
                'url': url,
                'type': 'web_headers',
                'status': 'Complete',
                'missing_headers': missing,
                'severity': 'high' if missing else 'low',
                'evidence': f"Missing headers: {', '.join(missing)}" if missing else "All recommended headers present",
                'verified': False
            }
            self.report['web'].append(result)
        except Exception as exc:
            self.report['web'].append({
                'url': url,
                'type': 'web_headers',
                'status': 'Error',
                'evidence': str(exc),
                'severity': 'medium',
                'verified': False
            })

    def run_full_audit(self):
        t1 = threading.Thread(target=self.network_vuln_scan)
        t2 = threading.Thread(target=self.web_directory_fuzz)
        t3 = threading.Thread(target=self.web_security_headers)
        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()
        self.finalize_report()
        return self.report

    def finalize_report(self):
        console.print("\n[bold]--- VAPT FINAL SUMMARY ---[/bold]")
        console.print(f"Network Findings: {len(self.report['network'])}")
        console.print(f"Web Findings: {len(self.report['web'])}")
