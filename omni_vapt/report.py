import json
import zipfile
from datetime import datetime, timezone

from jinja2 import Template

from omni_vapt import console


class ReportGenerator:
    def generate_html_report(self, scan_data, cve_db=None, path="final_report.html"):
        html_layout = """
        <html>
        <head><style>
            body { font-family: sans-serif; margin: 20px; }
            .high { color: red; font-weight: bold; }
            .medium { color: orange; font-weight: bold; }
            .low { color: blue; font-weight: bold; }
            .critical { color: darkred; font-weight: bold; }
            .verified { background-color: #ffe6e6; border-left: 5px solid red; padding: 10px; margin: 10px 0; }
            .cve-card { background-color: #f5f5f5; border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
            table { border-collapse: collapse; width: 100%; margin: 20px 0; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background-color: #4CAF50; color: white; }
        </style></head>
        <body>
            <h1>VAPT Audit Report with CVE Database</h1>
            <p>Generated: {{ timestamp }}</p>

            <h2>Network Findings</h2>
            {% if network %}
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>Details</th>
                    </tr>
                    {% for item in network %}
                    <tr>
                        <td>{{ item.port }}</td>
                        <td>{{ item.service }}</td>
                        <td><span class="{{ item.severity|lower }}">{{ item.severity }}</span></td>
                        <td>{{ item.vulns }}</td>
                    </tr>
                    {% endfor %}
                </table>
            {% else %}
                <p>No network findings.</p>
            {% endif %}

            <h2>Web Findings (Verified)</h2>
            {% if web %}
                {% for item in web %}
                <div class="verified">
                    <strong>URL:</strong> {{ item.url }} <br>
                    <strong>Status:</strong> {{ item.evidence }}<br>
                    <strong>Severity:</strong> <span class="{{ item.severity|lower }}">{{ item.severity }}</span>
                </div>
                {% endfor %}
            {% else %}
                <p>No web findings.</p>
            {% endif %}

            {% if cve_stats %}
            <h2>CVE Database Statistics</h2>
            <ul>
                <li>Total CVEs in Database: {{ cve_stats.total_cves }}</li>
                <li>Unique Products: {{ cve_stats.unique_products }}</li>
                <li>CVEs from NVD: {{ cve_stats.nvd_count }}</li>
                <li>CVEs from CIRCL: {{ cve_stats.circl_count }}</li>
            </ul>
            {% endif %}
        </body>
        </html>
        """
        template = Template(html_layout)
        cve_stats = cve_db.get_db_stats() if cve_db else {}
        with open(path, "w") as f:
            f.write(template.render(
                network=scan_data['network'],
                web=scan_data['web'],
                timestamp=datetime.now(timezone.utc).isoformat(),
                cve_stats=cve_stats
            ))
        console.print(f"[green][+] HTML report generated:[/green] {path}")

    def generate_json_report(self, scan_data, cve_db=None, path="final_report.json"):
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "network": scan_data.get("network", []),
            "web": scan_data.get("web", []),
        }
        if cve_db:
            report["cve_stats"] = cve_db.get_db_stats()
        with open(path, "w") as f:
            json.dump(report, f, indent=4)
        console.print(f"[green][+] JSON report generated:[/green] {path}")

    def generate_odf_report(self, scan_data, cve_db=None, path="final_report.odt"):
        timestamp = datetime.now(timezone.utc).isoformat()
        cve_stats = cve_db.get_db_stats() if cve_db else {}

        network_rows = ""
        for item in scan_data.get("network", []):
            network_rows += f"<text:p>{item.get('port', '')} | {item.get('service', '')} | {item.get('severity', 'medium')} | {item.get('vulns', '')}</text:p>"

        web_rows = ""
        for item in scan_data.get("web", []):
            web_rows += f"<text:p>{item.get('url', '')} | {item.get('evidence', item.get('status', ''))} | {item.get('severity', 'high')}</text:p>"

        content_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
    office:version="1.2">
  <office:body>
    <office:text>
      <text:h text:outline-level="1">VAPT Audit Report</text:h>
      <text:p>Generated: {timestamp}</text:p>
      <text:h text:outline-level="2">Network Findings</text:h>
      {network_rows if network_rows else '<text:p>No network findings.</text:p>'}
      <text:h text:outline-level="2">Web Findings</text:h>
      {web_rows if web_rows else '<text:p>No web findings.</text:p>'}
      <text:h text:outline-level="2">CVE Database Statistics</text:h>
      <text:p>Total CVEs: {cve_stats.get('total_cves', 0)}</text:p>
      <text:p>Unique Products: {cve_stats.get('unique_products', 0)}</text:p>
      <text:p>CVEs from NVD: {cve_stats.get('nvd_count', 0)}</text:p>
      <text:p>CVEs from CIRCL: {cve_stats.get('circl_count', 0)}</text:p>
    </office:text>
  </office:body>
</office:document-content>"""

        styles_xml = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    office:version="1.2">
</office:document-styles>"""

        meta_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
    xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
    office:version="1.2">
  <office:meta>
    <meta:generator>OmniScan</meta:generator>
    <meta:creation-date>{timestamp}</meta:creation-date>
  </office:meta>
</office:document-meta>"""

        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("mimetype", "application/vnd.oasis.opendocument.text", zipfile.ZIP_STORED)
            zf.writestr("content.xml", content_xml)
            zf.writestr("styles.xml", styles_xml)
            zf.writestr("meta.xml", meta_xml)

        console.print(f"[green][+] ODF report generated:[/green] {path}")
