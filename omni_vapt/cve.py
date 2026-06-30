import json
import sqlite3

import requests

from omni_vapt import console


class CVEDatabase:
    """Manages CVE data from multiple sources (NVD, CIRCL)"""

    def __init__(self, db_path="cve_database.db"):
        self.db_path = db_path
        self.init_cve_db()

    def init_cve_db(self):
        """Initialize CVE database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS cves (
                          id INTEGER PRIMARY KEY,
                          cve_id TEXT UNIQUE,
                          product TEXT,
                          vendor TEXT,
                          version_start TEXT,
                          version_end TEXT,
                          severity TEXT,
                          cvss_score REAL,
                          description TEXT,
                          published_date TEXT,
                          source TEXT,
                          last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS cve_references (
                          id INTEGER PRIMARY KEY,
                          cve_id TEXT,
                          reference_url TEXT,
                          source TEXT,
                          FOREIGN KEY(cve_id) REFERENCES cves(cve_id))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS cve_search_cache (
                          id INTEGER PRIMARY KEY,
                          product TEXT,
                          version TEXT,
                          query_results TEXT,
                          cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        conn.commit()
        conn.close()

    def search_cves(self, product, version=None):
        """Search for CVEs by product and optional version"""
        cache_result = self._get_cache(product, version)
        if cache_result:
            return json.loads(cache_result)

        results = []
        circl_results = self._search_circl(product, version)
        results.extend(circl_results)
        nvd_results = self._search_nvd(product, version)
        results.extend(nvd_results)

        unique_results = {r['cve_id']: r for r in results}
        results = list(unique_results.values())
        self._cache_results(product, version, results)
        return results

    def _search_circl(self, product, version=None):
        results = []
        try:
            url = f"https://cve.circl.lu/api/search/{product}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    cve_entry = {
                        'cve_id': item.get('id', ''),
                        'product': product,
                        'severity': item.get('cvss', {}).get('level', 'UNKNOWN'),
                        'cvss_score': item.get('cvss', {}).get('score', 0),
                        'description': item.get('summary', ''),
                        'published_date': item.get('published', ''),
                        'source': 'CIRCL',
                        'references': [
                            ref.get('url', str(ref)) if isinstance(ref, dict) else ref
                            for ref in item.get('references', [])
                            if ref
                        ]
                    }
                    if version and 'affected' in item:
                        cve_entry['affected_versions'] = item.get('affected', [])
                    results.append(cve_entry)
                    self._store_cve(cve_entry)
        except Exception as e:
            console.print(f"[yellow][!] CIRCL search error: {e}[/yellow]")
        return results

    def _search_nvd(self, product, version=None):
        results = []
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': product,
                'resultsPerPage': 100
            }
            if version:
                params['keywordSearch'] = f"{product} {version}"

            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    metrics = cve.get('metrics', {})

                    cvss_score = 0
                    severity = 'UNKNOWN'
                    if 'cvssMetricV31' in metrics:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                        severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    elif 'cvssMetricV30' in metrics:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                        severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
                    elif 'cvssMetricV2' in metrics:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                        severity = metrics['cvssMetricV2'][0]['baseSeverity']

                    cve_entry = {
                        'cve_id': cve.get('id', ''),
                        'product': product,
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'published_date': cve.get('published', ''),
                        'source': 'NVD',
                        'references': [ref['url'] for ref in cve.get('references', [])]
                    }
                    results.append(cve_entry)
                    self._store_cve(cve_entry)
        except Exception as e:
            console.print(f"[yellow][!] NVD search error: {e}[/yellow]")
        return results

    def _store_cve(self, cve_entry):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT OR IGNORE INTO cves
                   (cve_id, product, severity, cvss_score, description, published_date, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (cve_entry.get('cve_id'),
                 cve_entry.get('product'),
                 cve_entry.get('severity'),
                 cve_entry.get('cvss_score'),
                 cve_entry.get('description'),
                 cve_entry.get('published_date'),
                 cve_entry.get('source'))
            )
            for ref in cve_entry.get('references', []):
                if isinstance(ref, str):
                    cursor.execute(
                        '''INSERT INTO cve_references (cve_id, reference_url, source)
                           VALUES (?, ?, ?)''',
                        (cve_entry.get('cve_id'), ref, cve_entry.get('source'))
                    )
            conn.commit()
            conn.close()
        except Exception as e:
            console.print(f"[yellow][!] Error storing CVE: {e}[/yellow]")

    def _cache_results(self, product, version, results):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO cve_search_cache (product, version, query_results)
                   VALUES (?, ?, ?)''',
                (product, version or '', json.dumps(results))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            console.print(f"[yellow][!] Cache error: {e}[/yellow]")

    def _get_cache(self, product, version, cache_hours=24):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT query_results FROM cve_search_cache
                   WHERE product = ? AND version = ?
                   AND datetime(cached_at) > datetime('now', '-' || ? || ' hours')
                   ORDER BY cached_at DESC LIMIT 1''',
                (product, version or '', str(cache_hours))
            )
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else None
        except Exception:
            return None

    def get_cves_for_version(self, product, version):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT cve_id, severity, cvss_score, description, published_date
                   FROM cves WHERE product LIKE ? ORDER BY cvss_score DESC''',
                (f"%{product}%",)
            )
            results = cursor.fetchall()
            conn.close()
            return [
                {
                    'cve_id': r[0],
                    'severity': r[1],
                    'cvss_score': r[2],
                    'description': r[3],
                    'published_date': r[4]
                }
                for r in results
            ]
        except Exception:
            return []

    def get_db_stats(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM cves')
            total_cves = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(DISTINCT product) FROM cves')
            unique_products = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM cves WHERE source = "NVD"')
            nvd_count = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM cves WHERE source = "CIRCL"')
            circl_count = cursor.fetchone()[0]
            conn.close()
            return {
                'total_cves': total_cves,
                'unique_products': unique_products,
                'nvd_count': nvd_count,
                'circl_count': circl_count
            }
        except Exception:
            return {}
