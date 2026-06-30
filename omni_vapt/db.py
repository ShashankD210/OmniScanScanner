import sqlite3


class DBManager:
    def __init__(self, path="vapt_vault.db"):
        self.path = path
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS targets (
                          id INTEGER PRIMARY KEY,
                          ip TEXT,
                          hostname TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS scans (
                          id INTEGER PRIMARY KEY,
                          target_id INTEGER,
                          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                          summary TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS findings (
                          id INTEGER PRIMARY KEY,
                          scan_id INTEGER,
                          type TEXT,
                          severity TEXT,
                          evidence TEXT,
                          cve_references TEXT)''')
        conn.commit()
        conn.close()

    def save_scan(self, target, summary):
        conn = sqlite3.connect(self.path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO targets (ip, hostname) VALUES (?, ?)", (target, target))
        target_id = cursor.lastrowid
        cursor.execute("INSERT INTO scans (target_id, summary) VALUES (?, ?)", (target_id, summary))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def save_finding(self, scan_id, v_type, severity, evidence, cve_refs=None):
        conn = sqlite3.connect(self.path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO findings (scan_id, type, severity, evidence, cve_references) VALUES (?, ?, ?, ?, ?)",
            (scan_id, v_type, severity, evidence, cve_refs or ''),
        )
        conn.commit()
        conn.close()
