"""
HeapHunter - Report Generator

This module handles the generation of HTML reports and text files
for the findings from heap dump analysis.
"""

import os
import json
from html import escape
from typing import Dict, List, Tuple, Optional

from utils import decode_jwt_parts


class ReportGenerator:
    """Generate HTML and text reports for heap dump analysis findings."""
    
    def __init__(self, findings: List[Dict], report_dir: str):
        """Initialize the report generator.
        
        Args:
            findings: List of findings from the analysis
            report_dir: Directory to save reports to
        """
        self.findings = findings
        self.report_dir = report_dir
        
        # Create report directory if it doesn't exist
        os.makedirs(report_dir, exist_ok=True)
    
    def export_token_lists(self, output_prefix: str = "heapdump") -> None:
        """Export discovered tokens and hashes to text files.
        
        Args:
            output_prefix: Prefix for output filenames
        """
        grouped = self._group_findings()
        export_types = {
            "sha256": "sha256.txt",
            "sha1/md5": "sha1_md5.txt",
            "bcrypt": "bcrypt.txt",
            "jwt": "jwt.txt"
        }
        
        for t_type, out_file in export_types.items():
            unique_values = set()
            for item in grouped.get(t_type, []):
                value = item["match"]
                if isinstance(value, tuple):
                    value = value[-1]
                unique_values.add(value.strip())
            
            if unique_values:
                full_path = os.path.join(self.report_dir, out_file)
                with open(full_path, "w", encoding="utf-8") as f:
                    for val in sorted(unique_values):
                        if t_type == "jwt":
                            f.write("Raw JWT:\n")
                            f.write(val + "\n")
                            result = decode_jwt_parts(val)
                            if result:
                                header, payload = result
                                try:
                                    header_json = json.dumps(json.loads(header), indent=4)
                                    payload_json = json.dumps(json.loads(payload), indent=4, ensure_ascii=False)
                                except Exception:
                                    header_json = header
                                    payload_json = payload
                                f.write("Header:\n" + header_json + "\n")
                                f.write("Payload:\n" + payload_json + "\n")
                            else:
                                f.write("Could not decode JWT\n")
                            f.write("\n" + "="*50 + "\n\n")
                        else:
                            f.write(val + "\n")
                
                print(f"✅ Exported {len(unique_values)} ➜ {full_path}")
    
    def generate_html_report(self, filtered_findings: Optional[List[Dict]] = None, output_prefix: str = "heapdump") -> None:
        """Generate HTML reports for the findings.
        
        Args:
            filtered_findings: Optional filtered findings list, uses all findings if None
            output_prefix: Prefix for output filenames
        """
        findings = filtered_findings if filtered_findings is not None else self.findings
        grouped = self._group_findings(findings)
        decrypted_only = self._get_decrypted_findings(findings)
        
        # Generate per-type HTML reports
        report_links = []
        for type_name, group in grouped.items():
            safe_type_name = type_name.replace("/", "_")
            filename = os.path.join(self.report_dir, f"{output_prefix}_{safe_type_name}.html")
            report_links.append((type_name, filename))
            
            self._write_type_report(filename, type_name, group)
            print(f"✅ Wrote report: {filename}")
        
        # Generate decrypted-only report
        decrypted_report = os.path.join(self.report_dir, f"{output_prefix}_decrypted.html")
        report_links.append(("decrypted", decrypted_report))
        
        self._write_decrypted_report(decrypted_report, decrypted_only)
        print(f"✅ Wrote report: {decrypted_report}")
        
        # Generate index report
        index_path = os.path.join(self.report_dir, "index.html")
        self._write_index_report(index_path, report_links, grouped, decrypted_only)
        print(f"✅ Wrote index: {index_path}")
    
    def _group_findings(self, findings: Optional[List[Dict]] = None) -> Dict[str, List[Dict]]:
        """Group findings by type.
        
        Args:
            findings: List of findings to group, uses self.findings if None
            
        Returns:
            Dictionary mapping types to lists of findings
        """
        to_group = findings if findings is not None else self.findings
        grouped = {}
        for f in to_group:
            grouped.setdefault(f['type'], []).append(f)
        return grouped
    
    def _get_decrypted_findings(self, findings: List[Dict]) -> List[Dict]:
        """Filter findings to only those with successful decryption.
        
        Args:
            findings: List of findings to filter
            
        Returns:
            List of findings with decrypted content
        """
        return [f for f in findings if f.get('brute_decrypted')]
    
    def _write_type_report(self, filename: str, type_name: str, findings: List[Dict]) -> None:
        """Write a type-specific HTML report.
        
        Args:
            filename: Output file path
            type_name: Type of findings
            findings: List of findings of this type
        """
        with open(filename, "w", encoding="utf-8") as f:
            f.write("<html><head><meta charset='utf-8'><style>")
            f.write("body{font-family:monospace;background:#121212;color:#f0f0f0;padding:20px;}")
            f.write(".entry{margin-bottom:20px;padding:10px;border:1px solid #444;background:#1e1e1e;}")
            f.write(".json{color:#7ec699;white-space:pre-wrap;}")
            f.write(".match{color:#e06c75;}")
            f.write(".decrypt{color:#61dafb;white-space:pre-wrap;}")
            f.write("a{color:#9cdcfe;text-decoration:none;}")
            f.write("</style></head><body>")
            f.write(f"<h1>🦅 Heapdump Hunter Report – {escape(type_name.upper())}</h1>")
            
            for fnd in findings:
                f.write("<div class='entry'>")
                
                if type_name == 'credentials':
                    f.write(f"<strong>🔑 Credential Key:</strong> <span class='match'>{escape(fnd.get('source_key', ''))}</span><br>")
                    f.write(f"<strong>🧷 Password:</strong> <code>{escape(fnd['match'])}</code><br>")
                    
                    if fnd.get('base64_decoded'):
                        f.write("<strong>📦 Base64 Decoded:</strong><br>")
                        f.write(f"<code>{escape(fnd['base64_decoded'])}</code><br>")
                    
                    if fnd.get('brute_decrypted'):
                        f.write("<strong>🔓 AES Decryption:</strong><br>")
                        for r in fnd['brute_decrypted']:
                            f.write(f"<div class='decrypt'>Key: <code>{escape(r['key'])}</code><br>IV: {r['iv']}<br>→ {escape(r['decrypted'])}</div>")
                
                elif type_name == 'credential_pair':
                    f.write(f"<strong>🔐 Credential Pair – {escape(fnd['prefix'])}</strong><br>")
                    f.write(f"<strong>👤 Username Key:</strong> <code>{escape(fnd['username_key'])}</code><br>")
                    f.write(f"<strong>🧑 Username:</strong> <code>{escape(fnd['username_val'])}</code><br>")
                    f.write(f"<strong>🔑 Password Key:</strong> <code>{escape(fnd['password_key'])}</code><br>")
                    f.write(f"<strong>🔐 Password:</strong> <code>{escape(fnd['password_val'])}</code><br>")
                
                else:
                    f.write(f"<strong>Line:</strong> {fnd['line_number']}<br>")
                    f.write(f"<strong>Type:</strong> <span class='match'>{escape(fnd['type'])}</span><br>")
                    f.write(f"<strong>Match:</strong> <code>{escape(fnd['match'])}</code><br>")
                    f.write(f"<strong>Context:</strong> <code>{escape(fnd['line'])}</code><br>")
                    
                    # JWT decoding
                    if fnd['type'] == 'jwt':
                        header, payload = decode_jwt_parts(fnd['match']) or (None, None)
                        if header:
                            try:
                                header_json = json.dumps(json.loads(header), indent=4, ensure_ascii=False)
                                f.write("<strong>📄 Header:</strong><pre class='json'>" + escape(header_json) + "</pre>")
                            except:
                                f.write("<strong>📄 Header (raw):</strong><pre>" + escape(header) + "</pre>")
                        if payload:
                            try:
                                payload_json = json.dumps(json.loads(payload), indent=4, ensure_ascii=False)
                                f.write("<strong>📦 Payload:</strong><pre class='json'>" + escape(payload_json) + "</pre>")
                            except:
                                f.write("<strong>📦 Payload (raw):</strong><pre>" + escape(payload) + "</pre>")
                    
                    if fnd.get('base64_decoded'):
                        f.write("<strong>Base64 Decoded:</strong>")
                        f.write(f"<div><code>{escape(fnd['base64_decoded'])}</code></div>")
                    
                    if fnd.get('json_parsed'):
                        formatted = json.dumps(fnd['json_parsed'], indent=2)
                        f.write("<strong>Parsed JSON:</strong>")
                        f.write(f"<div class='json'>{escape(formatted)}</div>")
                    
                    if fnd.get('brute_decrypted'):
                        f.write("<strong>🔓 AES Decryption Attempts:</strong>")
                        for r in fnd['brute_decrypted']:
                            f.write(f"<div class='decrypt'>Key: <code>{escape(r['key'])}</code><br>IV: {r['iv']}<br>→ {escape(r['decrypted'])}</div>")
                
                f.write("</div>")
            
            f.write("</body></html>")
    
    def _write_decrypted_report(self, filename: str, findings: List[Dict]) -> None:
        """Write a report of successfully decrypted values.
        
        Args:
            filename: Output file path
            findings: List of findings with decrypted content
        """
        with open(filename, "w", encoding="utf-8") as f:
            f.write("<html><head><meta charset='utf-8'><style>")
            f.write("body{font-family:monospace;background:#121212;color:#f0f0f0;padding:20px;}")
            f.write(".entry{margin-bottom:20px;padding:10px;border:1px solid #444;background:#1e1e1e;}")
            f.write(".decrypt{color:#61dafb;white-space:pre-wrap;}")
            f.write("</style></head><body>")
            f.write("<h1>🔐 Heapdump Decrypted Results (AES)</h1>")
            
            for fnd in findings:
                f.write("<div class='entry'>")
                f.write(f"<strong>Line:</strong> {fnd['line_number']}<br>")
                f.write(f"<strong>Match:</strong> <code>{escape(fnd['match'])}</code><br>")
                f.write(f"<strong>Context:</strong> <code>{escape(fnd['line'])}</code><br>")
                for r in fnd['brute_decrypted']:
                    f.write(f"<div class='decrypt'>Key: <code>{escape(r['key'])}</code><br>IV: {r['iv']}<br>→ {escape(r['decrypted'])}</div>")
                f.write("</div>")
            
            f.write("</body></html>")
    
    def _write_index_report(self, filename: str, report_links: List[Tuple[str, str]], 
                           grouped: Dict[str, List[Dict]], decrypted_only: List[Dict]) -> None:
        """Write the main index HTML report with links to all other reports.
        
        Args:
            filename: Output file path
            report_links: List of (type, filename) tuples
            grouped: Dictionary of findings grouped by type
            decrypted_only: List of findings with successful decryption
        """
        with open(filename, "w", encoding="utf-8") as f:
            f.write("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>🦅 Heapdump Hunter Dashboard</title>
  <style>
    body {
        font-family: 'Segoe UI', sans-serif;
        background-color: #0d1117;
        color: #c9d1d9;
        padding: 40px;
        line-height: 1.6;
    }
    h1 {
        font-size: 32px;
        margin-bottom: 10px;
    }
    h2 {
        margin-top: 30px;
    }
    input[type="text"] {
        margin-top: 10px;
        padding: 8px;
        width: 320px;
        border: 1px solid #333;
        background-color: #161b22;
        color: #f0f0f0;
        border-radius: 4px;
        font-size: 16px;
    }
    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
        gap: 16px;
        margin-top: 20px;
    }
    .card {
        background-color: #21262d;
        padding: 12px 16px;
        border-left: 4px solid #58a6ff;
        border-radius: 4px;
        font-size: 15px;
    }
    .report-link {
        display: block;
        padding: 6px 12px;
        background-color: #21262d;
        border-left: 4px solid #58a6ff;
        color: #58a6ff;
        text-decoration: none;
        border-radius: 3px;
        font-weight: 500;
    }
    .report-link:hover {
        background-color: #30363d;
    }
  </style>
  <script>
    function filterLinks() {
        const input = document.getElementById('search').value.toLowerCase();
        const links = document.querySelectorAll('.report-link, .card');
        links.forEach(link => {
            if (link.innerText.toLowerCase().includes(input)) {
                link.style.display = 'block';
            } else {
                link.style.display = 'none';
            }
        });
    }
  </script>
</head>
<body>

  <h1>🗂️ Heapdump Hunter Report Index</h1>
  <input id="search" type="text" placeholder="🔍 Search reports..." onkeyup="filterLinks()">

  <h2>📊 Report Summary</h2>
  <div class="grid">
""")
            
            # Summary cards
            for label, _ in report_links:
                count = len(grouped.get(label, [])) if label in grouped else len(decrypted_only)
                f.write(f"<div class='card'><strong>{label.title()}</strong><br>{count} entries</div>\n")
            
            f.write("""</div>
  <h2>📁 Reports</h2>
  <div class="grid">
""")
            
            # Report links
            for label, fname in report_links:
                relative_name = os.path.basename(fname)
                f.write(f"<a class='report-link' href='{relative_name}' target='_blank'>🧾 {label.title()} Report</a>\n")
            
            f.write("</div></body></html>")
