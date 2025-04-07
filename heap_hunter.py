# hunter_fixed.py
# 🔧 Javított verzió – 2025.04.07 – Arcanum Cyber

import re
import base64
import json
from pathlib import Path
from html import escape
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import argparse
from os.path import join as path_join, splitext, basename
import string

CONFIG_KEY_PATH = "keys.txt"

SENSITIVE_PATTERNS = {
    'jwt': re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'),
    'bcrypt': re.compile(r'(\$2[aby]\$.{56})'),
    'sha256': re.compile(r'([a-fA-F0-9]{64})'),
    'sha1/md5': re.compile(r'([a-fA-F0-9]{32})'),
    'tokens': re.compile(r'(?i)(bearer|token|secret|apikey)[=: ]+([^\s"\']{10,})'),
    'base64': re.compile(r'([A-Za-z0-9+/=]{40,})'),
}

CREDENTIAL_KEY_BLACKLIST = [
    "key", "keys", "field", "factory", "method", "clazz", "type", 
    "Token", "Deserializer", "Deserializer", "Generator", "Handler",
    "Iterator", "Map", "HashMap", "Set", "Value", "Operation", "Parameter", 
    "Builder", "Strategy", "Node", "Object", "Thread", "ByteBuf",
    "invoke", "LambdaForm", "java/", "javax/", "org/", "sun/", "jdk/"
]

def is_plausible_credential(key: str, value: str) -> bool:
    key_lower = key.lower()
    value = value.strip().strip('#!;:=')

    # ❌ Ha kulcs blacklistelt, dobjuk
    if any(blk in key_lower for blk in CREDENTIAL_KEY_BLACKLIST):
        return False

    # ✅ Ha a kulcs hiteles (pl. 'secret', 'key', 'jwt'), engedjük át
    if any(kw in key_lower for kw in ['password', 'secret', 'token', 'key', 'jwt', 'username', 'user']):
        return True

    # ✅ Ha az érték base64-szerű (és elég hosszú), engedjük át
    if len(value) >= 20 and re.match(r'^[A-Za-z0-9+/=]+$', value):
        return True

    # ✅ Ha jelszónak néz ki
    if is_strong_candidate(value):
        return True

    return False

def print_help():
    print("""
🦅 Heapdump Hunter Usage:
--------------------------

python hunter.py [heapdump.hprof] [options]

Options:
  --extract-only       Only export sha256 / jwt / bcrypt / md5 hashes to .txt
  --html-only          Only generate HTML reports (no .txt exports)
  --jwt-only           Only generate report for JWT tokens
  --sha256-only        Only generate report for SHA256 hashes
  --sha1-md5-only      Only generate report for SHA1/MD5 hashes
  --bcrypt-only        Only generate report for bcrypt hashes
  --decrypted-only     Only show AES-decrypted values
  --help               Show this help and exit

Defaults:
  - All reports and exports are saved to the ./report/ folder
  - Output includes per-type HTML reports + index.html dashboard

🔐 keys.txt – AES brute kulcslista:
-----------------------------------
Place your common AES decryption keys (for Base64 blobs) in a keys.txt file.
One key per line.

Example:
  secret123
  jwt-secret
  mypasswordkey
  springbootkey

These keys will be used to try decrypting Base64 strings found in the heapdump.

Examples:
  python hunter.py heapdump.hprof
  python hunter.py heapdump.hprof --extract-only
  python hunter.py heapdump.hprof --sha256-only
""")

def is_likely_garbage(match, source_key):
    if len(match) > 50:
        return True
    if re.match(r'^[A-Z0-9_]+$', match):
        return True
    if re.search(r'[{}<>\[\]\(\)]', match):
        return True
    if any(bad in match.lower() for bad in ['lambda$', 'ljava', 'lorg', '$$', 'springframework', 'hibernate']):
        return True
    if ' ' in match or '\t' in match:
        return True
    if source_key:
        # 🔧 FIX: normalize kulcsnév és utólagos elemzés
        sk = re.sub(r'[^a-z0-9]', '', source_key.lower())
        if not any(x in sk for x in ['password', 'token', 'secret', 'key', 'pass']):
            return True
    return False

def extract_strings(filepath, min_length=4):
    with open(filepath, 'rb') as f:
        data = f.read()

    results = []
    current = bytearray()

    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                results.append(current.decode('ascii', errors='ignore'))
            current = bytearray()

    if len(current) >= min_length:
        results.append(current.decode('ascii', errors='ignore'))

    with open("debug_strings.txt", "w", encoding="utf-8") as f:
        for s in results:
            f.write(s + "\n")

    return results

def try_decode_base64(s):
    s = s.strip().rstrip('#!;')
    try:
        decoded = base64.b64decode(s + '=' * (-len(s) % 4)).decode(errors='ignore')
        return decoded if decoded.strip() else None
    except Exception:
        return None

def try_parse_json(s):
    try:
        return json.loads(s)
    except Exception:
        return None

def load_keys(path=CONFIG_KEY_PATH):
    if not Path(path).exists():
        return []
    return [line.strip() for line in open(path, 'r') if line.strip()]

def is_readable(s):
    return any(c.isalnum() for c in s) and all(31 < ord(c) < 127 or c in '\n\r\t' for c in s)

def try_decrypt_base64_ciphertext(ciphertext_b64, keys):
    results = []
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception:
        return results

    iv_guesses = [ciphertext[:16], b'\x00' * 16]

    for key in keys:
        key_bytes = key.encode()[:32].ljust(32, b'\0')
        for iv in iv_guesses:
            try:
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
                decoded = decrypted.decode('utf-8')
                if is_readable(decoded):
                    results.append({
                        'key': key,
                        'iv': iv.hex(),
                        'decrypted': decoded
                    })
            except:
                continue
    return results

def hunt_strings(strings, keylist):
    findings = []
    for idx, line in enumerate(strings):
        for label, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(line)
            for match in matches:
                data = match[-1] if isinstance(match, tuple) else match
                base64_decoded = try_decode_base64(data)
                json_parsed = try_parse_json(base64_decoded) if base64_decoded else None
                brute_results = try_decrypt_base64_ciphertext(data, keylist) if label == "base64" else []

                findings.append({
                    'type': label,
                    'line': line.strip(),
                    'match': data,
                    'base64_decoded': base64_decoded,
                    'json_parsed': json_parsed,
                    'brute_decrypted': brute_results,
                    'line_number': idx + 1
                })
    return findings

# 🔧 Javított kulcsszó keresés – több kulcsot is megtart!
def hunt_contextual_passwords(strings, keylist, lookahead=3):
    findings = []
    keywords = [
        "password", "passwd", "pwd", "pass", "secret", "token", "key",
        "credential", "auth", "security", "jwt", "private", "apikey",
        "access", "jwt_secret", "secret_key", "encryption", "crypto"
    ]

    def is_likely_key_name(s):
        s = s.strip()
        if len(s) > 100:
            return False
        # 💥 pontosan kulcsformátumra szűrjünk
        if not re.match(r'^[a-zA-Z0-9_.\-]+[!:]$', s):
            return False
        if any(kw in s.lower() for kw in ['password', 'user', 'token', 'secret', 'key', 'auth', 'jwt']):
            return True
        return False


    for idx, line in enumerate(strings):
        line_lower = line.lower()
        if any(kw in line_lower for kw in keywords):
            for offset in range(1, lookahead + 1):
                if idx + offset >= len(strings):
                    continue

                candidate = strings[idx + offset].strip()
                candidate = re.sub(r'[^a-zA-Z0-9+/=]+$', '', candidate)

                if is_probable_key(candidate):
                    continue

                if is_likely_key_name(candidate):
                    continue  # 💥 ez a fix: ne fogadjunk el újabb kulcsot értékként

                if (
                    len(candidate) >= 8
                    and all(c.isprintable() for c in candidate)
                    and not any(c.isspace() for c in candidate)
                    and (is_strong_candidate(candidate) or candidate.endswith('=') or try_decode_base64(candidate))
                ):
                    findings.append({
                        'type': 'fallback_credential',
                        'line': line.strip(),
                        'source_key': line.strip(),
                        'match': candidate.strip().strip('#!;:'),
                        'line_number': idx + offset + 1,
                        'base64_decoded': try_decode_base64(candidate),
                        'json_parsed': try_parse_json(candidate),
                        'brute_decrypted': try_decrypt_base64_ciphertext(candidate, keylist)
                    })
                    break  # csak az első értéket vesszük, ha nem kulcs volt

    return findings

def is_probable_key(s: str) -> bool:
    s = s.strip()
    if len(s) > 100:
        return False
    if not re.match(r'^[a-zA-Z0-9_.\-]+[!:]$', s):
        return False
    if any(kw in s.lower() for kw in ['password', 'user', 'username', 'token', 'secret', 'key', 'auth', 'jwt']):
        return True
    return False

def find_username_password_pairs(strings):
    user_keywords = ['user', 'username', 'login']
    pass_keywords = ['password', 'passwd', 'pwd', 'secret']

    user_entries = {}
    pass_entries = {}
    pairs = []

    for i in range(len(strings) - 1):
        k = strings[i].strip()
        v = strings[i + 1].strip()

        # 🔒 Ne próbálkozz, ha a "kulcs" nem kulcsszerű
        if not is_probable_key(k):
            continue

        # 🔒 Ne próbálkozz, ha az "érték" is kulcsszerű
        if is_probable_key(v):
            continue
        
        if not is_real_value(v):
            continue

        k_lc = k.lower()

        for kw in user_keywords:
            if kw in k_lc:
                prefix = k.rsplit('.', 1)[0] if '.' in k else None
                if prefix:
                    user_entries.setdefault(prefix, []).append({
                        "key": k,
                        "value": v
                    })

        for kw in pass_keywords:
            if kw in k_lc:
                prefix = k.rsplit('.', 1)[0] if '.' in k else None
                if prefix:
                    pass_entries.setdefault(prefix, []).append({
                        "key": k,
                        "value": v
                    })

    for prefix in user_entries:
        if prefix in pass_entries:
            for user in user_entries[prefix]:
                for pw in pass_entries[prefix]:
                    if user['value'] == pw['value']:
                        continue
                    if not is_plausible_credential(user['key'], user['value']):
                        continue
                    if not is_plausible_credential(pw['key'], pw['value']):
                        continue

                    pairs.append({
                        'type': 'credential_pair',
                        'prefix': prefix,
                        'username_key': user['key'],
                        'username_val': user['value'],
                        'password_key': pw['key'],
                        'password_val': pw['value']
                    })

    return pairs

def is_strong_candidate(pw):
    if len(pw) < 8:
        return False
    if not re.search(r"[a-zA-Z]", pw):
        return False
    if not re.search(r"[0-9]", pw):
        return False
    return True

def filter_credential_findings(findings):
    valid = []

    for f in findings:
        if f['type'] != 'credentials':
            continue

        pwd = f.get('match') or f.get('password') or ''
        pwd_str = str(pwd).strip().strip('#!;:=')
        key = f.get('source_key', '') or f.get('line', '')
        key_lc = key.lower()

        # 💥 Fő fix: ha kulcs megbízható, automatikusan elfogadjuk
        if any(kw in key_lc for kw in ['password', 'secret', 'token', 'key', 'jwt', 'username', 'user']):
            if len(pwd_str) >= 8:
                valid.append(f)
                continue

        # Másodlagos: ha base64-szerű, vagy karakter szempontból erős
        if len(pwd_str) >= 20 and re.match(r'^[A-Za-z0-9+/=]+$', pwd_str):
            valid.append(f)
            continue

        if is_strong_candidate(pwd_str):
            valid.append(f)
            continue

        #print(f"❌ Rejected (not plausible): {key} → {pwd_str}")

    return valid

def export_token_lists(grouped, output_prefix="heapdump", report_dir="report"):
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
            full_path = path_join(report_dir, out_file)
            with open(full_path, "w", encoding="utf-8") as f:
                for val in sorted(unique_values):
                    f.write("Raw JWT:\n")
                    f.write(val + "\n")
                    if t_type == "jwt":
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

def generate_html_report(findings, output_prefix="heapdump", report_dir="report"):
    grouped = {}
    decrypted_only = []

    for f in findings:
        grouped.setdefault(f['type'], []).append(f)
        if f.get('brute_decrypted'):
            decrypted_only.append(f)

    # === Index linkgyűjtő
    report_links = []

    # === Típusonkénti HTML fájlok ===
    for type_name, group in grouped.items():
        safe_type_name = type_name.replace("/", "_")
        filename = path_join(REPORT_DIR, f"{output_prefix}_{safe_type_name}.html")
        report_links.append((type_name, filename))

        index_path = path_join(REPORT_DIR, "index.html")
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

            for fnd in group:
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
        print(f"✅ Wrote report: {filename}")

    # === Decrypted-only riport ===
    decrypted_report = path_join(REPORT_DIR, f"{output_prefix}_decrypted.html")
    report_links.append(("decrypted", decrypted_report))

    with open(decrypted_report, "w", encoding="utf-8") as f:
        f.write("<html><head><meta charset='utf-8'><style>")
        f.write("body{font-family:monospace;background:#121212;color:#f0f0f0;padding:20px;}")
        f.write(".entry{margin-bottom:20px;padding:10px;border:1px solid #444;background:#1e1e1e;}")
        f.write(".decrypt{color:#61dafb;white-space:pre-wrap;}")
        f.write("</style></head><body>")
        f.write("<h1>🔐 Heapdump Decrypted Results (AES)</h1>")

        for fnd in decrypted_only:
            f.write("<div class='entry'>")
            f.write(f"<strong>Line:</strong> {fnd['line_number']}<br>")
            f.write(f"<strong>Match:</strong> <code>{escape(fnd['match'])}</code><br>")
            f.write(f"<strong>Context:</strong> <code>{escape(fnd['line'])}</code><br>")
            for r in fnd['brute_decrypted']:
                f.write(f"<div class='decrypt'>Key: <code>{escape(r['key'])}</code><br>IV: {r['iv']}<br>→ {escape(r['decrypted'])}</div>")
            f.write("</div>")

        f.write("</body></html>")
    print(f"✅ Wrote report: {decrypted_report}")

    # === Index riport generálása + stat + kereső ===
    index_path = path_join(REPORT_DIR, "index.html")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("<html><head><meta charset='utf-8'><style>")
        f.write("body{font-family:Arial;background:#0d1117;color:#c9d1d9;padding:40px;}")
        f.write("a{display:block;margin:8px 0;font-size:18px;color:#58a6ff;text-decoration:none;}")
        f.write("input{margin-bottom:20px;padding:8px;width:300px;border:1px solid #333;background:#161b22;color:#f0f0f0;}")
        f.write("</style>")
        f.write("<script>")
        f.write("""
            function filterLinks() {
                const input = document.getElementById('search').value.toLowerCase();
                const links = document.querySelectorAll('.report-link');
                links.forEach(link => {
                    if (link.innerText.toLowerCase().includes(input)) {
                        link.style.display = 'block';
                    } else {
                        link.style.display = 'none';
                    }
                });
            }
        """)
        f.write("</script></head><body>")
        f.write("<h1>🗂️ Heapdump Hunter Report Index</h1>")
        f.write("<input id='search' type='text' placeholder='🔍 Search report type...' onkeyup='filterLinks()'>")

        f.write("<h2>📊 Report Summary</h2><ul>")
        for label, fname in report_links:
            count = len(grouped.get(label, [])) if label in grouped else len(decrypted_only)
            f.write(f"<li>{label.title()} ➜ {count} entries</li>")
        f.write("</ul>")

        f.write("<h2>📁 Reports</h2>")
        for label, fname in report_links:
            relative_name = Path(fname).name  # csak a fájlnév, mappa nélkül
            f.write(f"<a class='report-link' href='{relative_name}' target='_blank'>🗂️ {label.title()} report</a>")


        f.write("</body></html>")


    print("✅ Wrote index: index.html")

def hunt_key_value_sequences(strings):
    findings = []

    for idx in range(len(strings) - 1):
        key = strings[idx].strip()
        val = strings[idx + 1].strip()

        if not is_probable_key(key):
            continue
        if not val or len(val) < 6:
            continue
        if not all(c.isprintable() and not c.isspace() for c in val):
            continue

        findings.append({
            'type': 'credentials',
            'source_key': key,
            'line': key,
            'match': val.strip().strip('#!;:'),
            'line_number': idx + 2,
            'base64_decoded': try_decode_base64(val),
            'json_parsed': try_parse_json(val),
            'brute_decrypted': try_decrypt_base64_ciphertext(val, load_keys())
        })

    return findings

def hunt_adjacent_credentials(strings):
    findings = []

    for i in range(len(strings) - 2):
        maybe_key = strings[i + 1].strip()
        maybe_val = strings[i + 2].strip()

        if not is_probable_key(maybe_key):
            continue
        if not maybe_val or len(maybe_val) < 6:
            continue
        if not all(c.isprintable() and not c.isspace() for c in maybe_val):
            continue

        findings.append({
            'type': 'credentials',
            'source_key': maybe_key,
            'line': maybe_key,
            'match': maybe_val.strip().strip('#!;:'),
            'line_number': i + 3,
            'base64_decoded': try_decode_base64(maybe_val),
            'json_parsed': try_parse_json(maybe_val),
            'brute_decrypted': try_decrypt_base64_ciphertext(maybe_val, load_keys())
        })

    return findings

def is_real_value(val: str) -> bool:
    if not val or len(val) < 3:
        return False
    if any(s in val for s in ['/', '.', '$', ';', 'Lorg', 'Ljava', 'io.', 'org.', 'java.', 'net.', 'jakarta.']):
        return False
    return True

def run_hunter(hprof_path, mode="all", report_dir="report"):
    print(f"[🦅] Scanning: {hprof_path}")
    strings = extract_strings(hprof_path)
    keys = load_keys()
    print(f"[+] Loaded {len(keys)} keys from config.")
    findings = hunt_strings(strings, keys)
    findings += hunt_contextual_passwords(strings, keys, lookahead=3)
    findings += hunt_adjacent_credentials(strings)
    findings += hunt_key_value_sequences(strings)
    findings += find_username_password_pairs(strings)
 
    # ✅ fallback_credential kiszűrése, ha van erősebb credentials
    strong_keys = set(f['source_key'] for f in findings if f['type'] == 'credentials')
    findings = [
        f for f in findings
        if not (f['type'] == 'fallback_credential' and f['source_key'] in strong_keys)
    ]

    before = len([f for f in findings if f['type'] == 'credentials'])
    credentials_raw = [f for f in findings if f['type'] == 'credentials']
    credentials_filtered = filter_credential_findings(credentials_raw)
    non_credentials = [f for f in findings if f['type'] != 'credentials']
    findings = non_credentials + credentials_filtered
    after = len([f for f in findings if f['type'] == 'credentials'])
    print(f"🔍 Filtered credentials: {before} → {after}")

    grouped = {}
    for f in findings:
        grouped.setdefault(f['type'], []).append(f)

    if mode == "extract-only":
        export_token_lists(grouped, report_dir=report_dir)

    elif mode == "html-only":
        generate_html_report(findings, report_dir=report_dir)

    elif mode in ["jwt-only", "sha256-only", "sha1-md5-only", "bcrypt-only"]:
        target_type = {
            "jwt-only": "jwt",
            "sha256-only": "sha256",
            "sha1-md5-only": "sha1/md5",
            "bcrypt-only": "bcrypt"
        }[mode]
        filtered_findings = grouped.get(target_type, [])
        generate_html_report(filtered_findings, report_dir=report_dir)

    elif mode == "decrypted-only":
        decrypted_only = [f for f in findings if f["brute_decrypted"]]
        generate_html_report(decrypted_only, report_dir=report_dir)

    else:
        generate_html_report(findings, report_dir=report_dir)
        export_token_lists(grouped, report_dir=report_dir)

def decode_jwt_parts(jwt_str):
    try:
        parts = jwt_str.split(".")
        if len(parts) < 2:
            return None

        header = base64.urlsafe_b64decode(pad_base64(parts[0])).decode('utf-8', errors='ignore')
        payload = base64.urlsafe_b64decode(pad_base64(parts[1])).decode('utf-8', errors='ignore')
        return header, payload
    except Exception:
        return None

def pad_base64(s):
    return s + "=" * (-len(s) % 4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("heapdump", nargs="?", default="heapdump.hprof")
    parser.add_argument("--extract-only", action="store_true")
    parser.add_argument("--html-only", action="store_true")
    parser.add_argument("--jwt-only", action="store_true")
    parser.add_argument("--sha256-only", action="store_true")
    parser.add_argument("--sha1-md5-only", action="store_true")
    parser.add_argument("--bcrypt-only", action="store_true")
    parser.add_argument("--decrypted-only", action="store_true")
    parser.add_argument("--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print_help()
        exit(0)

    base_filename = splitext(basename(args.heapdump))[0]
    REPORT_DIR = f"report_{base_filename}"
    Path(REPORT_DIR).mkdir(exist_ok=True)

    mode = "all"
    if args.extract_only:
        mode = "extract-only"
    elif args.html_only:
        mode = "html-only"
    elif args.jwt_only:
        mode = "jwt-only"
    elif args.sha256_only:
        mode = "sha256-only"
    elif args.sha1_md5_only:
        mode = "sha1-md5-only"
    elif args.bcrypt_only:
        mode = "bcrypt-only"
    elif args.decrypted_only:
        mode = "decrypted-only"

    run_hunter(args.heapdump, mode, report_dir=REPORT_DIR)