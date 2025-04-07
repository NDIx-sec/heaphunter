# heap_hunter by NDIx
Scraping heapdump.hprof files to extract juicy infos

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
