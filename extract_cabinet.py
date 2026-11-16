import re
import struct

with open(r'C:\Users\FaarusDz\Downloads\Telegram Desktop\InfinityERP_Full_Setup.exe', 'rb') as f:
    data = f.read()

# Search for cabinet file signatures
# MSCF signature for CAB files
cab_signatures = [
    b'MSCF',  # Standard CAB
    b'CAB',   # Alternative
]

# Search for MSI signatures
msi_signatures = [
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',  # OLE compound document (MSI)
]

# Search for ZIP signatures
zip_signatures = [
    b'PK\x03\x04',  # ZIP local file header
    b'PK\x05\x06',  # ZIP end of central directory
    b'PK\x07\x08',  # ZIP archive extra data
]

# Search for common installer payload markers
payload_markers = [
    b'CABINET',
    b'INSTALL',
    b'PAYLOAD',
    b'ARCHIVE',
    b'COMPRESS',
]

print("=== SEARCHING FOR EMBEDDED ARCHIVES/CABINETS ===\n")

# Find all occurrences of MSCF
for sig in cab_signatures:
    positions = []
    start = 0
    while True:
        pos = data.find(sig, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    if positions:
        print(f"CAB signature {sig}: Found at {len(positions)} positions")
        for pos in positions[:10]:
            print(f"  Offset 0x{pos:X} ({pos}) - Context: {data[max(0,pos-16):pos+32]}")

# Find MSI signatures
for sig in msi_signatures:
    positions = []
    start = 0
    while True:
        pos = data.find(sig, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    if positions:
        print(f"\nMSI signature: Found at {len(positions)} positions")
        for pos in positions[:10]:
            print(f"  Offset 0x{pos:X} ({pos})")

# Find ZIP signatures
for sig in zip_signatures:
    positions = []
    start = 0
    while True:
        pos = data.find(sig, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    if positions:
        print(f"\nZIP signature {sig}: Found at {len(positions)} positions")
        for pos in positions[:10]:
            print(f"  Offset 0x{pos:X} ({pos})")

# Search for payload markers
print("\n=== PAYLOAD MARKERS ===")
for marker in payload_markers:
    positions = []
    start = 0
    while True:
        pos = data.find(marker, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    if positions:
        print(f"'{marker.decode()}': Found at {len(positions)} positions")
        for pos in positions[:5]:
            print(f"  Offset 0x{pos:X} ({pos}) - Context: {data[max(0,pos-32):pos+64]}")

# Search for registry paths
print("\n=== REGISTRY PATHS ===")
registry_patterns = [
    rb'HKEY_[A-Z_]+',
    rb'SOFTWARE\\[^\\x00]*',
    rb'CurrentVersion\\[^\\x00]*',
    rb'Run\\[^\\x00]*',
    rb'RunOnce\\[^\\x00]*',
    rb'Uninstall\\[^\\x00]*',
]

for pattern in registry_patterns:
    matches = re.findall(pattern, data)
    if matches:
        print(f"Pattern {pattern}: {len(matches)} matches")
        for m in matches[:20]:
            print(f"  {m.decode('ascii', errors='ignore')}")

# Search for more URLs and domains
print("\n=== URLS AND DOMAINS ===")
url_pattern = rb'https?://[^\x00\s"\'<>]{4,}'
urls = re.findall(url_pattern, data)
for url in urls:
    print(f"  {url.decode('ascii', errors='ignore')}")

domain_pattern = rb'[a-zA-Z0-9.-]+\.(?:com|net|org|site|online|it\.com|fr)[^\x00\s"\'<>]*'
domains = re.findall(domain_pattern, data)
for domain in domains:
    print(f"  {domain.decode('ascii', errors='ignore')}")

# Search for API endpoints
print("\n=== API ENDPOINTS ===")
api_pattern = rb'/api/[^\x00\s"\'<>]{4,}'
apis = re.findall(api_pattern, data)
for api in apis:
    print(f"  {api.decode('ascii', errors='ignore')}")

# Search for port numbers
print("\n=== PORT NUMBERS ===")
port_pattern = rb'(?:port|Port|PORT)[:=\s]*(\d{2,5})'
ports = re.findall(port_pattern, data)
for port in ports:
    print(f"  {port.decode('ascii', errors='ignore')}")

# Look for embedded file names with extensions
print("\n=== EMBEDDED FILE NAMES ===")
file_pattern = rb'[A-Za-z0-9_.-]+\.(?:exe|dll|msi|cab|zip|jar|bat|cmd|ps1|sql|db|ini|config|json|xml|txt|log|dat|bak|tmp)[^\x00\s"\'<>]*'
files = re.findall(file_pattern, data)
for f in files[:50]:
    print(f"  {f.decode('ascii', errors='ignore')}")

# Check for PostgreSQL/MySQL references
print("\n=== DATABASE REFERENCES ===")
db_patterns = [rb'postgres', rb'mysql', rb'sqlite', rb'mssql', rb'oracle', rb'5432', rb'3306', rb'1433']
for pattern in db_patterns:
    matches = list(re.finditer(pattern, data, re.IGNORECASE))
    if matches:
        print(f"'{pattern.decode()}': {len(matches)} matches")
        for m in matches[:5]:
            start = max(0, m.start() - 64)
            end = min(len(data), m.end() + 64)
            print(f"  Offset 0x{m.start():X}: ...{data[start:end]}...")

# Check for certificate/key material
print("\n=== CERTIFICATE/KEY MARKERS ===")
cert_patterns = [rb'-----BEGIN', rb'PRIVATE KEY', rb'PUBLIC KEY', rb'CERTIFICATE', rb'RSA', rb'EC ', rb'SHA256', rb'sha256']
for pattern in cert_patterns:
    matches = list(re.finditer(pattern, data, re.IGNORECASE))
    if matches:
        print(f"'{pattern.decode()}': {len(matches)} matches")

# Look for version info
print("\n=== VERSION STRINGS ===")
version_pattern = rb'\d+\.\d+\.\d+\.\d+'
versions = re.findall(version_pattern, data)
for v in versions[:20]:
    print(f"  {v.decode('ascii', errors='ignore')}")