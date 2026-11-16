import struct
import re

# Analyze the RT_RCDATA resource (173KB) - likely contains installer payload
with open('resource_RT_RCDATA_102_1.bin', 'rb') as f:
    data = f.read()

print(f"RCDATA size: {len(data)} bytes (0x{len(data):X})")
print(f"First 64 bytes: {data[:64]}")
print(f"Last 64 bytes: {data[-64:]}")

# Check for CAB signature
if data[:4] == b'MSCF':
    print("\n>>> FOUND CABINET (MSCF) SIGNATURE AT START!")
    # Parse CAB header
    # MSCF signature (4), reserved (4), cabinet size (4), reserved (4),
    # offset to first folder (4), reserved (4), version (2), num folders (2),
    # num files (2), flags (2), set id (2), cabinet number (2)
    cab_header = data[:36]
    sig, res1, cab_size, res2, offset_folders, res3, version, num_folders, num_files, flags, set_id, cab_num = struct.unpack('<4sIIIIHHHHHH', cab_header)
    print(f"  Cabinet size: {cab_size} (0x{cab_size:X})")
    print(f"  Num folders: {num_folders}")
    print(f"  Num files: {num_files}")
    print(f"  Flags: 0x{flags:X}")
    print(f"  Version: {version}")
    print(f"  Set ID: {set_id}")
    print(f"  Cabinet #: {cab_num}")

# Check for MSI/OLE signature
elif data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
    print("\n>>> FOUND OLE/MSO (MSI) SIGNATURE AT START!")

# Check for ZIP signature
elif data[:4] == b'PK\x03\x04':
    print("\n>>> FOUND ZIP SIGNATURE AT START!")

# Search for embedded cabinets within the RCDATA
print("\n=== SEARCHING FOR EMBEDDED CABINETS IN RCDATA ===")
cab_positions = []
start = 0
while True:
    pos = data.find(b'MSCF', start)
    if pos == -1:
        break
    cab_positions.append(pos)
    start = pos + 1

if cab_positions:
    print(f"Found {len(cab_positions)} MSCF signatures at offsets:")
    for pos in cab_positions:
        print(f"  0x{pos:X} ({pos})")
        # Try to parse each cabinet header
        if pos + 36 <= len(data):
            cab_header = data[pos:pos+36]
            try:
                sig, res1, cab_size, res2, offset_folders, res3, version, num_folders, num_files, flags, set_id, cab_num = struct.unpack('<4sIIIIHHHHHH', cab_header)
                print(f"    Size: {cab_size}, Folders: {num_folders}, Files: {num_files}, Flags: 0x{flags:X}")
            except:
                print(f"    Could not parse header")
else:
    print("No MSCF signatures found in RCDATA")

# Search for other archive signatures
print("\n=== SEARCHING FOR OTHER ARCHIVE SIGNATURES ===")
signatures = {
    b'PK\x03\x04': 'ZIP local header',
    b'PK\x05\x06': 'ZIP end of central directory',
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'OLE/MSO compound document (MSI)',
    b'MSCF': 'Cabinet (CAB)',
    b'CAB\x00': 'Alternative CAB',
}

for sig, desc in signatures.items():
    positions = []
    start = 0
    while True:
        pos = data.find(sig, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    if positions:
        print(f"{desc} ({sig}): {len(positions)} occurrences at {[f'0x{p:X}' for p in positions[:10]]}")

# Search for strings in RCDATA
print("\n=== STRINGS IN RCDATA ===")
ascii_strings = re.findall(b'[\x20-\x7e]{6,}', data)
utf16_strings = re.findall(b'(?:[\x20-\x7e]\x00){6,}', data)

interesting_keywords = [
    'install', 'setup', 'cabinet', 'payload', 'archive', 'compress',
    'infinity', 'erp', 'postgres', 'mysql', 'database', 'sql',
    'firewall', 'netsh', 'taskkill', 'process', 'service',
    'http', 'api', 'cloud', 'server', 'endpoint',
    'whatsApp', 'OTP', 'phone', 'mobile',
    'C:\\', 'Program Files', 'AppData',
    '.exe', '.dll', '.msi', '.cab', '.zip', '.sql',
    'younes', 'mouffok', 'infi', 'so-infi',
    'error', 'exception', 'fail', 'crash',
    'license', 'trial', 'activation', 'register',
]

print("Interesting strings found:")
for s in ascii_strings:
    sl = s.decode('ascii', errors='ignore').lower()
    for kw in interesting_keywords:
        if kw.lower() in sl:
            print(f"  [{kw}] {s.decode('ascii', errors='ignore')}")
            break

for s in utf16_strings:
    try:
        decoded = s.decode('utf-16le', errors='ignore')
        dl = decoded.lower()
        for kw in interesting_keywords:
            if kw.lower() in dl:
                print(f"  [UTF16][{kw}] {decoded}")
                break
    except:
        pass

# Save raw RCDATA for external analysis
print("\n=== RCDATA saved to resource_RT_RCDATA_102_1.bin ===")
print("You can analyze it with: 7z l resource_RT_RCDATA_102_1.bin")
print("Or with: cabextract resource_RT_RCDATA_102_1.bin")

# Also check the VERSION resource
print("\n=== VERSION RESOURCE ===")
with open('resource_RT_VERSION_1_1.bin', 'rb') as f:
    ver_data = f.read()
print(f"Size: {len(ver_data)} bytes")
print(f"First 100 bytes: {ver_data[:100]}")

# Parse VS_VERSION_INFO
if ver_data[:2] == b'\x00\x00':  # Often starts with padding
    # Find the actual version info
    pass

# Try to decode as UTF-16
try:
    print(ver_data.decode('utf-16le', errors='ignore'))
except:
    pass

# Check MANIFEST resource
print("\n=== MANIFEST RESOURCE ===")
with open('resource_RT_MANIFEST_1_1.bin', 'rb') as f:
    man_data = f.read()
print(f"Size: {len(man_data)} bytes")
try:
    print(man_data.decode('utf-8', errors='ignore'))
except:
    pass