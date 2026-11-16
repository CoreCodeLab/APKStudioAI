import re
import sys

with open(r'C:\Users\FaarusDz\Downloads\Telegram Desktop\InfinityERP_Full_Setup.exe', 'rb') as f:
    data = f.read()

# Find all ASCII strings >= 6 chars
ascii_strings = re.findall(b'[\x20-\x7e]{6,}', data)
# Find all UTF-16LE strings >= 6 chars
utf16_strings = re.findall(b'(?:[\x20-\x7e]\x00){6,}', data)

# Filter for interesting patterns
keywords = [
    'http', 'https', 'ftp', 'api', 'endpoint', 'server', 'cloud',
    'registry', 'HKEY', 'SOFTWARE', 'CurrentVersion', 'Run',
    'error', 'exception', 'fail', 'crash', 'debug', 'trace',
    'password', 'secret', 'token', 'key', 'auth', 'license',
    'install', 'uninstall', 'setup', 'configure', 'update',
    'whatsApp', 'OTP', 'SMS', 'phone', 'mobile',
    'postgres', 'mysql', 'database', 'sql', 'port',
    'firewall', 'netsh', 'taskkill', 'process',
    'C:\\', 'Program Files', 'AppData', 'LocalAppData',
    'Infinity', 'ERP', 'YOUNES', 'MOUFFOK', 'ISS',
    '.site', '.com', '.net', '.org', '.online',
    'so-infi', 'infi-', 'younesmouffok', 'younesnasro',
    'bootstrap', 'installer', 'uninstaller',
]

print('=== FILTERED INTERESTING STRINGS ===')
all_strings = []
for s in ascii_strings:
    decoded = s.decode('ascii', errors='ignore')
    all_strings.append(decoded)
for s in utf16_strings:
    try:
        decoded = s.decode('utf-16le', errors='ignore')
        all_strings.append(decoded)
    except:
        pass

# Filter and deduplicate
seen = set()
for s in all_strings:
    sl = s.lower()
    for kw in keywords:
        if kw.lower() in sl and s not in seen:
            seen.add(s)
            print(f"[{kw}] {s}")
            break

print('\n=== ALL UNIQUE STRINGS (first 1000) ===')
count = 0
for s in all_strings:
    if s not in seen:
        seen.add(s)
        print(s)
        count += 1
        if count >= 1000:
            break