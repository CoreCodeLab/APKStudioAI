import re
import sys

with open(r'C:\Users\FaarusDz\Downloads\Telegram Desktop\InfinityERP_Full_Setup.exe', 'rb') as f:
    data = f.read()

# Find all ASCII strings >= 6 chars
ascii_strings = re.findall(b'[\x20-\x7e]{6,}', data)
# Find all UTF-16LE strings >= 6 chars
utf16_strings = re.findall(b'(?:[\x20-\x7e]\x00){6,}', data)

print('=== ASCII STRINGS ===')
for s in ascii_strings:
    print(s.decode('ascii', errors='ignore'))

print('\n=== UTF-16 STRINGS ===')
for s in utf16_strings:
    try:
        print(s.decode('utf-16le', errors='ignore'))
    except:
        pass