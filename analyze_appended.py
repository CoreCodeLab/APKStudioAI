import struct

# Analyze the appended data (Authenticode signature)
with open('appended_data.bin', 'rb') as f:
    data = f.read()

print(f"Appended data size: {len(data)} bytes (0x{len(data):X})")
print(f"First 64 bytes: {data[:64].hex()}")
print(f"Last 64 bytes: {data[-64:].hex()}")

# Parse PKCS#7 structure (WIN_CERTIFICATE)
# WIN_CERTIFICATE structure:
# dwLength (4), wRevision (2), wCertificateType (2), bCertificate[variable]
if len(data) >= 8:
    dwLength, wRevision, wCertType = struct.unpack('<IHH', data[:8])
    print(f"\nWIN_CERTIFICATE:")
    print(f"  dwLength: {dwLength} (0x{dwLength:X})")
    print(f"  wRevision: {wRevision} (0x{wRevision:X})")
    print(f"  wCertificateType: {wCertType} (0x{wCertType:X}) - 2 = WIN_CERT_TYPE_PKCS_SIGNED_DATA")

    cert_data = data[8:dwLength]
    print(f"  Certificate data: {len(cert_data)} bytes")

    # Check for PKCS#7 OID: 1.2.840.113549.1.7.2 (signedData)
    # DER encoding: 06 09 2a 86 48 86 f7 0d 01 07 02
    pkcs7_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02'
    pos = cert_data.find(pkcs7_oid)
    if pos >= 0:
        print(f"  PKCS#7 signedData OID found at offset {pos}")

    # Look for certificate data
    # Certificate DER: 30 82 ... (SEQUENCE)
    # Search for 30 82
    seq_pos = cert_data.find(b'\x30\x82')
    if seq_pos >= 0:
        print(f"  DER SEQUENCE (certificate) found at offset {seq_pos}")
        # Try to parse length
        if seq_pos + 4 <= len(cert_data):
            length_bytes = cert_data[seq_pos+2:seq_pos+4]
            if length_bytes[0] & 0x80:
                num_len_bytes = length_bytes[0] & 0x7F
                if seq_pos + 4 + num_len_bytes <= len(cert_data):
                    cert_len = int.from_bytes(length_bytes[1:1+num_len_bytes], 'big')
                    print(f"    Certificate length: {cert_len} bytes")

# Also check the original file's certificate directory
with open(r'C:\Users\FaarusDz\Downloads\Telegram Desktop\InfinityERP_Full_Setup.exe', 'rb') as f:
    full_data = f.read()

# The certificate directory was at offset 837632 (0xCC800), size 10640
cert_dir_offset = 837632
cert_dir_size = 10640
cert_dir_data = full_data[cert_dir_offset:cert_dir_offset+cert_dir_size]
print(f"\nCertificate directory from PE: {len(cert_dir_data)} bytes")
print(f"Matches appended data: {cert_dir_data == data}")

# Try to extract and analyze the PNG from RCDATA
print("\n=== PNG ANALYSIS ===")
with open('resource_RT_RCDATA_102_1.bin', 'rb') as f:
    png_data = f.read()

# Check PNG chunks
pos = 8  # Skip signature
while pos < len(png_data):
    if pos + 8 > len(png_data):
        break
    length = struct.unpack('>I', png_data[pos:pos+4])[0]
    chunk_type = png_data[pos+4:pos+8]
    chunk_data = png_data[pos+8:pos+8+length]
    crc = png_data[pos+8+length:pos+8+length+4]
    print(f"  Chunk: {chunk_type.decode('ascii', errors='ignore')}, Length: {length}, CRC: {crc.hex()}")
    if chunk_type == b'IEND':
        break
    pos += 12 + length

# Check for hidden data after IEND
print(f"\nData after IEND: {len(png_data) - pos} bytes")
if pos < len(png_data):
    remaining = png_data[pos:]
    print(f"  First 32 bytes: {remaining[:32].hex()}")
    # Check if it's another PNG or data
    if remaining[:8] == b'\x89PNG\r\n\x1a\n':
        print("  -> Another PNG image appended!")
    elif remaining[:4] == b'MSCF':
        print("  -> CABINET signature found!")
    elif remaining[:4] == b'PK\x03\x04':
        print("  -> ZIP signature found!")