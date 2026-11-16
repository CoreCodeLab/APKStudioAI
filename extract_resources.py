import struct
import os

with open(r'C:\Users\FaarusDz\Downloads\Telegram Desktop\InfinityERP_Full_Setup.exe', 'rb') as f:
    data = f.read()

print(f"File size: {len(data)} bytes (0x{len(data):X})")

# Parse PE header to find resource directory
# DOS header
dos_header = data[:64]
e_lfanew = struct.unpack('<I', dos_header[0x3C:0x40])[0]
print(f"PE header offset: 0x{e_lfanew:X}")

# PE signature
pe_sig = data[e_lfanew:e_lfanew+4]
print(f"PE signature: {pe_sig}")

# COFF header
coff = data[e_lfanew+4:e_lfanew+24]
machine, num_sections, timestamp, sym_table_ptr, num_symbols, opt_header_size, characteristics = struct.unpack('<HHIIIHH', coff[:20])
print(f"Machine: 0x{machine:X}, Sections: {num_sections}, OptHeaderSize: {opt_header_size}")

# Optional header
opt_start = e_lfanew + 24
opt_header = data[opt_start:opt_start+opt_header_size]

# Data directories start at offset 96 in PE32+ optional header
# For PE32+, optional header is 240 bytes, data directories at offset 112
data_dirs_start = opt_start + 112  # PE32+ data directories offset

# Resource directory is directory index 2
res_dir_offset = data_dirs_start + 2 * 8
res_rva, res_size = struct.unpack('<II', data[res_dir_offset:res_dir_offset+8])
print(f"Resource directory: RVA 0x{res_rva:X}, Size: {res_size}")

# Convert RVA to file offset - need section headers
section_headers_start = opt_start + opt_header_size
print(f"Section headers at: 0x{section_headers_start:X}")

# Find .rsrc section
for i in range(num_sections):
    sh = data[section_headers_start + i*40:section_headers_start + (i+1)*40]
    name = sh[:8].rstrip(b'\x00')
    virt_size, virt_addr, raw_size, raw_ptr, reloc_ptr, linenum_ptr, num_reloc, num_linenum, characteristics = struct.unpack('<IIIIIIHHI', sh[8:40])
    print(f"  Section {i}: {name.decode()} - VA: 0x{virt_addr:X}, Raw: 0x{raw_ptr:X}, Size: {virt_size}")
    if name.startswith(b'.rsrc') or b'rsrc' in name.lower():
        rsrc_section = (virt_addr, raw_ptr, virt_size, raw_size)
        print(f"  -> This is the resource section!")

if 'rsrc_section' in locals():
    virt_addr, raw_ptr, virt_size, raw_size = rsrc_section
    # Resource directory is at res_rva relative to image base
    # File offset = raw_ptr + (res_rva - virt_addr)
    res_file_offset = raw_ptr + (res_rva - virt_addr)
    print(f"Resource directory file offset: 0x{res_file_offset:X}")

    # Parse resource directory
    res_data = data[res_file_offset:res_file_offset+res_size]

    # Resource directory table
    chars, time, major, minor, num_named, num_id = struct.unpack('<IIHHHH', res_data[:16])
    print(f"Resource dir: {num_named} named, {num_id} ID entries")

    entries = []
    for i in range(num_named + num_id):
        entry_offset = 16 + i * 8
        if entry_offset + 8 > len(res_data):
            break
        name_or_id, offset = struct.unpack('<II', res_data[entry_offset:entry_offset+8])
        is_named = (name_or_id & 0x80000000) != 0
        entries.append((name_or_id & 0x7FFFFFFF, offset, is_named))

    print("\n=== TOP-LEVEL RESOURCE TYPES ===")
    resource_types = {
        1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU', 5: 'RT_DIALOG',
        6: 'RT_STRING', 7: 'RT_FONTDIR', 8: 'RT_FONT', 9: 'RT_ACCELERATOR',
        10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE', 12: 'RT_GROUP_CURSOR',
        14: 'RT_GROUP_ICON', 16: 'RT_VERSION', 17: 'RT_DLGINCLUDE',
        19: 'RT_PLUGPLAY', 20: 'RT_VXD', 21: 'RT_ANICURSOR', 22: 'RT_ANIICON',
        23: 'RT_HTML', 24: 'RT_MANIFEST'
    }

    for name_id, offset, is_named in entries:
        if offset & 0x80000000:  # Subdirectory
            subdir_offset = offset & 0x7FFFFFFF
            subdir_data = res_data[subdir_offset:subdir_offset+16]
            if len(subdir_data) >= 16:
                _, _, _, _, sub_named, sub_id = struct.unpack('<IIHHHH', subdir_data)
                type_name = resource_types.get(name_id, f'TYPE_{name_id}')
                print(f"  Type: {type_name} (ID={name_id}) -> Subdir with {sub_named} named, {sub_id} ID entries")

                # Parse subdirectory entries
                for j in range(sub_named + sub_id):
                    sub_entry_offset = subdir_offset + 16 + j * 8
                    if sub_entry_offset + 8 > len(res_data):
                        break
                    sub_name_id, sub_offset = struct.unpack('<II', res_data[sub_entry_offset:sub_entry_offset+8])
                    is_sub_named = (sub_name_id & 0x80000000) != 0
                    sub_name_id = sub_name_id & 0x7FFFFFFF

                    if sub_offset & 0x80000000:  # Another subdir (language)
                        lang_offset = sub_offset & 0x7FFFFFFF
                        lang_data = res_data[lang_offset:lang_offset+16]
                        if len(lang_data) >= 16:
                            _, _, _, _, lang_named, lang_id = struct.unpack('<IIHHHH', lang_data)
                            for k in range(lang_named + lang_id):
                                lang_entry_offset = lang_offset + 16 + k * 8
                                if lang_entry_offset + 8 > len(res_data):
                                    break
                                _, data_offset = struct.unpack('<II', res_data[lang_entry_offset:lang_entry_offset+8])
                                data_offset &= 0x7FFFFFFF
                                # Data entry: offset, size, codepage, reserved
                                data_entry = res_data[data_offset:data_offset+16]
                                if len(data_entry) >= 16:
                                    data_rva, data_size, codepage, _ = struct.unpack('<IIII', data_entry)
                                    file_off = raw_ptr + (data_rva - virt_addr)
                                    type_name = resource_types.get(name_id, f'TYPE_{name_id}')
                                    print(f"    ID={sub_name_id}, Lang={lang_id}: RVA=0x{data_rva:X}, Size={data_size}, FileOff=0x{file_off:X}")

                                    # Extract resource data
                                    if file_off + data_size <= len(data):
                                        resource_bytes = data[file_off:file_off+data_size]
                                        # Save to file
                                        out_name = f"resource_{type_name}_{sub_name_id}_{lang_id}.bin"
                                        with open(out_name, 'wb') as out:
                                            out.write(resource_bytes)
                                        print(f"      -> Saved to {out_name} ({len(resource_bytes)} bytes)")

# Check for appended data after PE
print(f"\n=== CHECKING FOR APPENDED DATA ===")
# Find end of last section
max_end = 0
for i in range(num_sections):
    sh = data[section_headers_start + i*40:section_headers_start + (i+1)*40]
    raw_ptr = struct.unpack('<I', sh[20:24])[0]
    raw_size = struct.unpack('<I', sh[16:20])[0]
    max_end = max(max_end, raw_ptr + raw_size)

print(f"Last section ends at offset: 0x{max_end:X} ({max_end})")
print(f"File size: 0x{len(data):X} ({len(data)})")

if max_end < len(data):
    appended = len(data) - max_end
    print(f"APPENDED DATA: {appended} bytes (0x{appended:X})")
    appended_data = data[max_end:]
    # Check for signatures
    if appended_data[:4] == b'MSCF':
        print("  -> MSCF (CAB) signature found!")
    elif appended_data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        print("  -> OLE/MSO signature found!")
    elif appended_data[:4] == b'PK\x03\x04':
        print("  -> ZIP signature found!")
    else:
        print(f"  -> First bytes: {appended_data[:32]}")

    # Save appended data
    with open('appended_data.bin', 'wb') as f:
        f.write(appended_data)
    print(f"  -> Saved appended data to appended_data.bin")

print("\n=== DONE ===")