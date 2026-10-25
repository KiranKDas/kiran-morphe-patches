#!/usr/bin/env python3
import os
import struct
import zipfile
from pathlib import Path

def parse_dex_detailed(data):
    if len(data) < 112 or data[:4] != b'dex\n':
        return None
    string_ids_size, string_ids_off = struct.unpack_from('<II', data, 56)
    type_ids_size, type_ids_off = struct.unpack_from('<II', data, 64)
    proto_ids_size, proto_ids_off = struct.unpack_from('<II', data, 72)
    field_ids_size, field_ids_off = struct.unpack_from('<II', data, 80)
    method_ids_size, method_ids_off = struct.unpack_from('<II', data, 88)
    class_defs_size, class_defs_off = struct.unpack_from('<II', data, 96)

    def read_uleb128(off):
        res = 0
        shift = 0
        while True:
            b = data[off]
            off += 1
            res |= (b & 0x7f) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res, off

    # Strings
    strings = []
    string_offsets = struct.unpack_from(f'<{string_ids_size}I', data, string_ids_off)
    for off in string_offsets:
        utf16_size, str_off = read_uleb128(off)
        null_idx = data.find(b'\x00', str_off)
        if null_idx == -1:
            s = data[str_off:].decode('utf-8', errors='replace')
        else:
            s = data[str_off:null_idx].decode('utf-8', errors='replace')
        strings.append(s)

    string_to_idx = {s: i for i, s in enumerate(strings)}

    # Types
    type_descriptor_indices = struct.unpack_from(f'<{type_ids_size}I', data, type_ids_off)
    types = [strings[idx] for idx in type_descriptor_indices if idx < len(strings)]

    # Method IDs: class_idx (H), proto_idx (H), name_idx (I)
    methods = []
    for i in range(method_ids_size):
        c_idx, p_idx, n_idx = struct.unpack_from('<HHI', data, method_ids_off + i * 8)
        c_name = types[c_idx] if c_idx < len(types) else f"type_{c_idx}"
        m_name = strings[n_idx] if n_idx < len(strings) else f"str_{n_idx}"
        methods.append((c_name, m_name))

    target_strings = [
        "https://api.redgifs.com",
        "redgifs_access_token",
        "https://media.redgifs.com/",
        "redgifs.com",
        "automatically_try_redgifs",
        "featuredGif",
        "getFeaturedGif"
    ]
    target_string_indices = {string_to_idx[s]: s for s in target_strings if s in string_to_idx}

    print(f"Target string indices count: {len(target_string_indices)}")

    matches = []
    for i in range(class_defs_size):
        c_idx, access, super_idx, iface_off, src_idx, annot_off, class_data_off, static_values_off = struct.unpack_from('<IIIIIIII', data, class_defs_off + i * 32)
        c_name = types[c_idx] if c_idx < len(types) else f"type_{c_idx}"
        super_name = types[super_idx] if super_idx != 0xFFFFFFFF and super_idx < len(types) else ""
        src_file = strings[src_idx] if src_idx != 0xFFFFFFFF and src_idx < len(strings) else ""

        if class_data_off == 0:
            continue

        off = class_data_off
        static_fields_size, off = read_uleb128(off)
        instance_fields_size, off = read_uleb128(off)
        direct_methods_size, off = read_uleb128(off)
        virtual_methods_size, off = read_uleb128(off)

        for _ in range(static_fields_size):
            _, off = read_uleb128(off)
            _, off = read_uleb128(off)
        for _ in range(instance_fields_size):
            _, off = read_uleb128(off)
            _, off = read_uleb128(off)

        def scan_methods(count, current_off):
            method_idx = 0
            for _ in range(count):
                diff, current_off = read_uleb128(current_off)
                method_idx += diff
                m_access, current_off = read_uleb128(current_off)
                code_off, current_off = read_uleb128(current_off)

                if code_off == 0:
                    continue

                m_def = methods[method_idx] if method_idx < len(methods) else ("unknown", f"m_{method_idx}")
                
                reg_size, ins_size, outs_size, tries_size, debug_off, insns_size = struct.unpack_from('<HHHHII', data, code_off)
                insns_bytes = data[code_off + 16 : code_off + 16 + insns_size * 2]
                
                u16 = struct.unpack_from(f'<{insns_size}H', insns_bytes)
                matched_strings = []
                invoked_methods = []

                idx = 0
                while idx < len(u16):
                    inst = u16[idx]
                    opcode = inst & 0xFF
                    if opcode == 0x1A: # const-string
                        if idx + 1 < len(u16):
                            str_idx = u16[idx + 1]
                            if str_idx in target_string_indices:
                                matched_strings.append(target_string_indices[str_idx])
                        idx += 2
                    elif opcode == 0x1B: # const-string/jumbo
                        if idx + 2 < len(u16):
                            str_idx = u16[idx + 1] | (u16[idx + 2] << 16)
                            if str_idx in target_string_indices:
                                matched_strings.append(target_string_indices[str_idx])
                        idx += 3
                    elif opcode in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78): # invokes
                        if idx + 1 < len(u16):
                            midx = u16[idx + 1]
                            if midx < len(methods):
                                invoked_methods.append(methods[midx])
                        idx += 3
                    else:
                        idx += 1

                if matched_strings:
                    matches.append({
                        "class": c_name,
                        "super": super_name,
                        "src": src_file,
                        "method": m_def[1],
                        "strings": matched_strings,
                        "invokes": invoked_methods[:15]
                    })

            return current_off

        off = scan_methods(direct_methods_size, off)
        off = scan_methods(virtual_methods_size, off)

    return matches

def main():
    apk_candidates = [
        Path("C:/source/patches/Infinity+-v8.3.4.apk"),
        Path("Infinity+-v8.3.4.apk"),
        Path("../Infinity+-v8.3.4.apk")
    ]
    apk_path = None
    for cand in apk_candidates:
        if cand.is_file():
            apk_path = cand
            break

    if not apk_path:
        print(f"ERROR: Target APK not found in candidates: {apk_candidates}")
        return

    with zipfile.ZipFile(apk_path, "r") as z:
        for dex_name in [n for n in z.namelist() if n.endswith(".dex")]:
            print(f"\n==================== {dex_name} ====================")
            data = z.read(dex_name)
            matches = parse_dex_detailed(data)
            if not matches:
                continue
            print(f"Total matching methods in {dex_name}: {len(matches)}\n")
            for m in matches:
                print(f"CLASS:   {m['class']} (super={m['super']}, src={m['src']})")
                print(f"METHOD:  {m['method']}")
                print(f"STRINGS: {m['strings']}")
                print("INVOKED METHODS:")
                for c, meth in m['invokes']:
                    print(f"   -> {c}->{meth}")
                print("-" * 60)

if __name__ == "__main__":
    main()