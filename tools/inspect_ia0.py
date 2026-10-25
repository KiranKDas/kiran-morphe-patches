#!/usr/bin/env python3
import struct
import zipfile
from pathlib import Path

def inspect_ia0():
    apk_path = Path("C:/source/patches/Infinity+-v8.3.4.apk")
    with zipfile.ZipFile(apk_path, "r") as z:
        data = z.read("classes.dex")

    string_ids_size, string_ids_off = struct.unpack_from('<II', data, 56)
    type_ids_size, type_ids_off = struct.unpack_from('<II', data, 64)
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

    types = [strings[idx] for idx in struct.unpack_from(f'<{type_ids_size}I', data, type_ids_off) if idx < len(strings)]

    methods = []
    for i in range(method_ids_size):
        c_idx, p_idx, n_idx = struct.unpack_from('<HHI', data, method_ids_off + i * 8)
        c_name = types[c_idx] if c_idx < len(types) else f"type_{c_idx}"
        m_name = strings[n_idx] if n_idx < len(strings) else f"str_{n_idx}"
        methods.append((c_name, m_name))

    for i in range(class_defs_size):
        c_idx, access, super_idx, iface_off, src_idx, annot_off, class_data_off, static_values_off = struct.unpack_from('<IIIIIIII', data, class_defs_off + i * 32)
        c_name = types[c_idx] if c_idx < len(types) else ""

        if c_name != "Lia0;":
            continue

        super_name = types[super_idx] if super_idx != 0xFFFFFFFF and super_idx < len(types) else ""
        print(f"FOUND CLASS Lia0; (super={super_name})")

        # Interfaces
        if iface_off != 0:
            iface_sz = struct.unpack_from('<I', data, iface_off)[0]
            ifaces = [types[idx] for idx in struct.unpack_from(f'<{iface_sz}H', data, iface_off + 4)]
            print(f"INTERFACES: {ifaces}")

        off = class_data_off
        static_fields_size, off = read_uleb128(off)
        instance_fields_size, off = read_uleb128(off)
        direct_methods_size, off = read_uleb128(off)
        virtual_methods_size, off = read_uleb128(off)

        for _ in range(static_fields_size + instance_fields_size):
            _, off = read_uleb128(off)
            _, off = read_uleb128(off)

        def dump_methods(count, cur_off):
            midx = 0
            for _ in range(count):
                diff, cur_off = read_uleb128(cur_off)
                midx += diff
                m_access, cur_off = read_uleb128(cur_off)
                code_off, cur_off = read_uleb128(cur_off)

                if code_off == 0:
                    continue

                m_name = methods[midx][1]
                reg_size, ins_size, outs_size, tries_size, debug_off, insns_size = struct.unpack_from('<HHHHII', data, code_off)
                insns_bytes = data[code_off + 16 : code_off + 16 + insns_size * 2]
                u16 = struct.unpack_from(f'<{insns_size}H', insns_bytes)

                print(f"\n--- Method: {m_name} (midx={midx}, insns_size={insns_size}) ---")
                idx = 0
                while idx < len(u16):
                    inst = u16[idx]
                    opcode = inst & 0xFF
                    if opcode == 0x1A: # const-string
                        str_idx = u16[idx + 1]
                        if str_idx < len(strings):
                            print(f"  [0x{idx:04x}] const-string \"{strings[str_idx]}\"")
                        idx += 2
                    elif opcode == 0x1B: # const-string/jumbo
                        str_idx = u16[idx + 1] | (u16[idx + 2] << 16)
                        if str_idx < len(strings):
                            print(f"  [0x{idx:04x}] const-string/jumbo \"{strings[str_idx]}\"")
                        idx += 3
                    elif opcode in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
                        m_call_idx = u16[idx + 1]
                        if m_call_idx < len(methods):
                            print(f"  [0x{idx:04x}] invoke {methods[m_call_idx][0]}->{methods[m_call_idx][1]}")
                        idx += 3
                    else:
                        idx += 1
            return cur_off

        cur = dump_methods(direct_methods_size, off)
        dump_methods(virtual_methods_size, cur)

if __name__ == "__main__":
    inspect_ia0()