#!/usr/bin/env python3
import struct
import zipfile
from pathlib import Path

def dump_c():
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

    strings = []
    string_offsets = struct.unpack_from(f'<{string_ids_size}I', data, string_ids_off)
    for off in string_offsets:
        utf16_size, str_off = read_uleb128(off)
        null_idx = data.find(b'\x00', str_off)
        s = data[str_off:].decode('utf-8', errors='replace') if null_idx == -1 else data[str_off:null_idx].decode('utf-8', errors='replace')
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
        if c_name == "Lia0;":
            off = class_data_off
            sf_sz, off = read_uleb128(off)
            if_sz, off = read_uleb128(off)
            dm_sz, off = read_uleb128(off)
            vm_sz, off = read_uleb128(off)
            for _ in range(sf_sz + if_sz):
                _, off = read_uleb128(off)
                _, off = read_uleb128(off)
            
            midx = 0
            for _ in range(dm_sz):
                diff, off = read_uleb128(off)
                midx += diff
                m_acc, off = read_uleb128(off)
                code_off, off = read_uleb128(off)
                if methods[midx][1] == 'c':
                    reg_size, ins_size, outs_size, tries_size, debug_off, insns_size = struct.unpack_from('<HHHHII', data, code_off)
                    insns_bytes = data[code_off + 16 : code_off + 16 + insns_size * 2]
                    u16 = struct.unpack_from(f'<{insns_size}H', insns_bytes)
                    print(f"Lia0;->c (reg={reg_size}, ins={ins_size}, outs={outs_size}, insns={insns_size}):")
                    idx = 0
                    while idx < len(u16):
                        inst = u16[idx]
                        op = inst & 0xFF
                        if op in (0x1A, 0x1B):
                            sidx = u16[idx + 1] if op == 0x1A else (u16[idx + 1] | (u16[idx + 2] << 16))
                            sval = strings[sidx] if sidx < len(strings) else ""
                            print(f"  [0x{idx:04x}] const-string v{(inst >> 8)}, \"{sval}\"")
                            idx += 2 if op == 0x1A else 3
                        elif op in (0x6E, 0x6F, 0x70, 0x71, 0x72):
                            mcall = u16[idx + 1]
                            cname, mname = methods[mcall]
                            print(f"  [0x{idx:04x}] invoke {cname}->{mname}")
                            idx += 3
                        elif op in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B): # if-*
                            target = idx + struct.unpack('<h', struct.pack('<H', u16[idx + 1]))[0]
                            print(f"  [0x{idx:04x}] if (op 0x{op:02x}) -> 0x{target:04x}")
                            idx += 2
                        elif op in (0x28, 0x29): # goto
                            target = idx + (struct.unpack('<b', struct.pack('<B', inst >> 8))[0] if op == 0x28 else struct.unpack('<h', struct.pack('<H', u16[idx + 1]))[0])
                            print(f"  [0x{idx:04x}] goto -> 0x{target:04x}")
                            idx += 1 if op == 0x28 else 2
                        elif op == 0x0E: # return-void
                            print(f"  [0x{idx:04x}] return-void")
                            idx += 1
                        elif op in (0x0F, 0x10, 0x11): # return
                            print(f"  [0x{idx:04x}] return v{(inst >> 8)}")
                            idx += 1
                        else:
                            idx += 1

if __name__ == "__main__":
    dump_c()