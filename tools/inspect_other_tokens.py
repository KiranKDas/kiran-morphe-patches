#!/usr/bin/env python3
import struct
import zipfile
from pathlib import Path

def inspect_other_tokens():
    apk_path = Path("C:/source/patches/Infinity+-v8.3.4.apk")
    with zipfile.ZipFile(apk_path, "r") as z:
        data = z.read("classes.dex")

    string_ids_size, string_ids_off = struct.unpack_from('<II', data, 56)
    type_ids_size, type_ids_off = struct.unpack_from('<II', data, 64)
    proto_ids_size, proto_ids_off = struct.unpack_from('<II', data, 72)
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

    protos = []
    for i in range(proto_ids_size):
        shorty_idx, return_type_idx, params_off = struct.unpack_from('<III', data, proto_ids_off + i * 12)
        ret_type = types[return_type_idx]
        params = []
        if params_off != 0:
            sz = struct.unpack_from('<I', data, params_off)[0]
            params = [types[pidx] for pidx in struct.unpack_from(f'<{sz}H', data, params_off + 4)]
        protos.append((ret_type, params))

    methods = []
    for i in range(method_ids_size):
        c_idx, p_idx, n_idx = struct.unpack_from('<HHI', data, method_ids_off + i * 8)
        c_name = types[c_idx] if c_idx < len(types) else f"type_{c_idx}"
        m_name = strings[n_idx] if n_idx < len(strings) else f"str_{n_idx}"
        ret_type, params = protos[p_idx]
        methods.append((c_name, m_name, ret_type, params))

    targets = [("Ldg6;", "Q"), ("Lkl6;", "q"), ("Ln5;", "run"), ("Lro2;", "I")]

    for i in range(class_defs_size):
        c_idx, access, super_idx, iface_off, src_idx, annot_off, class_data_off, static_values_off = struct.unpack_from('<IIIIIIII', data, class_defs_off + i * 32)
        c_name = types[c_idx] if c_idx < len(types) else ""

        for target_c, target_m in targets:
            if c_name == target_c:
                off = class_data_off
                sf_sz, off = read_uleb128(off)
                if_sz, off = read_uleb128(off)
                dm_sz, off = read_uleb128(off)
                vm_sz, off = read_uleb128(off)
                for _ in range(sf_sz + if_sz):
                    _, off = read_uleb128(off)
                    _, off = read_uleb128(off)
                
                midx = 0
                for count in [dm_sz, vm_sz]:
                    for _ in range(count):
                        diff, off = read_uleb128(off)
                        midx += diff
                        m_acc, off = read_uleb128(off)
                        code_off, off = read_uleb128(off)
                        if code_off != 0 and methods[midx][1] == target_m:
                            print(f"\n{c_name}->{target_m}: {methods[midx][2]} params={methods[midx][3]}")
                            reg_size, ins_size, outs_size, tries_size, debug_off, insns_size = struct.unpack_from('<HHHHII', data, code_off)
                            insns_bytes = data[code_off + 16 : code_off + 16 + insns_size * 2]
                            u16 = struct.unpack_from(f'<{insns_size}H', insns_bytes)
                            for idx in range(len(u16)):
                                op = u16[idx] & 0xFF
                                if op in (0x1A, 0x1B) and idx + 1 < len(u16):
                                    sidx = u16[idx + 1] if op == 0x1A else (u16[idx + 1] | (u16[idx + 2] << 16))
                                    if sidx < len(strings):
                                        s = strings[sidx]
                                        if any(k in s.lower() for k in ['redgif', 'token', 'http', 'api']):
                                            print(f"  [0x{idx:04x}] const-string \"{s}\"")
                                elif op in (0x6E, 0x6F, 0x70, 0x71, 0x72) and idx + 1 < len(u16):
                                    mcall = u16[idx + 1]
                                    if mcall < len(methods):
                                        c, m, ret, p = methods[mcall]
                                        if any(k in c.lower() or k in m.lower() for k in ['token', 'ia0', 'redgif', 'pref']):
                                            print(f"  [0x{idx:04x}] invoke {c}->{m}")

if __name__ == "__main__":
    inspect_other_tokens()