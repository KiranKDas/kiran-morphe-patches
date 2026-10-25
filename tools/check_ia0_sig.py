#!/usr/bin/env python3
import struct
import zipfile
from pathlib import Path

def check_all_ia0():
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
            
            for is_virtual, count in [(False, dm_sz), (True, vm_sz)]:
                midx = 0
                for _ in range(count):
                    diff, off = read_uleb128(off)
                    midx += diff
                    m_acc, off = read_uleb128(off)
                    code_off, off = read_uleb128(off)
                    c_name, m_name, ret_type, params = methods[midx]
                    print(f"[{'V' if is_virtual else 'D'}] {m_name}({', '.join(params)}) -> {ret_type} (access=0x{m_acc:x})")

if __name__ == "__main__":
    check_all_ia0()