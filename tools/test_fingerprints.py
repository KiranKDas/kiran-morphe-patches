#!/usr/bin/env python3
import struct
import zipfile
from pathlib import Path

def test_fingerprints():
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

    fp1_matches = []
    fp2_matches = []

    for i in range(class_defs_size):
        c_idx, access, super_idx, iface_off, src_idx, annot_off, class_data_off, static_values_off = struct.unpack_from('<IIIIIIII', data, class_defs_off + i * 32)
        c_name = types[c_idx] if c_idx < len(types) else ""

        if class_data_off == 0:
            continue

        off = class_data_off
        sf_sz, off = read_uleb128(off)
        if_sz, off = read_uleb128(off)
        dm_sz, off = read_uleb128(off)
        vm_sz, off = read_uleb128(off)
        for _ in range(sf_sz + if_sz):
            _, off = read_uleb128(off)
            _, off = read_uleb128(off)

        for is_vm, count in [(False, dm_sz), (True, vm_sz)]:
            midx = 0
            for _ in range(count):
                diff, off = read_uleb128(off)
                midx += diff
                m_acc, off = read_uleb128(off)
                code_off, off = read_uleb128(off)

                if code_off == 0:
                    continue

                c_type, m_name, ret_type, params = methods[midx]

                reg_size, ins_size, outs_size, tries_size, debug_off, insns_size = struct.unpack_from('<HHHHII', data, code_off)
                insns_bytes = data[code_off + 16 : code_off + 16 + insns_size * 2]
                u16 = struct.unpack_from(f'<{insns_size}H', insns_bytes)

                m_strings = set()
                m_invokes = []
                idx = 0
                while idx < len(u16):
                    op = u16[idx] & 0xFF
                    if op == 0x1A and idx + 1 < len(u16):
                        sidx = u16[idx + 1]
                        if sidx < len(strings):
                            m_strings.add(strings[sidx])
                        idx += 2
                    elif op == 0x1B and idx + 2 < len(u16):
                        sidx = u16[idx + 1] | (u16[idx + 2] << 16)
                        if sidx < len(strings):
                            m_strings.add(strings[sidx])
                        idx += 3
                    elif op in (0x6E, 0x6F, 0x70, 0x71, 0x72) and idx + 1 < len(u16):
                        mcall = u16[idx + 1]
                        if mcall < len(methods):
                            m_invokes.append((idx, methods[mcall]))
                        idx += 3
                    else:
                        idx += 1

                # Check FP1:
                if "https://api.redgifs.com" in m_strings and "redgifs_access_token" in m_strings and ret_type == "Ljava/lang/String;" and len(params) == 0:
                    fp1_matches.append((c_type, m_name, ret_type, params, m_invokes))

                # Check FP2:
                if "Authorization" in m_strings and "redgifs_access_token" in m_strings:
                    fp2_matches.append((c_type, m_name, ret_type, params, m_invokes))

    print(f"FP1 (Token Getter) matches: {len(fp1_matches)}")
    for c, m, ret, p, inv in fp1_matches:
        print(f"  {c}->{m}{tuple(p)}{ret}")

    print(f"\nFP2 (Interceptor) matches: {len(fp2_matches)}")
    for c, m, ret, p, inv in fp2_matches:
        print(f"  {c}->{m}{tuple(p)}{ret}")
        get_string_calls = [iv for iv in inv if iv[1][1] == "getString" and "SharedPreferences" in iv[1][0]]
        print(f"    SharedPreferences.getString calls: {len(get_string_calls)}")

if __name__ == "__main__":
    test_fingerprints()