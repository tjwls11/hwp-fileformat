import sys, struct, zlib, olefile, argparse

# ------------------ 레코드 파서 ------------------

REC_TAG_BITS = (0, 10)
REC_LEVEL_BITS = (10, 10)
REC_SIZE_BITS = (20, 12)
TAG_PARA_TEXT = 67
TAG_PARA_CHAR_SHAPE = 68

def bits(v, o, n): return (v >> o) & ((1 << n) - 1)

def parse_records(raw: bytes):
    """압축 해제된 Section 바이트열 → (tag, level, payload) 리스트"""
    recs = []; off = 0; n = len(raw)
    while off < n:
        if off + 4 > n: break
        h = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        tag = bits(h, *REC_TAG_BITS)
        lvl = bits(h, *REC_LEVEL_BITS)
        sz  = bits(h, *REC_SIZE_BITS)
        if sz == 0xFFF:  # 확장 길이
            sz = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        data = raw[off:off+sz]; off += sz
        recs.append((tag, lvl, data))
    return recs

def build_records(recs):
    """(tag, level, payload) 리스트 → 직렬화 바이트열"""
    out = bytearray()
    for tag, lvl, data in recs:
        sz = len(data)
        if sz < 0xFFF:
            h = (tag & 0x3FF) | ((lvl & 0x3FF) << 10) | ((sz & 0xFFF) << 20)
            out += struct.pack("<I", h)
        else:
            h = (tag & 0x3FF) | ((lvl & 0x3FF) << 10) | (0xFFF << 20)
            out += struct.pack("<I", h)
            out += struct.pack("<I", sz)
        out += data
    return bytes(out)


def redact_para_text(data: bytes, old: str, new: str):
    """PARA_TEXT(67)에서 old→new 치환. delta=문자 길이 변화"""
    old_b = old.encode("utf-16le")
    new_b = new.encode("utf-16le")
    if old_b not in data:
        return data, 0, None
    # 위치 찾기 (문자 단위 오프셋)
    txt = data.decode("utf-16le", errors="ignore")
    hit_pos = txt.find(old)
    patched = data.replace(old_b, new_b, 1)  # 첫 매치만 교체
    delta = (len(new_b) - len(old_b)) // 2   # 문자 수 변화
    return patched, delta, hit_pos

def adjust_para_char_shape(data: bytes, hit_offset: int, delta: int):
    """PARA_CHAR_SHAPE(68)의 pos 값 보정"""
    out = bytearray()
    for i in range(0, len(data), 4):
        if i + 4 > len(data): break
        pos, sid = struct.unpack_from("<HH", data, i)
        if hit_offset is not None and pos > hit_offset:
            pos += delta
        out += struct.pack("<HH", pos, sid)
    return bytes(out)

def process_records(records, old, new):
    out_recs = []
    last_delta = 0
    hit_offset = None
    for tag, lvl, data in records:
        if tag == TAG_PARA_TEXT:
            new_data, delta, hit = redact_para_text(data, old, new)
            out_recs.append((tag, lvl, new_data))
            if delta != 0:
                last_delta = delta
                hit_offset = hit
        elif tag == TAG_PARA_CHAR_SHAPE and last_delta != 0:
            adj = adjust_para_char_shape(data, hit_offset, last_delta)
            out_recs.append((tag, lvl, adj))
        else:
            out_recs.append((tag, lvl, data))
    return out_recs

# ------------------ FileHeader ------------------

def read_fileheader(ole: olefile.OleFileIO):
    data = ole.openstream("FileHeader").read()
    sig = data[0:32].rstrip(b"\x00").decode("ascii", "ignore")
    ver_u32 = struct.unpack("<I", data[32:36])[0]
    ver = f"{(ver_u32>>24)&0xFF}.{(ver_u32>>16)&0xFF}.{(ver_u32>>8)&0xFF}.{ver_u32&0xFF}"
    flag0 = struct.unpack("<I", data[36:40])[0]
    packed    = bool(flag0 & 0b1)
    encrypted = bool(flag0 & 0b10)
    return sig, ver, flag0, packed, encrypted

# ------------------ 메인 ------------------

def main(path, old, new, out_path):
    ole = olefile.OleFileIO(path)
    if not ole.exists("FileHeader"):
        print("[!] FileHeader 없음"); return
    sig, ver, flag0, packed, encrypted = read_fileheader(ole)
    print(f"[+] Signature={sig}, Version={ver}, packed={packed}, encrypted={encrypted}")

    if encrypted:
        print("[!] 암호 문서는 처리 불가."); return

    # Section0만 대상으로 (데모)
    name = "BodyText/Section0"
    if not ole.exists(name):
        print("[!] BodyText/Section0 없음"); return
    raw = ole.openstream(name).read()
    dec = zlib.decompress(raw, -15) if packed else raw

    # 파싱 → 치환 → 재조립
    recs = parse_records(dec)
    patched_recs = process_records(recs, old, new)
    new_dec = build_records(patched_recs)
    new_raw = zlib.compress(new_dec) if packed else new_dec

    # 결과 저장 (섹션만 따로 저장)
    with open(out_path, "wb") as f:
        f.write(new_raw)
    print(f"[+] Section0 patched 저장 완료: {out_path}")
    print("    (OLE 전체에 다시 넣으려면 OLE writer 필요)")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--out", default="Section0_patched.bin")
    args = ap.parse_args()
    main(args.file, args.old, args.new, args.out)
