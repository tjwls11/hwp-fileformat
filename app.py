import sys, struct, zlib, argparse, olefile

# ------------------ 레코드 파서 ------------------
REC_TAG_BITS = (0, 10)
REC_LEVEL_BITS = (10, 10)
REC_SIZE_BITS = (20, 12)
TAG_PARA_TEXT = 67

def bits(v, o, n):
    return (v >> o) & ((1 << n) - 1)

def parse_records(raw: bytes):
    recs, off, n = [], 0, len(raw)
    while off < n:
        if off + 4 > n:
            break
        h = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        tag = bits(h, *REC_TAG_BITS)
        lvl = bits(h, *REC_LEVEL_BITS)
        sz = bits(h, *REC_SIZE_BITS)
        if sz == 0xFFF:
            sz = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        data = raw[off:off+sz]; off += sz
        recs.append((tag, lvl, data))
    return recs

# ------------------ 텍스트 처리 ------------------
def clean_para_text(data: bytes):
    """67번 레코드에서 본문 텍스트만 추출 (제어코드 제거)"""
    chars = []
    for i in range(0, len(data), 2):
        if i + 2 > len(data):
            break
        code = struct.unpack_from("<H", data, i)[0]
        if (
            0x0020 <= code <= 0x007E   # ASCII
            or 0xAC00 <= code <= 0xD7A3  # 한글
            or 0x3130 <= code <= 0x318F  # 한글 자모
            or 0x1100 <= code <= 0x11FF  # 호환 자모
        ):
            chars.append(chr(code))
    return "".join(chars)

def extract_text_from_records(records):
    texts = []
    for tag, lvl, data in records:
        if tag == TAG_PARA_TEXT:
            txt = clean_para_text(data)
            if txt.strip():
                texts.append(txt)
    return texts

# ------------------ FileHeader ------------------
def read_fileheader(ole: olefile.OleFileIO):
    data = ole.openstream("FileHeader").read()
    if not data or len(data) < 40:
        raise ValueError(f"FileHeader 스트림이 너무 짧음 (읽은 크기={len(data) if data else 0})")
    sig = data[0:32].rstrip(b"\x00").decode("ascii", "ignore")
    ver_u32 = struct.unpack("<I", data[32:36])[0]
    ver = f"{(ver_u32>>24)&0xFF}.{(ver_u32>>16)&0xFF}.{(ver_u32>>8)&0xFF}.{ver_u32&0xFF}"
    flag0 = struct.unpack("<I", data[36:40])[0]
    packed = bool(flag0 & 0b1)
    encrypted = bool(flag0 & 0b10)
    return sig, ver, flag0, packed, encrypted

# ------------------ 메인 ------------------
def main(path):
    ole = olefile.OleFileIO(path)

    sig, ver, flag0, packed, encrypted = read_fileheader(ole)
    print(f"[+] Signature={sig}, Version={ver}, packed={packed}, encrypted={encrypted}")

    if encrypted:
        print("[!] 암호 문서는 처리 불가.")
        return

    raw = ole.openstream("BodyText/Section0").read()
    try:
        dec = zlib.decompress(raw, -15)
        print(f"[DEBUG] 압축 해제 성공: {len(raw)} → {len(dec)} bytes")
    except zlib.error:
        dec = raw
        print(f"[DEBUG] 압축 아님: {len(raw)} bytes 그대로 사용")

    recs = parse_records(dec)
    texts = extract_text_from_records(recs)

    print("=== 추출된 텍스트 ===")
    for t in texts:
        print(t)

# ------------------ 실행 ------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    args = ap.parse_args()
    main(args.file)
