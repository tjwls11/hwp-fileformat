import sys, struct, zlib, argparse, olefile, os

# ------------------ 레코드 파서 ------------------
REC_TAG_BITS = (0, 10)
REC_LEVEL_BITS = (10, 10)
REC_SIZE_BITS = (20, 12)

TAG_PARA_TEXT = 67
TAG_PARA_CHAR_SHAPE = 68
TAG_PARA_LINESEG = 70
TAG_PARARANGE = 71
TAG_PARALIST = 73
TAG_PARAUNKNOWN74 = 74
TAG_PARAUNKNOWN75 = 75

def bits(v, o, n):
    return (v >> o) & ((1 << n) - 1)

def parse_records(raw: bytes):
    recs, off, n = [], 0, len(raw)
    while off < n:
        if off + 4 > n: break
        h = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        tag = bits(h, *REC_TAG_BITS)
        lvl = bits(h, *REC_LEVEL_BITS)
        sz = bits(h, *REC_SIZE_BITS)
        ext = False
        if sz == 0xFFF:
            sz = struct.unpack("<I", raw[off:off+4])[0]; off += 4
            ext = True
        data = raw[off:off+sz]; off += sz
        recs.append((tag, lvl, data, ext))
    return recs

def build_records(recs):
    out = bytearray()
    for tag, lvl, data, ext in recs:
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

# ------------------ 텍스트 치환 ------------------
def replace_in_para_text(data: bytes, old: str, new: str):
    old_b = old.encode("utf-16le")
    new_b = new.encode("utf-16le")

    if old_b not in data:
        return data, 0, None, 0

    # count 읽기
    count = struct.unpack_from("<H", data, 0)[0]

    # 본문 (앞 4바이트 이후)에서 교체
    body = data[4:]
    patched = body.replace(old_b, new_b, 1)

    delta = (len(new_b) - len(old_b)) // 2
    new_count = count + delta

    # 새 데이터 조립
    new_data = struct.pack("<H", new_count) + data[2:4] + patched

    print(f"[DEBUG] TAG67 count 업데이트: {count} → {new_count} (delta={delta})")

    hit_pos = 0
    return new_data, delta, hit_pos, 1

def adjust_para_char_shape(data: bytes, hit_offset: int, delta: int):
    out = bytearray()
    for i in range(0, len(data), 4):
        if i+4 > len(data): break
        pos, sid = struct.unpack_from("<HH", data, i)
        if hit_offset is not None and pos > hit_offset:
            pos += delta
        out += struct.pack("<HH", pos, sid)
    return bytes(out)

def adjust_para_line_seg(data: bytes, hit_offset: int, delta: int):
    out = bytearray()
    for i in range(0, len(data), 12):
        if i+12 > len(data): break
        pos, vpos, h, toff, flags = struct.unpack_from("<HHHHI", data, i)
        if hit_offset is not None and pos > hit_offset:
            pos += delta
        if hit_offset is not None and toff > hit_offset:
            toff += delta
        out += struct.pack("<HHHHI", pos, vpos, h, toff, flags)
    return bytes(out)

def adjust_para_range(data: bytes, hit_offset: int, delta: int):
    out = bytearray()
    for i in range(0, len(data), 6):
        if i+6 > len(data): break
        start, end, flag = struct.unpack_from("<HHH", data, i)
        if hit_offset is not None and start > hit_offset:
            start += delta
        if hit_offset is not None and end > hit_offset:
            end += delta
        out += struct.pack("<HHH", start, end, flag)
    return bytes(out)

def adjust_generic_pos(data: bytes, hit_offset: int, delta: int):
    out = bytearray()
    for i in range(0, len(data), 2):
        if i+2 > len(data): break
        val = struct.unpack_from("<H", data, i)[0]
        if val != 0xFFFF and hit_offset is not None and val > hit_offset:
            val += delta
        out += struct.pack("<H", val)
    return bytes(out)

def process_records(records, old, new):
    out_recs = []
    last_delta = 0; hit_offset = None; replaced = False
    for tag, lvl, data, ext in records:
        if tag == TAG_PARA_TEXT and not replaced:
            new_data, delta, hit, chg = replace_in_para_text(data, old, new)
            out_recs.append((tag, lvl, new_data, ext))
            if chg:
                replaced = True
                last_delta = delta
                hit_offset = hit
        elif tag == TAG_PARA_CHAR_SHAPE and last_delta != 0:
            out_recs.append((tag, lvl, adjust_para_char_shape(data, hit_offset, last_delta), ext))
        elif tag == TAG_PARA_LINESEG and last_delta != 0:
            out_recs.append((tag, lvl, adjust_para_line_seg(data, hit_offset, last_delta), ext))
        elif tag == TAG_PARARANGE and last_delta != 0:
            out_recs.append((tag, lvl, adjust_para_range(data, hit_offset, last_delta), ext))
        elif tag in (TAG_PARALIST, TAG_PARAUNKNOWN74, TAG_PARAUNKNOWN75) and last_delta != 0:
            out_recs.append((tag, lvl, adjust_generic_pos(data, hit_offset, last_delta), ext))
        else:
            out_recs.append((tag, lvl, data, ext))
    return out_recs

# ------------------ FileHeader ------------------
def read_fileheader(ole: olefile.OleFileIO):
    data = ole.openstream("FileHeader").read()
    sig = data[0:32].rstrip(b"\x00").decode("ascii", "ignore")
    ver_u32 = struct.unpack("<I", data[32:36])[0]
    ver = f"{(ver_u32>>24)&0xFF}.{(ver_u32>>16)&0xFF}.{(ver_u32>>8)&0xFF}.{ver_u32&0xFF}"
    flag0 = struct.unpack("<I", data[36:40])[0]
    packed = bool(flag0 & 0b1); encrypted = bool(flag0 & 0b10)
    return sig, ver, flag0, packed, encrypted

# ------------------ 메인 ------------------
def main(path, old, new):
    ole = olefile.OleFileIO(path)
    sig, ver, flag0, packed, encrypted = read_fileheader(ole)
    print(f"[+] Signature={sig}, Version={ver}, packed={packed}, encrypted={encrypted}")
    if encrypted:
        print("[!] 암호 문서는 처리 불가."); return

    raw = ole.openstream("BodyText/Section0").read()
    try:
        dec = zlib.decompress(raw, -15)
        print(f"[DEBUG] 압축 해제 성공: {len(raw)} → {len(dec)} bytes")
    except zlib.error:
        dec = raw
        print(f"[DEBUG] 압축 아님: {len(raw)} bytes 그대로 사용")

    recs = parse_records(dec)
    patched = process_records(recs, old, new)
    new_dec = build_records(patched)

    if packed:
        cobj = zlib.compressobj(level=9, wbits=-15)
        new_raw = cobj.compress(new_dec) + cobj.flush()
        print(f"[DEBUG] 재압축 완료: {len(new_dec)} → {len(new_raw)} bytes")
    else:
        new_raw = new_dec
        print(f"[DEBUG] 압축 없음: {len(new_raw)} bytes")

    out_path = os.path.splitext(path)[0] + "_edit.hwp"
    with open(out_path, "wb") as f:
        f.write(ole.openstream("FileHeader").getvalue())  
    print(f"[+] 새 HWP 파일 생성 완료: {out_path}")

# ------------------ 실행 ------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file"); ap.add_argument("--old", required=True); ap.add_argument("--new", required=True)
    args = ap.parse_args(); main(args.file, args.old, args.new)
