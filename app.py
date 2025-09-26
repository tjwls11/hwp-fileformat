import sys, struct, zlib, argparse, olefile, os, pythoncom
from win32com.storagecon import *

# ------------------ 레코드 파서 ------------------
REC_TAG_BITS = (0, 10)
REC_LEVEL_BITS = (10, 10)
REC_SIZE_BITS = (20, 12)

TAG_PARA_TEXT = 67
TAG_PARA_CHAR_SHAPE = 68

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

def build_records(recs):
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

# ------------------ 텍스트 교체 ------------------
def replace_in_para_text(data: bytes, old: str, new: str):
    old_b = old.encode("utf-16le")
    new_b = new.encode("utf-16le")

    if old_b not in data:
        return data, 0, None

    # 제어코드 제외 문자열화
    txt = "".join(chr(struct.unpack_from("<H", data, i)[0])
                  for i in range(0, len(data), 2)
                  if struct.unpack_from("<H", data, i)[0] >= 0x20)

    hit_pos = txt.find(old)
    if hit_pos == -1:
        return data, 0, None

    patched = data.replace(old_b, new_b, 1)
    delta = (len(new_b) - len(old_b)) // 2
    return patched, delta, hit_pos

def adjust_para_char_shape(data: bytes, hit_offset: int, delta: int):
    out = bytearray()
    for i in range(0, len(data), 4):
        if i + 4 > len(data):
            break
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
            new_data, delta, hit = replace_in_para_text(data, old, new)
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
    packed = bool(flag0 & 0b1)
    encrypted = bool(flag0 & 0b10)
    return sig, ver, flag0, packed, encrypted

# ------------------ 메인 ------------------
def main(path, old, new):
    ole = olefile.OleFileIO(path)
    sig, ver, flag0, packed, encrypted = read_fileheader(ole)
    print(f"[+] Signature={sig}, Version={ver}, packed={packed}, encrypted={encrypted}")
    if encrypted:
        print("[!] 암호 문서는 처리 불가.")
        return

    # Section0 읽기
    raw = ole.openstream("BodyText/Section0").read()
    try:
        dec = zlib.decompress(raw, -15)
        print(f"[DEBUG] 압축 해제 성공: {len(raw)} → {len(dec)} bytes")
    except zlib.error:
        dec = raw
        print(f"[DEBUG] 압축 아님: {len(raw)} bytes 그대로 사용")

    recs = parse_records(dec)
    patched_recs = process_records(recs, old, new)
    new_dec = build_records(patched_recs)

    if packed:
        cobj = zlib.compressobj(level=9, wbits=-15)
        new_raw = cobj.compress(new_dec) + cobj.flush()
        print(f"[DEBUG] 재압축 완료: {len(new_dec)} → {len(new_raw)} bytes")
    else:
        new_raw = new_dec
        print(f"[DEBUG] 압축 없음: {len(new_raw)} bytes")

    out_path = os.path.splitext(path)[0] + "_edit.hwp"
    dst_storage = pythoncom.StgCreateDocfile(
        out_path, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0
    )

    for entry in ole.listdir(streams=True, storages=True):
        full_name = "/".join(entry)
        try:
            data = ole.openstream(entry).read()
            if full_name == "BodyText/Section0":
                print(f"[DEBUG] 교체됨: {full_name}, 새 크기={len(new_raw)}")
                data = new_raw
            parts = entry[:-1]
            name = entry[-1]
            cur_storage = dst_storage
            for p in parts:
                try:
                    cur_storage = cur_storage.OpenStorage(
                        p, None, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, None, 0
                    )
                except:
                    cur_storage = cur_storage.CreateStorage(
                        p, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0
                    )

            stm = cur_storage.CreateStream(
                name, STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE, 0, 0
            )
            stm.Write(data)

        except Exception:
            # storage
            parts = entry
            cur_storage = dst_storage
            for p in parts:
                try:
                    cur_storage = cur_storage.OpenStorage(
                        p, None, STGM_READWRITE | STGM_SHARE_EXCLUSIVE, None, 0
                    )
                except:
                    cur_storage = cur_storage.CreateStorage(
                        p, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, 0
                    )
            continue

    print(f"[+] 새 HWP 파일 생성 완료: {out_path}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    args = ap.parse_args()
    main(args.file, args.old, args.new)
