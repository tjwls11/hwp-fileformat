import olefile, zlib, struct, binascii

def dump_section0(path):
    ole = olefile.OleFileIO(path)
    raw = ole.openstream("BodyText/Section0").read()
    try:
        dec = zlib.decompress(raw, -15)
        print(f"압축 해제 성공: {len(raw)} → {len(dec)} bytes")
    except zlib.error:
        dec = raw
        print(f"압축 아님: {len(raw)} bytes 그대로 사용")

    # 첫 200바이트만 hex dump
    print("=== HEX DUMP (앞 200바이트) ===")
    print(binascii.hexlify(dec[:200], " ").decode())

    return dec

dec = dump_section0("테스트.hwp")
