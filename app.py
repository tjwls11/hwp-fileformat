import sys, struct, olefile

def read_fileheader(ole: olefile.OleFileIO):
    data = ole.openstream("FileHeader").read() # FileHeader 스트림 읽기

    # [0x00..1F] 시그니처
    sig = data[0:32].rstrip(b"\x00").decode("ascii", "ignore")

    # [0x20..23] 버전 (각 바이트가 점 표기)
    ver_u32 = struct.unpack("<I", data[32:36])[0]
    ver = f"{(ver_u32>>24)&0xFF}.{(ver_u32>>16)&0xFF}.{(ver_u32>>8)&0xFF}.{ver_u32&0xFF}"

    # [0x24..27] flag0 (bit0=packed, bit1=encrypted)
    flag0 = struct.unpack("<I", data[36:40])[0]
    packed    = bool(flag0 & 0b1)       
    encrypted = bool(flag0 & 0b10)       

    return sig, ver, flag0, packed, encrypted

def main(path):
    ole = olefile.OleFileIO(path)
    if not ole.exists("FileHeader"):
        print("[!] FileHeader 스트림없음")
        return
    sig, ver, flag0, packed, encrypted = read_fileheader(ole)
    print(f"[+] Signature = {sig}")
    print(f"[+] Version   = {ver}")
    print(f"[+] Flags     = 0x{flag0:08X}")
    print(f"    - packed={packed}  (본문 섹션 DEFLATE 여부)")
    print(f"    - encrypted={encrypted}  (문서 암호화 여부)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    main(sys.argv[1])