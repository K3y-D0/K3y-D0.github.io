---
title: "FOR01 + FOR02 - CSCV2026"
date: 2026-10-26
draft: false
url: /posts/for01-for02/
subject: CTF Writeups
topic: Digital Forensics
tags:
  - sqlite
  - ntfs
  - forensics
summary: Khôi phục dữ liệu SQLite WAL và phân tích NTFS USN Journal trong hai thử thách Forensics.
---

## 1. SQLite3

- Không mở chatapp.db bằng công cụ có quyền ghi (DB Browser, sqlite3 CLI ở chế độ mặc định...).
Khi mở, SQLite sẽ tự checkpoint: nội dung -wal bị gộp vào file .db, và các phiên bản trang
còn giữ tin nhắn đã xóa sẽ mất vĩnh viễn. Script này chỉ đọc file gốc dưới dạng byte,
còn mọi lần mở bằng sqlite3 đều thực hiện trên snapshot tự dựng, ở chế độ immutable.
- Thư mục databases có chatapp.db, chatapp.db-shm và chatapp.db-wal. File -wal khác rỗng
nghĩa là còn những transaction chưa được checkpoint vào file chính. Mở một bản sao ở chế độ
read-only để đọc schema: bảng messages có các cột id, thread_id, sender, body, timestamp.
- Đọc code từ file apk được cung cấp
Decompile chatapp.apk bằng jadx, class com.example.chatapp.Constants chứa:
NONCE_HEX = "706eeff3706eeff3706eeff3706eeff3"
ORDER_XOR = 931071618 (= 0x377F0682, jadx hiển thị dạng thập phân)
SECRET_MESSAGE = "sqlite3_forensics_2026"
SELECT_MOD = 3
PREFS_NAME = "chat_prefs", SALT_KEY = "device_salt"
Hai hằng số cuối cho biết salt không nằm trong APK mà nằm trong
shared_prefs/chat_prefs.xml, dưới khóa device_salt ⇒ Mở file đó, lấy giá trị
device_salt
- Khôi phục bản ghi đã xóa từ WAL.
File -wal gồm header 32 byte, tiếp theo là các frame (header 24 byte + một trang dữ liệu).
Frame hợp lệ phải có salt khớp với WAL header và checksum cộng dồn đúng. Frame có trường
"db size after commit" khác 0 là commit frame, đánh dấu kết thúc một transaction.
Cùng một page number có thể xuất hiện nhiều lần trong WAL, mỗi lần là một phiên bản của trang tại một thời điểm. Áp lần lượt các frame lên bản sao của .db để dựng snapshot sau từng
transaction, rồi so sánh các snapshot liên tiếp: rowid có ở snapshot trước nhưng mất ở
snapshot sau chính là bản ghi đã bị DELETE. Vì dựng lại nguyên trang, các record tràn sang
overflow page cũng được khôi phục đầy đủ, điều mà nhiều công cụ mã nguồn mở hiện chưa làm được.
- Ghép ciphertext và giải mã.
    
    Lọc các bản ghi đã xóa có body dạng "XX==", tính sortkey, giữ sortkey % 3 == 0,
    sắp tăng dần, lấy byte đầu sau khi decode base64 -> 16 byte ciphertext.
    key = SHA256(SECRET_MESSAGE || salt) hoặc SHA256(salt || SECRET_MESSAGE): không rõ thứ tự ghép nên thử cả hai. Để biết kết quả nào đúng, để ý NONCE_HEX là một nhóm 4 byte lặp lại
    4 lần: đó chính là CRC32 của flag, nên CRC32(plaintext) khớp với 4 byte này là đúng.
    

```python
#!/usr/bin/env python3
"""
khôi phục tin nhắn đã xóa từ WAL và giải mã secret message

Chạy:
    python3 for01.py <thư_mục_dữ_liệu_app> [-o out]
    # thư mục dữ liệu app là thư mục chứa databases

Cần: pip install cryptography
"""

import argparse
import base64
import datetime
import hashlib
import os
import re
import sqlite3
import struct
import sys
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# ---------------- Tham số lấy từ APK (com.example.chatapp.Constants) ----------------
NONCE_HEX      = "706eeff3706eeff3706eeff3706eeff3"
ORDER_XOR      = 931071618            # = 0x377F0682
SECRET_MESSAGE = "sqlite3_forensics_2026"
SELECT_MOD     = 3
# PREFS_NAME = "chat_prefs", SALT_KEY = "device_salt" -> salt nằm trong shared_prefs/chat_prefs.xml

# ---------------- Salt lấy từ shared_prefs/chat_prefs.xml ----------------
SALT_B64       = "bVaN8B8ekPGF5tPMwKoubg=="

TABLE   = "messages"
BODY_RE = re.compile(r"^[A-Za-z0-9+/]{2}==$")   # body mang đúng 1 byte (base64 của 1 byte)
TZ      = datetime.timezone(datetime.timedelta(hours=7))

WAL_HDR, WAL_FRAME_HDR = 32, 24

# ======================================================================
# BƯỚC 1: Đọc WAL
# ======================================================================

def read_wal_header(blob):
    """Header 32 byte: magic, version, page size, checkpoint seq, salt1, salt2, checksum1, checksum2."""
    magic, ver, pgsz, ckpt, s1, s2, c1, c2 = struct.unpack(">8I", blob[:WAL_HDR])
    if magic not in (0x377F0682, 0x377F0683):
        raise ValueError("Magic WAL không hợp lệ: 0x%08x" % magic)
    return {"big_endian": magic == 0x377F0683,         # 0x...83 = checksum big-endian
            "page_size": 65536 if pgsz == 1 else pgsz,
            "salt": (s1, s2), "checksum": (c1, c2)}

def wal_checksum(data, s1, s2, big_endian):
    """Checksum của SQLite WAL: cộng dồn theo từng cặp word 32-bit."""
    words = struct.unpack(("%s%dI" % (">" if big_endian else "<", len(data) // 4)), data)
    for i in range(0, len(words), 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
    return s1, s2

def iter_frames(blob, hdr):
    """Duyệt từng frame (header 24 byte + 1 trang) và kiểm tra salt + checksum."""
    ps, be = hdr["page_size"], hdr["big_endian"]
    run = hdr["checksum"]                    # checksum cộng dồn, bắt đầu từ checksum của header
    off, idx = WAL_HDR, 0
    while off + WAL_FRAME_HDR + ps <= len(blob):
        fh = blob[off:off + WAL_FRAME_HDR]
        pgno, dbsize, fs1, fs2, fc1, fc2 = struct.unpack(">6I", fh)
        page = blob[off + WAL_FRAME_HDR:off + WAL_FRAME_HDR + ps]
        c = wal_checksum(fh[:8], run[0], run[1], be)
        c = wal_checksum(page, c[0], c[1], be)
        ok = c == (fc1, fc2) and (fs1, fs2) == hdr["salt"]
        # Frame sai salt/checksum là rác của lần WAL cũ -> SQLite bỏ qua, ta cũng dừng tại đây
        if not ok:
            break
        yield {"index": idx, "pgno": pgno, "commit_size": dbsize, "page": page}
        run = c
        off += WAL_FRAME_HDR + ps
        idx += 1

def split_transactions(frames):
    """Cắt transaction tại mỗi commit frame (db size after commit != 0)."""
    txs, cur = [], []
    for f in frames:
        cur.append(f)
        if f["commit_size"]:
            txs.append(cur)
            cur = []
    return txs

def materialize(db_blob, frames, upto, page_size, out_path):
    """Dựng snapshot: áp mọi frame có index <= upto lên bản sao của .db.
    Áp nguyên trang nên record nằm trên overflow page cũng được khôi phục đúng."""
    data = bytearray(db_blob)
    dbsize = None
    for f in frames:
        if f["index"] > upto:
            break
        p = f["pgno"]
        need = p * page_size
        if len(data) < need:
            data.extend(b"\x00" * (need - len(data)))
        data[(p - 1) * page_size:p * page_size] = f["page"]
        if f["commit_size"]:
            dbsize = f["commit_size"]
    if dbsize:
        data = data[:dbsize * page_size]
        data[28:32] = struct.pack(">I", dbsize)        # đồng bộ số trang trong DB header
    with open(out_path, "wb") as fh:
        fh.write(bytes(data))
    return out_path

def open_ro(path):
    # immutable=1: SQLite không tạo -wal/-shm, không checkpoint, không ghi gì vào file
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % os.path.abspath(path), uri=True)

def read_rows(path):
    con = open_ro(path)
    try:
        cols = [r[1] for r in con.execute("PRAGMA table_info(%s)" % TABLE)]
        rows = {r[0]: dict(zip(cols, r[1:]))
                for r in con.execute("SELECT rowid,%s FROM %s" % (",".join(cols), TABLE))}
        return cols, rows
    finally:
        con.close()

def recover_deleted(db_path, wal_path, outdir):
    db_blob = open(db_path, "rb").read()               # chỉ đọc byte, không mở bằng sqlite3
    wal_blob = open(wal_path, "rb").read()
    page_size = struct.unpack(">H", db_blob[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size

    hdr = read_wal_header(wal_blob)
    frames = list(iter_frames(wal_blob, hdr))
    txs = split_transactions(frames)
    print("[*] WAL: %d frame hợp lệ, %d transaction đã commit, page size %d"
          % (len(frames), len(txs), page_size))

    # Snapshot 0 = file .db trước khi áp WAL, sau đó là snapshot sau từng transaction
    snaps = [materialize(db_blob, [], -1, page_size, os.path.join(outdir, "state_00_base.db"))]
    for i, tx in enumerate(txs, 1):
        snaps.append(materialize(db_blob, frames, tx[-1]["index"], page_size,
                                 os.path.join(outdir, "state_%02d_tx%d.db" % (i, i))))

    # So sánh snapshot liên tiếp: rowid biến mất = bản ghi bị DELETE
    deleted, prev = {}, None
    for i, path in enumerate(snaps):
        cols, rows = read_rows(path)
        if prev is not None:
            gone = sorted(set(prev) - set(rows))
            added = len(set(rows) - set(prev))
            print("    state_%02d: %4d dòng  (+%d, -%d)" % (i, len(rows), added, len(gone)))
            for rid in gone:
                deleted[rid] = prev[rid]
        else:
            print("    state_00: %4d dòng  (file .db gốc)" % len(rows))
        prev = rows
    print("[+] Khôi phục %d bản ghi đã bị xóa" % len(deleted))
    return deleted

# ======================================================================
# BƯỚC 2: Ghép ciphertext
# ======================================================================

def fmt_ts(ts):
    sec = ts / 1000 if ts > 10**11 else ts             # timestamp ms hay s
    return datetime.datetime.fromtimestamp(sec, TZ).strftime("%Y-%m-%d %H:%M:%S")

def build_ciphertext(deleted):
    cands = [r for r in deleted.values()
             if isinstance(r.get("body"), str) and BODY_RE.match(r["body"])]

    # Nếu có nhiều thread, lấy thread chứa nhiều tin nhắn mang byte nhất
    if cands and "thread_id" in cands[0]:
        by_thread = {}
        for r in cands:
            by_thread.setdefault(r["thread_id"], []).append(r)
        print("[*] Ứng viên body 'XX==' theo thread: %s"
              % {k: len(v) for k, v in sorted(by_thread.items())})
        thread, cands = max(by_thread.items(), key=lambda kv: len(kv[1]))
        print("[*] Chọn thread_id = %s (%d bản ghi)" % (thread, len(cands)))

    selected = []
    for r in cands:
        k = r["timestamp"] ^ ORDER_XOR                 # sortkey
        if k % SELECT_MOD == 0:                        # chỉ tin nhắn này mang byte thật
            selected.append((k, r))
    selected.sort(key=lambda x: x[0])                  # sắp sortkey tăng dần

    print("[*] Giữ sortkey %% %d == 0: %d bản ghi" % (SELECT_MOD, len(selected)))
    print("    %-4s %-19s %-12s %-6s %s" % ("#", "timestamp (UTC+7)", "sortkey", "body", "byte"))
    ct = bytearray()
    for i, (k, r) in enumerate(selected):
        b = base64.b64decode(r["body"])[0]
        ct.append(b)
        print("    %-4d %-19s %-12d %-6s %02x" % (i, fmt_ts(r["timestamp"]), k, r["body"], b))
    return bytes(ct)

# ======================================================================
# BƯỚC 3: Giải mã
# ======================================================================

def chacha20(data, key, nonce):
    # Nonce 16 byte (counter 4 byte + nonce 12 byte) là đúng dạng thư viện `cryptography` nhận.
    # PyCryptodome chỉ nhận nonce 8/12 byte nên không dùng trực tiếp được.
    return Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor().update(data)

def decrypt(ct, salt_b64):
    salt = base64.b64decode(salt_b64)                  # salt phải decode base64 trước khi ghép
    secret = SECRET_MESSAGE.encode()
    nonce = bytes.fromhex(NONCE_HEX)
    expect_crc = int(NONCE_HEX[:8], 16)                # NONCE = CRC32(flag) lặp 4 lần

    found = None
    for label, material in (("SECRET || salt", secret + salt),
                            ("salt || SECRET", salt + secret)):
        key = hashlib.sha256(material).digest()
        pt = chacha20(ct, key, nonce)
        crc = zlib.crc32(pt) & 0xFFFFFFFF
        ok = crc == expect_crc
        print("    [%s] %-15s crc32=%08x  %r" % ("+" if ok else "-", label, crc, pt))
        if ok:
            found = pt
    return found

# ======================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("appdir", help="thư mục dữ liệu app (chứa databases/)")
    ap.add_argument("-o", "--outdir", default="out", help="thư mục chứa snapshot dựng lại")
    a = ap.parse_args()

    db = os.path.join(a.appdir, "databases", "chatapp.db")
    wal = db + "-wal"
    for p in (db, wal):
        if not os.path.exists(p):
            sys.exit("[!] Không tìm thấy %s" % p)
    os.makedirs(a.outdir, exist_ok=True)

    print("=== BƯỚC 1: Khôi phục bản ghi đã xóa từ WAL ===")
    deleted = recover_deleted(db, wal, a.outdir)

    print("\n=== BƯỚC 2: Ghép ciphertext ===")
    ct = build_ciphertext(deleted)
    print("[+] Ciphertext (%d byte): %s" % (len(ct), ct.hex()))

    print("\n=== BƯỚC 3: Giải mã ChaCha20 ===")
    print("[*] Salt (device_salt): %s" % SALT_B64)
    flag = decrypt(ct, SALT_B64)
    if flag:
        print("\n[+] SECRET MESSAGE: %s" % flag.decode("utf-8", "replace"))
    else:
        print("\n[!] Không thứ tự ghép key nào cho CRC32 khớp, kiểm tra lại ciphertext.")

if __name__ == "__main__":
    main()
```

## 2. Ghost Tree

Vùng đĩa trống đã bị ghi đè, nên các kỹ thuật quen thuộc như file carving hay khôi phục nội dung từ cluster chưa cấp phát gần như vô dụng. Bản ghi trong $MFT của file và các thư mục cha cũng không đáng tin, vì sau khi xóa, entry MFT được giải phóng và có thể bị chính quá trình wipe tái sử dụng (wipe tool thường tạo hàng loạt file tạm để lấp đầy đĩa).

Tuy nhiên, `$UsnJrnl` là một file hệ thống đang được cấp phát, không nằm trong free space, nên không bị wipe xóa. NTFS ghi vào đây một bản ghi cho mỗi thay đổi trên file và thư mục: tạo, đổi tên, ghi dữ liệu, xóa. Mỗi bản ghi lưu tên (chỉ tên, không có đường dẫn), số tham chiếu của chính nó và số tham chiếu của thư mục cha. Vì vậy, dù dữ liệu không còn, ta vẫn có thể dựng lại cây thư mục bằng cách nối các bản ghi qua trường ParentFileReferenceNumber.

Điểm mấu chốt của đề là: việc wipe sinh ra rất nhiều bản ghi mới dùng lại các entry MFT cũ. Nếu chỉ khớp theo số entry, ta sẽ nối nhầm sang file rác của wipe tool. Cách đúng là khớp theo toàn bộ tham chiếu 64-bit, gồm cả số entry lẫn số sequence.

```python
#!/usr/bin/env python3
"""
Hướng giải:
  1. Parse toàn bộ USN record trong $J.
  2. Lấy mọi file .txt có bản ghi FileDelete -> danh sách ứng viên.
  3. Với mỗi ứng viên, đi ngược ParentFileReferenceNumber (khớp FULL 64-bit)
     cho tới root volume (MFT entry 5) hoặc tới khi chuỗi đứt.
  4. In đường dẫn đầy đủ của từng file .txt đã bị xóa

Chạy:
  python for02.py -j J.bin
"""

import struct, datetime, argparse, sys

ROOT_ENTRY = 5          # MFT entry 5 = thư mục gốc của volume (\)
# Reason codes (tham khảo tài liệu về USN record của Microsoft docs)
REASONS = [
    (0x00000001, "DataOverwrite"), (0x00000002, "DataExtend"), (0x00000004, "DataTruncation"),
    (0x00000100, "FileCreate"),    (0x00000200, "FileDelete"),
    (0x00001000, "RenameOldName"), (0x00002000, "RenameNewName"),
    (0x00008000, "BasicInfoChange"), (0x80000000, "Close"),
]

def reasons(r):
    return "|".join(n for m, n in REASONS if r & m) or hex(r)

def ft(v):
    # FILETIME: số khoảng 100ns tính từ 1601-01-01 UTC
    if not v:
        return ""
    try:
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "?"

def parse(path):
    data = open(path, "rb").read()
    recs = []
    off, n = 0, len(data)

    # $J là sparse stream: đầu file thường là vùng toàn byte 0.
    # Quét theo bước 8 byte (bản ghi luôn căn lề 8) và kiểm tra từng ứng viên.
    while off + 60 <= n:                                  # header cố định 60 byte
        rl = struct.unpack_from("<I", data, off)[0]       # 0x00 RecordLength
        if rl == 0:
            off += 8; continue                            # vùng trống
        if rl < 60 or rl > 4096 or off + rl > n:
            off += 8; continue                            # độ dài vô lý -> rác
        if struct.unpack_from("<H", data, off + 4)[0] != 2:
            off += 8; continue                            # 0x04 MajorVersion phải = 2

        frn  = struct.unpack_from("<Q", data, off + 8)[0]   # 0x08 FileReferenceNumber
        pfrn = struct.unpack_from("<Q", data, off + 16)[0]  # 0x10 ParentFileReferenceNumber
        usn  = struct.unpack_from("<Q", data, off + 24)[0]  # 0x18 Usn
        ts   = struct.unpack_from("<Q", data, off + 32)[0]  # 0x20 TimeStamp
        rsn  = struct.unpack_from("<I", data, off + 40)[0]  # 0x28 Reason
        attr = struct.unpack_from("<I", data, off + 52)[0]  # 0x34 FileAttributes
        nlen = struct.unpack_from("<H", data, off + 56)[0]  # 0x38 FileNameLength
        noff = struct.unpack_from("<H", data, off + 58)[0]  # 0x3A FileNameOffset

        name = ""
        if noff and nlen and off + noff + nlen <= n:
            name = data[off + noff:off + noff + nlen].decode("utf-16-le", "replace")

        # Reference 64-bit = 48 bit thấp (MFT entry) + 16 bit cao (sequence).
        # ref/pref (giá trị nguyên) là khóa dùng để nối cây.
        recs.append(dict(
            usn=usn, ref=frn, pref=pfrn,
            entry=frn & 0xFFFFFFFFFFFF,  seq=(frn >> 48) & 0xFFFF,
            pentry=pfrn & 0xFFFFFFFFFFFF, pseq=(pfrn >> 48) & 0xFFFF,
            ts=ft(ts), reason=reasons(rsn), rsn=rsn,
            isdir=bool(attr & 0x10), name=name))
        off += rl
    return recs

def build_index(recs):
    # Gom bản ghi theo FULL 64-bit reference.
    # [QUAN TRỌNG] Không gom theo entry: wipe tool tạo hàng loạt file tạm dùng lại
    # các MFT entry đã giải phóng (sequence tăng). Gom theo entry sẽ trộn thư mục
    # thật với file rác và nối sai cây.
    idx = {}
    for r in recs:
        if r["name"]:
            idx.setdefault(r["ref"], []).append(r)
    return idx

def best_record(idx, ref):
    cand = idx.get(ref)
    if not cand:
        return None
    # Ưu tiên bản ghi FileDelete: đó là tên CUỐI CÙNG trước khi bị xóa
    # (thư mục/file có thể đã bị rename trước đó).
    dele = [r for r in cand if r["rsn"] & 0x200]
    return dele[-1] if dele else cand[-1]

def walk_up(idx, start_pref):
    """Đi ngược từ parent ref lên tới root volume. Trả về (levels leaf -> root, lý do dừng)."""
    levels, cur, seen = [], start_pref, set()
    while cur and cur not in seen:
        seen.add(cur)
        if cur & 0xFFFFFFFFFFFF == ROOT_ENTRY:
            return levels, "root"                 # tới \ của volume
        rec = best_record(idx, cur)
        if not rec:
            return levels, "broken"               # journal không còn bản ghi của cấp này
        levels.append(rec)
        cur = rec["pref"]
    return levels, "loop"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", "--journal", required=True, help="file $J đã trích xuất")
    ap.add_argument("--ext", default=".txt", help="đuôi file cần tìm (mặc định .txt)")
    a = ap.parse_args()

    recs = parse(a.journal)
    idx = build_index(recs)
    print(f"[*] parsed {len(recs)} USN records")

    # --- Bước 1: liệt kê mọi file .txt đã bị xóa (mỗi reference một ứng viên) ---
    leaves = {}
    for r in recs:
        if (r["rsn"] & 0x200) and not r["isdir"] and r["name"].lower().endswith(a.ext.lower()):
            leaves[r["ref"]] = r                  # giữ bản ghi FileDelete cuối cùng
    if not leaves:
        print(f"[!] không có file {a.ext} nào bị xóa trong journal."); sys.exit(1)
    print(f"[*] {len(leaves)} file {a.ext} bị xóa\n")

    # --- Bước 2: dựng đường dẫn đầy đủ cho từng file ---
    results = []
    for leaf in leaves.values():
        levels, why = walk_up(idx, leaf["pref"])
        levels.reverse()                          # lá->gốc  =>  ngoài->trong
        path = "\\" + "\\".join([r["name"] for r in levels] + [leaf["name"]])
        results.append((leaf, levels, path, why))

    # Sắp theo độ sâu giảm dần: file nằm sâu trong một cây thư mục thường đáng chú ý hơn
    results.sort(key=lambda x: len(x[1]), reverse=True)

    # end = root   : dựng được tới thư mục gốc của volume
    # end = broken : journal mất bản ghi của một cấp cha -> đầu đường dẫn có thể thiếu
    print(f"{'depth':>5}  {'end':<7} {'deleted (UTC)':<19}  path")
    for leaf, levels, path, why in results:
        print(f"{len(levels):>5}  {why:<7} {leaf['ts']:<19}  {path}")

if __name__ == "__main__":
    main()
```

