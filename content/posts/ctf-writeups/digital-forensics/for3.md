---
title: "For3 - CTF CSCV2026"
date: 2026-10-26
draft: false
url: /posts/for3/
subject: CTF Writeups
topic: Digital Forensics
tags:
  - vmware
  - ntfs
  - cache-forensics
summary: Điều tra forensics bài khó nhất CSC 2026 Final - phân tích snapshot VMware, cache trình duyệt Edge và khôi phục file đã xoá qua NTFS $I30 để dựng lại chuỗi SHA-256 ghép thành flag.
---

![](/images/for3/image.png)

Mình nhận được một số file VMware liên quan tới một máy Windows Server 2025. Trong đó có file **WindowsServer2025-000001.vmdk** là ổ đĩa delta, chứa những block được ghi thêm từ Snapshot 2 tới Snapshot 5. Những file còn lại có **WindowsServer2025.vmdk** là ổ đĩa gốc ở thời điểm Snapshot 2, **WindowsServer2025-000002.vmdk** là delta mới nhất nhưng chỉ nặng 5 MB nên chắc là cũng không có gì, có **.vmsd** là danh sách snapshot, hai file **.vmsn** lưu trạng thái lúc chụp snapshot, còn **.vmx**, **.vmxf** và **.nvram** là cấu hình và BIOS của máy ảo. [[Tham khảo]](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/9-0/vsphere-single-host-management-vmware-host-client/virtual-machine-management-with-the-vsphere-host-client/managing-virtual-machines-in-the-vsphere-host-client/using-snapshots-to-manage-virtual-machines/snapshot-file-names-and-description.html)

Mình mở file **WindowsServer2025-000001.vmdk** bằng FTK Imager.

## SHA-256 của ransomware

Bắt đầu từ thư mục cá nhân. Trong C:\Users có hai tài khoản là Administrator và **subadmin**. Trong thư mục của subadmin, mình thấy mục Downloads có thời gian sửa đổi là 3:54:53 PM ngày 8/10/2026, mới hơn các thư mục khác.

![](/images/for3/image-1.png)

Ngoài desktop.ini, FTK còn hiện **vohai.exe** và **vohai.zip** với type [$I30 INDX Entry](https://www.cyberengage.org/post/understanding-collecting-parsing-the-i30). Đây là hai file đã bị xoá, FTK chỉ còn thấy tên của chúng trong index của thư mục. Một file .zip vừa tải về rồi giải nén ra file .exe, sau đó cả hai bị xoá, rất có mùi🤌.

File thì phải tải từ trình duyệt. Trong AppData\Local\Microsoft của subadmin có thư mục Edge, mà Edge thì lưu tạm những gì đã tải qua mạng vào thư mục cache. Mình export thư mục **Cache_Data** của Edge ra ổ **O:\**.

![](/images/for3/image-2.png)

Đọc cache bằng ChromeCacheView.

![](/images/for3/image-3.png)

Công cụ đọc ra **2,538** entry. Tìm thử “vohai.zip” thì ra một entry application/zip dài 12,369,012 byte, tải từ **cdn.discordapp.com**.

![](/images/for3/image-4.png)

Trong Properties của entry này có 1 số info quan trọng:

- **URL**: đường dẫn đầy đủ tới file trên Discord.
- **ETag**: 1af8bcef9c2021234f4db4022917003a. Discord lưu file trên Google Cloud Storage, mà ở đó ETag chính là MD5 của file [[Tham khảo]](https://cloud.google.com/storage/docs/hashes-etags).
- **Cache Name**: f_0000b1, tên file trong thư mục cache chứa nội dung của vohai.zip.

![](/images/for3/image-5.png)

Mở thư mục O:\Cache_Data lên xem thì **f_0000b1** trống trơn. Có lẽ bản ghi MFT của f_0000b1 không còn đọc được, nên FTK chỉ export ra được một file rỗng. Cache chỉ còn giữ được URL và header.

![](/images/for3/image-6.png)

Vì vậy mình thử tải lại file từ chính URL đó. Link file đính kèm của Discord có ba tham số:

- **ex** là thời điểm hết hạn
- **is** là thời điểm cấp
- **hm** là chữ ký

[[Tham khảo]](https://docs.discord.com/developers/reference#signed-attachment-cdn-urls) [[Tham khảo]](https://www.bleepingcomputer.com/news/security/discord-will-switch-to-temporary-file-links-to-block-malware-delivery/)

![](/images/for3/image-7.png)

Ở đây **ex** tương ứng 09/10/2026 15:53:51 UTC, đúng 24 giờ sau **is** 08/10/2026 15:53:51 UTC, vậy là trường chữ ký **hm** đã hết hạn, vì vậy link sẽ không sử dụng trực tiếp được.

![](/images/for3/image-8.png)

Discord chỉ ký lại link khi link xuất hiện trong ứng dụng của nó, nên mình paste link này lên Discord.

![](/images/for3/image-9.png)

![](/images/for3/image-10.png)

Tính MD5 bằng 7-Zip ra **1af8bcef9c2021234f4db4022917003a**, khớp đúng ETag trong cache, nghĩa là đây chính là file đã được tải.

![](/images/for3/image-11.png)

File zip yêu cầu mật khẩu, vậy vẫn là [chưa xong](https://www.youtube.com/watch?v=GUCd7imBCmU) 🥲.

![](/images/for3/image-12.png)

File được gửi qua Discord, nên khả năng mật khẩu cũng nằm trong cùng kênh chat. Link tệp đính kèm của Discord có dạng attachments/[id kênh]/[id tệp]/[tên file], nên từ URL của vohai.zip mình biết id kênh là **1557232976834732105**.

![](/images/for3/image-13.png)

Tìm id này trong ChromeCacheView thì kết quả đầu tiên là chính entry vohai.zip.

![](/images/for3/image-14.png)

Kết quả tiếp theo là **10.json**, có dạng **/api/v9/channels/1557232976834732105/messages?limit=10**. Search một chút, mình biết được rằng khi mở một kênh, Discord gọi API Get Channel Messages để tải danh sách tin nhắn [[Tham khảo]](https://docs.discord.com/developers/resources/message#get-channel-messages), và phản hồi đó cũng được Edge lưu vào cache.

![](/images/for3/image-15.png)

Entry này là JSON nén gzip, dài 707 byte.

![](/images/for3/image-16.png)

Chép entry ra O:\q1, ChromeCacheView tự giải nén gzip khi chép, rồi mở bằng Edge. Kênh chỉ có hai tin nhắn**,** một tin đính kèm vohai.zip, và một tin ẩn dưới dạng spoiler chứa mật khẩu.

![](/images/for3/image-17.png)

Bỏ phần escape đi thì mật khẩu là **`*6cG*5+d6woU/t:@0CfrYs”zlPvD?O`**.

Có mật khẩu rồi, mình quay lại 7-Zip để giải nén và hash file vohai.exe bên trong.

![](/images/for3/image-18.png)

![](/images/for3/image-19.png)

**Answer: 972dfa3661e358d21ebcbb96109ed9c40181341fe364669a6c03101fd0805ac1**

## SHA-256 của file báo cáo ngày 25-5-2049

Mở lịch sử Edge của subadmin, có thể thấy các file báo cáo nằm ở D:\Test.

![](/images/for3/image-20.png)

Nhưng máy chỉ có một ổ đĩa, thế ổ D: kia ở đâu? Mở thư mục gốc của C: trong FTK, file có dung lượng lớn nhất là **vhd_e.vhdx**, một ổ đĩa ảo.

![](/images/for3/image-21.png)

Mình export vhd_e.vhdx từ FTK ra máy. Rồi gắn nó vào Windows bằng Disk Management. Windows gán ổ này chữ F:.

![](/images/for3/image-22.png)

![](/images/for3/image-23.png)

Thư mục F:\Test có **26,076** mục, toàn bộ là các file .pdf.enc và .pdf.rsa, không còn file PDF gốc nào. Mình thêm F: vào FTK để đọc được cả file đã xoá lẫn vùng trống của ổ này.

![](/images/for3/image-24.png)

File Bao_cao_ngay_25-5-2049.pdf.enc có kích thước **473,964** byte.

![](/images/for3/image-25.png)

Mở file bằng HxD thì 32 byte đầu là header, gồm chữ ký RSAENC32 và 24 byte nonce, phía sau là dữ liệu đã mã hoá.

![](/images/for3/image-26.png)

Khoá để giải mã nằm trong file .rsa đi kèm, nhưng bị khoá lại bằng RSA-2048, không có private key thì không mở được. Vậy phải đi tìm bản PDF gốc. Kiểu mã hoá có nonce như này thường không làm dữ liệu dài thêm, nên file gốc nhiều khả năng dài 473,964 − 32 = **473,932** byte.

Bản gốc đã bị xoá khỏi D:. Nhưng ổ D: có bật Data Deduplication. [[Tham khảo]](https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/understand).

![](/images/for3/image-27.png)

Khi ransomware xoá file PDF, NTFS chỉ xoá file khỏi thư mục. Chunk và stream map của nó vẫn sẽ nằm trong kho cho tới khi job Garbage Collection của Dedup chạy để dọn những chunk không còn file nào dùng.

Vậy nếu mình tìm được stream map của file 25-5-2049 thì ghép lại được file gốc, và chỉ cần tìm theo kích thước 473,932 byte.

Cấu trúc kho chunk được mô tả trong bài viết này [[Tham khảo]](https://7h3kn0w3r.github.io/blog/windows-data-deduplication/). Kho có hai loại file cần dùng.

- **Stream*.ccc** chứa các stream map. Mỗi stream map bắt đầu bằng chữ “Smap”, tiếp theo là các entry 64 byte, mỗi entry ứng với một chunk của file.
- **Data*.ccc** chứa nội dung các chunk. Mỗi chunk bắt đầu bằng chữ ký “Ckhr”.

Trong FTK, chuột phải thư mục {B663825E-12FB-4DC6-B37F-0AD484BADE11}.ddp, chọn Export Files ra O:\ChunkStore để mở bằng HxD.

Entry cuối của stream map ghi offset kết thúc của chunk cuối, cũng chính là kích thước file, dưới dạng 8 byte little endian. 473,932 = 0x73B4C, nên mình tìm chuỗi hex `4C 3B 07 00 00 00 00 00`.

Mở lần lượt 3 file trong thư mục Stream bằng HxD, vào Search chọn Find, tab Hex-values. Chỉ file 00030000.00000001.ccc có một kết quả, tại 0x16C900, và khung Data inspector bên phải đọc 8 byte này ra đúng 473932.

![](/images/for3/image-28.png)

Lùi lên vài hàng là chữ “Smap” ở 0x16C7A8 (khung đỏ trên cùng), tức stream map của file 25-5-2049. Từ 0x16C7B0 là 6 entry, HxD hiện 16 byte mỗi hàng nên mỗi entry chiếm đúng 4 hàng. Mỗi entry có mấy ô quan trọng sau:

- **Khung cam** là số thứ tự chunk, entry đầu là 82 0D 00 00 = 3458.
- **Khung đỏ** là 4 byte số container rồi 4 byte offset của chunk trong file Data. Cả 6 entry đều là container 08 00 00 00, tức file Data\00000008.00000001.ccc.
- **Khung xanh dương** là offset kết thúc của chunk trong file PDF.
- **Khung xanh lá** là độ dài của chunk sau khi nén.

Đọc ngược từng giá trị (byte nhỏ đứng trước) mình có:

Để chắc offset này trỏ đúng chunk, mở Data\00000008.00000001.ccc trong HxD, vào Search chọn Go to, nhập 4099C90 là offset của chunk 1.

![](/images/for3/image-29.png)

Tại offset này có mấy thông tin mình đối chiếu.

- **Khung đỏ** là chữ ký “Ckhr”, đúng là chỗ bắt đầu một chunk.
- **Khung cam** là số chunk 82 0D 00 00 = 3458, giống entry 1 trong stream map.
- **Khung xanh lá** là độ dài B6 41 00 00 = 16,822, giống độ dài nén trong bảng.
- **Khung xanh dương** là chỗ dữ liệu nén bắt đầu, sau header 0x58 = 88 byte, tức 4099CE8 [[Tham khảo]](https://koreascience.or.kr/article/JAKO201706749670643.page). Kiểu nén là Plain LZ77 của Microsoft [[Tham khảo]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8), mở đầu bằng 4 byte cờ 00 00 10 00. Bit 0 nghĩa là byte giữ nguyên, nên ngay sau đó là chữ %PDF chưa bị nén.

Chunk này chỉ dài 16,822 byte nhưng phải ra 78,477 byte, nên đã bị nén.

Windows có sẵn hàm RtlDecompressBuffer trong ntdll để giải nén kiểu này, chọn định dạng COMPRESSION_FORMAT_XPRESS (giá trị 3) [[Tham khảo]](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer). Vậy chỉ cần vài dòng Python giải nén 6 chunk theo bảng trên rồi ghép lại.

```python
import ctypes

data = open(r"ChunkStore\{B663825E-12FB-4DC6-B37F-0AD484BADE11}.ddp\Data\00000008.00000001.ccc", "rb").read()
chunks = [(0x4099C90, 16822, 78477), (0x409DEA0, 19343, 169864), (0x40A2A88, 19924, 264598),
          (0x40A78B8, 8764, 305055), (0x40A9B50, 24855, 423547), (0x40AFCC0, 10867, 473932)]

out, prev = b"", 0
for offset, n, end in chunks:
    buf = ctypes.create_string_buffer(end - prev)
    ctypes.windll.ntdll.RtlDecompressBuffer(3, buf, end - prev, data[offset + 88:offset + 88 + n], n, ctypes.byref(ctypes.c_ulong()))
    out += buf.raw
    prev = end

open(r"q3\Bao_cao_ngay_25-5-2049.pdf", "wb").write(out)
print(len(out), "byte")
```

File ghép ra dài 473,932 byte, đúng kích thước đã tính từ file .enc, và mở được như một PDF bình thường.

Tính SHA-256 bằng 7-Zip.

![](/images/for3/image-30.png)

**Answer: 5905dbc3f93f33923f40657725c20b3a6c762ef7ac171c326ec3f00faa6bdf46**

## SHA-256 của file báo cáo ngày 30-4-2026

Trong F:\Test không có file nào tên 30-4-2026, kể cả file .enc, nên lần này không có kích thước nào để bám vào.

![](/images/for3/image-31.png)

Nhưng file bị xoá thì tên vẫn có thể còn sót lại, giống vohai.exe ở phần đầu. NTFS ghi danh sách file của mỗi thư mục vào một index tên $I30. Khi file bị xoá, entry của nó thường chưa mất hẳn mà nằm lại trong slack của index, vẫn còn tên và kích thước [[Tham khảo]](https://www.sans.org/blog/ntfs-i30-index-attributes-evidence-of-deleted-and-overwritten-files). FTK không hiện entry nào tên 30-4-2026 trong F:\Test, nên mình đọc $I30 bằng **MFTECmd**.

Trong FTK, thư mục F:\Test có một file tên $I30. Chuột phải, chọn Export Files ra O:\, rồi chạy lệnh sau trong PowerShell.

```text
MFTECmd.exe -f 'O:\$I30' --csv O:\i30 --csvf D_Test_I30.csv
```

Mở file CSV bằng Timeline Explorer rồi gõ 30-4-2026 vào ô lọc của cột File Name, còn đúng một dòng.

![](/images/for3/image-32.png)

Dòng này có mấy thông tin quan trọng.

- **From Slack = True** nghĩa là entry nằm trong slack, file đã bị xoá.
- **Flags** chỉ có Archive. File nào đã bị dedup thì có thêm cờ SparseFile|ReparsePoint, nội dung nằm trong kho chunk. File này không có, nên nội dung của nó nằm thẳng trên ổ.
- **Logical Size = 511,456** là kích thước thật của file.
- **Physical Size = 512,000** là chỗ file chiếm trên ổ, bằng 125 cluster × 4096 byte.

Khi file bị xoá, 125 cluster đó được trả lại vùng trống, nhưng dữ liệu vẫn còn nếu chưa bị ghi đè. Trong FTK, mục [unallocated space] của F: liệt kê từng vùng trống, tên là số cluster bắt đầu, cột Size là độ dài. Vùng đầu tiên, **0003244**, dài 512,000 byte, bằng Physical Size, mở ra thì bắt đầu bằng %PDF-1.4.

![](/images/for3/image-33.png)

Mình trích xuất khối dữ liệu `0003244` ra và mở bằng HxD để kiểm tra tại offset `0x7CDE0` (tương ứng với *Logical Size* là 511,456 byte). Ngay trước vị trí này là chuỗi `%%EOF` đánh dấu kết thúc file PDF, còn toàn bộ phần phía sau chỉ là các byte `00`. Từ đó mình xác định được 511,456 byte đầu tiên chính là dữ liệu thực của file PDF, phần còn lại chỉ là slack space của cluster cuối.

![](/images/for3/image-34.png)

Tiếp theo, mình cắt lấy 511,456 byte đầu tiên này (từ offset `0x0` với độ dài `0x7CDE0`) và lưu lại thành file `Bao_cao_ngay_30-4-2026.pdf`. Cuối cùng, băm SHA-256 của file vừa khôi phục.

![](/images/for3/image-35.png)

**Answer: fe4387f81272658af9c749ba1a148b8cc2fc4761d2c2a14a295c0b08ca3f0b30**

**Flag: CSCV2026{972dfa3661e358d21ebcbb96109ed9c40181341fe364669a6c03101fd0805ac1_fe4387f81272658af9c749ba1a148b8cc2fc4761d2c2a14a295c0b08ca3f0b30_5905dbc3f93f33923f40657725c20b3a6c762ef7ac171c326ec3f00faa6bdf46}**
