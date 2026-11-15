# BỘ BÀN GIAO THÀNH VIÊN 4 (HIỆP) — CHUẨN MÔN INS3062 (VNU-IS)

- **Môn học:** Các nguyên lí an toàn thông tin (`INS3062 - INS306202`)
- **Giảng viên:** TS. Diêm Công Hoàng (`Phòng thực hành 02 - 513, số 1 Phan Tây Nhạc`)
- **Nhóm:** Nhóm 2 POIS — **Vai trò của Hiệp:** Thành viên 4 (Code chính & Live Demo)

> **Nguyên tắc sống còn khi Demo trước TS. Diêm Công Hoàng:** Đây là môn **Nguyên lí An toàn thông tin**, không phải môn Lập trình Web. Tuyệt đối không mở đầu bằng *"đây là web nhắn tin Alice - Bob"*. Phải đi theo đúng thứ tự **Toán & Lỗ hổng Mật mã (`Tab 2`) → Hiệu năng & Chuẩn NIST (`Tab 3`) → Mô hình CIA & Zero-Knowledge (`Tab 1`) → Truy vết Kiểm toán (`Tab 4`)**.

---

## PHẦN A. CHECKLIST LÀM ĐÚNG VỚI MÔN HỌC (LÀM NGAY HÔM NAY)

1. **Kiểm tra lại đề bài gốc (`Topic9.pdf` & tên đề tài đã đăng ký):**
   - Trong DB test cũ của Kim Ngân từng có tệp tên `Topic9.pdf`, còn link tham khảo đầu kỳ có đề tài cũ `FoodTech/SmartMeal` (`pois`). Hãy nhắn hỏi Kim Ngân trong nhóm Zalo ngay: **đề bài Topic 9 / đề tài nhóm nộp cho thầy Hoàng có yêu cầu cụ thể nào khác không**, và **tên đề tài nhóm đã đổi sang "ECC cho Hệ thống Thông tin Bảo mật (`ECC-SIS`)" chưa**.
2. **Gửi 8 ảnh chụp sẵn (`demo_deliverables/screenshots/`) vào nhóm Zalo cho TV1, TV2, TV3:**
   - **Ảnh 1 (`01_Tab2_DoThi_toy_p97_DoubleAndAdd.png`)** → TV1 (Mục 2.2) & TV3 (Slide 4): Nguyên lý một chiều ECDLP & *Double-and-Add*.
   - **Ảnh 2 (`02_Tab2_TanCong_TrungNonce_PS3_ECDSA.png`)** → TV2 (Chương 4) & TV3 (Slide 8): Tấn công trùng Nonce `k` (Sony PS3) & phòng thủ **RFC 6979**.
   - **Ảnh 3a (`03a_Tab1_MoPhong5Giay_DoiChieu.png`)** → TV2 (Mục 3.1) & TV3 (Slide 6, 7): Kiến trúc Client-Side Crypto + Zero-Knowledge Server.
   - **Ảnh 3b (`03b_Tab1_HopThuBob_GiaiMa_Va_CSDL.png`)** → TV2 (Mục 3.2) & TV3 (Slide 7): Chứng minh SQLite chỉ có Hex (`Confidentiality at-rest`) + giải mã PDF phía Bob.
   - **Ảnh 4 (`04_Tab1_Phat_Hien_Can_Thiep_MITM.png`)** → TV2 (Chương 4) & TV3 (Slide 8): Phá 1 bit dữ liệu → chặn ngay (`Integrity`).
   - **Ảnh 5a (`05_Tab3_Benchmark_ECC_vs_RSA_Jacobian.png`)** → TV2 (Chương 5) & TV3 (Slide 10): Bảng NIST SP 800-57 & số đo thực tế trên máy bạn.
   - **Ảnh 5b (`06_Tab4_AuditLog_ChuoiBam_SHA256.png`)** → TV2 (Mục 3.2) & TV3 (Slide 6/12): Audit Log chuỗi băm SHA-256 (`Accountability`).
   - *(Phụ lục Word nếu cần)*: `03_Tab1_Alice_Gui_Bob_E2EE_Va_Soi_CSDL.png`.
3. **Nhắc TV1, TV2, TV3 sửa đúng 5 chỗ trong Báo cáo & Slide:**
   - Điền chuẩn thông tin trang bìa trong `BAO_CAO_CHI_TIET.md`: Trường Quốc tế - ĐHQGHN (`VNU-IS`), Môn `Các nguyên lí an toàn thông tin (INS3062 - INS306202)`, GVHD `TS. Diêm Công Hoàng`, tên 4 thành viên Nhóm 2.
   - Sửa lỗi gõ nhầm **`2^218` → `2^128` phép thử** trong Doc `poiz`.
   - Thêm lại tiêu đề **`CHƯƠNG 4`** bị nhảy mất trong Doc `poiz`.
   - Đổi tên nút tiếng Anh cũ sang đúng nút tiếng Việt trên web (`⚡ Hacker sửa 1 bit dữ liệu`, `❌ Chữ ký giả mạo`, `👁️ Soi CSDL Máy Chủ`).
   - Dùng bảng số liệu Benchmark thực tế trên máy bạn (`Ảnh 5a`): Jacobian nhanh hơn Affine **`5.43 lần`** (`2.249 ms` vs `12.208 ms`); ECC P-256 vs RSA-3072: tạo khóa **`2.111 ms` vs `1,601.703 ms`** (~`759x`), ký **`2.272 ms` vs `54.921 ms`**, verify **`4.405 ms` vs `0.257 ms`**, khóa nén **`33 B` vs `384 B` (`12x`)**.
4. **Họp nhóm 15 phút:** Bấm đúp `run_demo.bat` cho cả 3 bạn xem trực tiếp luồng **Tab 2 → Tab 3 → Tab 1 → Tab 4** để mọi người nói cùng một ngôn ngữ bảo mật.

---

## PHẦN B. KỊCH BẢN LIVE DEMO 3 PHÚT 30 GIÂY (THỨ TỰ CHUẨN ATTT)

> **Chuẩn bị trước khi lên bục:** Bấm đúp `run_demo.bat` sẵn (mở Brave tại `http://127.0.0.1:8000`). Mở sẵn 1 cửa sổ PowerShell ở thư mục `poipoi` nếu muốn show nhanh lệnh `python -m unittest discover -s tests -v` (`13/13 OK`).

### Pha 1 (0:00 – 0:55) — Cốt lõi Thuật toán, Test NIST & Tấn công Nonce Reuse (`Tab 2`)
- **Thao tác:** Mở sẵn **Tab 2 (`Thí Nghiệm Toán Học ECC`)**. Chỉ vào đồ thị `toy_p97` và bảng *Double-and-Add*. Kéo xuống bấm **`Ký Số, Soi Dấu & Tấn Công Demo`** (và bấm **`Chạy Bắt Tay ECDH`**).
- **Lời nói chuẩn môn INS3062:**
  *"Thưa thầy, trọng tâm bài của nhóm em là tự cài đặt lõi thuật toán ECC từ số học trường hữu hạn $\mathbb{F}_p$ trong `ecc_core/` (không dùng thư viện ECC làm sẵn), đã pass 13/13 unit test gồm vector chuẩn NIST CAVP AES-GCM. Trên màn hình là đường cong hữu hạn `toy_p97` minh họa tính một chiều của bài toán Logarit rời rạc (ECDLP).*
  *Đặc biệt trong phần tấn công mật mã, nếu lập trình viên sinh trùng số ngẫu nhiên `k` trong ECDSA — giống sự cố lộ khóa PlayStation 3 năm 2010 — hệ thống sẽ giải phương trình và khôi phục nguyên khóa bí mật như thầy thấy ở dòng `private_key_compromised: true`. Vì vậy nhóm em áp dụng chuẩn **RFC 6979** sinh `k` tất định để triệt tiêu lỗ hổng này."*

### Pha 2 (0:55 – 1:40) — Chuẩn NIST SP 800-57 & Đánh đổi Hiệu năng (`Tab 3`)
- **Thao tác:** Chuyển sang **Tab 3 (`Đua Tốc Độ: ECC vs RSA`)**, bấm **`▶ Chạy Đầy Đủ (+RSA-3072)`** (chờ ~2 giây).
- **Lời nói chuẩn môn INS3062:**
  *"Để đánh giá chi phí triển khai thực tế theo chuẩn **NIST SP 800-57**, nhóm đo trực tiếp trên cùng Python thuần: đầu tiên tối ưu tọa độ xạ ảnh **Jacobian** giúp giảm xuống chỉ còn 1 phép nghịch đảo modulo cuối cùng, nhanh hơn **~5.4 lần** so với Affine. Thứ hai, ở cùng độ an toàn **128-bit**, ECC `secp256r1` giảm kích thước khóa công khai tới **12 lần** (`33 B` so với `384 B` của RSA-3072) và tạo khóa nhanh hơn **~750 lần** (`~2.1 ms` vs `~1,600 ms`). Chính tốc độ tạo khóa này cho phép hệ thống thực thi nguyên lý **Forward Secrecy** — tạo khóa mới cho từng gói dữ liệu — mà RSA không đáp ứng nổi."*

### Pha 3 (1:40 – 2:55) — Mô phỏng Bảo vệ Bộ ba CIA & Zero-Knowledge Server (`Tab 1`)
- **Thao tác:** Chuyển sang **Tab 1 (`Nhắn Tin & Gửi File E2EE`)**:
  1. Bấm **`👤 Tài Khoản Khác`** → tạo nhanh 1 user mới (hoặc chỉ luồng **Challenge-Response**) để chứng minh **Authentication không mật khẩu**.
  2. Bấm **`▶ Chạy Mô Phỏng 5 Giây`** → chuyển về **Bob**, mở **`👁️ Soi CSDL Máy Chủ`** chỉ cả bản mã hex và tệp `Tai_Lieu_Mat_Noi_Bo_ECC_SIS.pdf` đã giải mã.
  3. Bấm **`⚡ Hacker sửa 1 bit dữ liệu`** ngay trên 1 gói tin ở hộp thư Bob → hiện khung cảnh báo đỏ.
- **Lời nói chuẩn môn INS3062:**
  *"Để chứng minh ECC giải quyết bài toán bảo vệ bộ ba CIA cho một hệ thống thông tin thực tế, nhóm xây dựng kiến trúc **Zero-Knowledge Server**:*
  - ***Authentication (Xác thực):** Không truyền hay lưu mật khẩu. Trình duyệt tự giữ Private Key; khi đăng nhập Server gửi `nonce` 32 byte dùng 1 lần (hết hạn 120s chống Replay Attack) để Client ký ECDSA.*
  - ***Confidentiality (Tính bí mật In-Transit & At-Rest):** Mỗi dữ liệu hay tệp PDF đều dùng mô hình lai ECIES (`Ephemeral ECDH + HKDF-SHA256 + AES-256-GCM`). Trên **Soi CSDL Máy Chủ**, bảng SQLite chỉ lưu hex — kể cả hacker chiếm được DB hoặc Admin xem trộm cũng có `0 byte` bản rõ.*
  - ***Integrity & Non-repudiation (Toàn vẹn & Chống chối bỏ):** Chữ ký ECDSA bọc ngoài cả siêu dữ liệu AAD (`người gửi | người nhận | tên file`). Khi em bấm giả lập kẻ tấn công sửa lén đúng **1 bit** trong DB, trình duyệt bắt ngay lỗi **`❌ Chữ ký giả mạo`** và chặn giải mã."*

### Pha 4 (2:55 – 3:30) — Trách nhiệm giải trình & Nhật ký Kiểm toán (`Tab 4`)
- **Thao tác:** Chuyển sang **Tab 4 (`Sổ Nhật Ký & Kiến Trúc`)**, bấm **`✓ Kiểm Tra Tính Toàn Vẹn Chuỗi Băm`**.
- **Lời nói chuẩn môn INS3062:**
  *"Cuối cùng để đảm bảo **Accountability (Auditability)**, mọi hành động đăng ký, xác thực, lưu bản mã và phát hiện giả mạo đều được băm nối chuỗi SHA-256 (`H_i = SHA256(H_{i-1} || ...)`), đảm bảo kẻ xấu không thể sửa hoặc xóa lịch sử kiểm toán âm thầm. Em xin kết thúc phần Demo và mời thầy đặt câu hỏi ạ."*

---

## PHẦN C. 10 CÂU HỎI XOÁY CỦA THẦY & ĐÁP ÁN CHUẨN XÁC

1. **Thầy hỏi:** *"Sao ghi Pure Python tự code mà trong `cipher.py` lại thấy import `cryptography`?"*
   - **Đáp án:** Toàn bộ toán **ECC** (`ecc_core/field.py`, `curves.py`, `ecdh.py`, `ecdsa.py`, `ecies.py`) do nhóm tự cài **100% Pure Python**. Riêng tầng mã hóa đối xứng **AES-256-GCM** trong `cipher.py` vừa có bản tự viết `PureAES256GCM` (đã đối khớp test vector chính thức **NIST SP 800-38D CAVP Case 15 & 16**), vừa tận dụng tăng tốc C (`cryptography.AESGCM`) khi máy có sẵn để xử lý tệp tới 5 MB mượt mà.

2. **Thầy hỏi:** *"Hai nút Alice với Bob bấm là vào, có phải hardcode khóa không? Khác gì ngoài thực tế?"*
   - **Đáp án:** Chỉ `alice` và `bob` gắn cặp JWK mẫu (`DEMO_PRESET_JWKS` trong `app.js`) để demo nhanh trong 5 giây. Còn khi bấm **"Tài Khoản Khác"** tạo user bất kỳ, trình duyệt tự sinh cặp khóa mới bằng WebCrypto lưu trong `localStorage`, và Server trả mã `409 Conflict` nếu trùng username để chặn chiếm danh tính.

3. **Thầy hỏi:** *"AES-GCM đã là AEAD có Auth Tag kiểm tra toàn vẹn rồi, sao còn bắt Alice ký ECDSA bọc ngoài làm gì?"*
   - **Đáp án:** Vì khóa AES-GCM tính từ **khóa tạm ẩn danh `(k_eph, Q_eph)`** và **Public Key công khai của Bob** (`Q_Bob` ai cũng biết). Nếu không có chữ ký ECDSA bằng khóa định danh của Alice, bất kỳ ai cũng tự tạo được gói tin AES-GCM hợp lệ gửi giả danh Alice (lỗ hổng giả mạo nguồn gốc / spam). Chữ ký ECDSA đảm bảo **Authentication & Non-repudiation**.

4. **Thầy hỏi:** *"Alice gửi xong nhìn lại hộp thư đã gửi của mình có tự giải mã đọc lại được không?"*
   - **Đáp án:** Không nếu đã hủy khóa tạm `k_eph` (đặc tính **Forward Secrecy**). Vì khóa phiên tính từ $k_{\text{eph}} \cdot Q_{\text{Bob}} = d_{\text{Bob}} \cdot Q_{\text{eph}}$, chỉ Bob giữ $d_{\text{Bob}}$ mới mở lại được.

5. **Thầy hỏi:** *"Kẻ gian giữ nguyên `ciphertext`, chỉ tráo tên file đính kèm hoặc đổi người nhận thì có lừa được không?"*
   - **Đáp án:** Không. Chuỗi siêu dữ liệu `sender|recipient|msg_type|filename` được đưa vào trường **AAD** của AES-256-GCM và gộp vào vùng dữ liệu ký **ECDSA** (`ECC-SIS-SIG-v1 || Q_eph || nonce || ciphertext || aad`). Sửa 1 ký tự siêu dữ liệu là rớt cả chữ ký lẫn GCM Tag.

6. **Thầy hỏi:** *"Hệ thống phòng chống Invalid-Curve Attack và Replay Attack bằng cơ chế nào?"*
   - **Đáp án:** (1) Mọi khóa công khai khi đăng ký và `ephemeral_pubkey_hex` đều qua `validate_public_key`: kiểm tra điểm khác vô cực, thỏa phương trình đường cong mod $p$, và kiểm tra bậc nhóm con $n \cdot Q = \mathcal{O}$ (sai là chặn `HTTP 400`, có unit test `test_invalid_public_key_rejected`). (2) Replay Attack bị chặn bằng Challenge `nonce` ngẫu nhiên 32 byte, TTL 120s và cờ `used = 1` ngay sau lần verify đầu tiên.

7. **Thầy hỏi:** *"Tại sao chuyển sang tọa độ Jacobian lại tăng tốc được hơn 5 lần?"*
   - **Đáp án:** Trên tọa độ Affine $(x, y)$, mỗi phép cộng/nhân đôi điểm trong vòng lặp 256-bit đều phải tính nghịch đảo modulo `mod_inv` (tốn CPU nhất). Tọa độ xạ ảnh Jacobian $(X, Y, Z)$ với $x = X/Z^2, y = Y/Z^3$ gom phép chia vào mẫu số $Z$, toàn bộ vòng lặp chỉ dùng nhân/bình phương và chỉ chia modulo đúng **1 lần duy nhất** ở cuối.

8. **Thầy hỏi:** *"ECC có nhược điểm nào so với RSA trong bảng Benchmark không?"*
   - **Đáp án:** Có, ở bước **Verify chữ ký**, `RSA-3072` (`~0.26 ms` trên máy em) nhanh hơn `ECC secp256r1` (`~4.41 ms`) do RSA dùng số mũ công khai nhỏ $e = 65537$. Nhưng ECC vượt trội hoàn toàn ở kích thước khóa (`12x`), tạo khóa (`~759x`), ký (`~24x`) và phù hợp cho thiết bị hạn chế băng thông / Forward Secrecy.

9. **Thầy hỏi:** *"Hệ thống này còn lỗ hổng gì nếu đem chạy thực tế (Production)?"*
   - **Đáp án:** Nhóm đã chỉ rõ 3 giới hạn ở Chương 6.2: (1) Python BigInt chưa đạt *constant-time* ở mức CPU → có thể dính *Timing Side-Channel*, thực tế cần thay lõi bằng OpenSSL/Rust/`libsodium`; (2) Chưa có xác thực chéo vân tay khóa (*Safety Number / QR / CA nội bộ*) để chống Server tráo Public Key ngay lúc đăng ký (*Key Substitution*); (3) Chưa triển khai *Double Ratchet* và *Hybrid Post-Quantum (ML-KEM)*.

10. **Thầy hỏi:** *"Tại sao nếu khởi động lại Server thì token phiên bị mất? Và làm sao tin được kết quả cài đặt đúng chuẩn?"*
    - **Đáp án:** Do khóa HMAC-SHA256 ký Bearer token (`_EPHEMERAL_SECRET`) mặc định sinh ngẫu nhiên trong RAM mỗi lần bật server nếu không cấu hình `SIS_SESSION_SECRET`. Về độ chuẩn xác thuật toán, toàn bộ lõi đã qua `13/13` test kiểm chứng vector **NIST SP 800-38D CAVP**, `toy_p97` đếm điểm, `Affine == Jacobian`, và `cli_demo.py` giao tiếp đồng nhất với WebCrypto trình duyệt.
