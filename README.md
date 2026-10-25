Sinh viên thực hiện: Bùi Hoàng Long

Mã sinh viên: K235480106044

Lớp: K59KMTK01

NỘI DUNG YÊU CẦU:

bài tập môn AN toàn và bảo mật thông tin.

bài 1: Mã hoá AES : Mã hoá đối xứng (mã hoá, giải mã cùng dùng 1 khoá)

- tạo app (not web) : console, form

  1. sinh khoá AES

  2. lưu khoá ra file

  3. import khoá từ file

  4. mã hoá 1 đoạn văn bản -> kq mã hoá ra màn hình

  5. mã hoá 1 file -> lưu vào 1 file.

  y/c: thử nghiệm với file có kích thước lớn (hàng GB)

       tính thời gian mã hoá, thời gian giải mã

       compare theo bytes: file nguồn và file giải mã

   => Kết luận dựa theo số liệu thu được

bài tập 2: mã hoá RSA : mã hoá bất đối xứng (mã hoá 1 chìa, giải mã bằng chìa còn lại)

  tạo app: (.NET)

 1. sinh cặp khoá

 2. xuất cặp khoá ra file (pem)

 3. view pem: cùng các ý nghĩa các byte trong format pem

 4. nhập 1 file pem : public key được n và e

    nhập 1 file pem : priavte key được n và e, d, ...

5. mã hoá dữ liệu sử dụng key vừa import:

    dữ liệu là 1 mảng byte ko quá 190 byte

   (khoá AES 256 bit <=> 32 byte (base64))

   kq mã hoá đc mảng byte (lưu ở dạng base64) => lưu file

6. giải mã: đầu vào là pem, file chứa data đã mã hoá (base64)

   so sánh kq giải mã với nguồn trước khi mã hoá.

7. viết đoạn code đánh giá tốc độ mã hoá, giải mã

   xem dùng khoá nào (pulic key: n, e bé), private key(n, d to đùng)

   thì tốc độ ra sao?

8. tạo giao diện sinh chuỗi băm SHA256 bít

   khi thay đổi đầu vào => băm mới: đánh giá sự thay đổi của kq băm  khi dữ liệu đầu vào thay đổi (rất ít)

9. CHỮ KÝ SỐ: thực ra là dùng RSA với khoá bí mật cho kq băm của dữ liệu => được gọi là chữ ký số của dữ liệu đó.

=> dữ liệu khác nhau : có chữ ký số khác nhau (của cùng người ký)

MONG MUỐN: 

  + cùng 1 dữ liệu, 

  + Cùng 1 người ký (cùng private key) 

  =>thì chữ ký số cũng khác nhau với các lần ký khác nhau

HÃY ĐỀ XUẤT PHƯƠNG PHÁP ĐỂ ĐẠT ĐƯỢC ĐIỀU NÀY.

BÀI LÀM 

Bài 1:

1. Người dùng nhập lựa chọn 1 trên màn hình dòng lệnh để yêu cầu hệ thống tạo một khóa bí mật mới. Chương trình thực hiện khởi tạo và sinh khóa ngẫu nhiên với độ dài khóa là 128 bit, sau đó mã hóa và hiển thị kết quả trực quan dưới dạng chuỗi Base64 ngay trên giao diện bảng điều khiển.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 203339" src="https://github.com/user-attachments/assets/1f71bc34-f138-4398-a413-e90011ebe02c" />

2. Người dùng nhập lựa chọn 2 và tiến hành chỉ định tên tệp/đường dẫn lưu trữ khóa là aes.key. Hệ thống tiếp nhận đường dẫn, ghi dữ liệu khóa hiện tại đang nằm trên bộ nhớ xuống tệp tin trên ổ đĩa và phản hồi lại bằng dòng thông báo xác nhận thành công.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 203353" src="https://github.com/user-attachments/assets/8af0549f-8c43-4bdf-9502-c24a3528949b" />

3. Người dùng nhập lựa chọn 3 và cung cấp lại đường dẫn tệp aes.key vừa lưu trước đó.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 203537" src="https://github.com/user-attachments/assets/9dd2328d-8dc4-4c17-9edd-40a60f2abbf5" />

4. 
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 203706" src="https://github.com/user-attachments/assets/2d1407d4-aaa2-492c-b483-6007cbedb515" />

<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 203729" src="https://github.com/user-attachments/assets/aaf89cbd-0bcc-4cad-a929-64f8c5576ef3" />

5. Kết luận

Tính đúng đắn: Thuận nghịch hoàn toàn (không mất mát dữ liệu), kiểm tra từng byte trên các mức kích thước 100 MB, 500 MB và 1 GB đều khớp tuyệt đối.

Kích thước file mã hóa: Luôn lớn hơn file gốc đúng 32 byte (16 byte IV + 16 byte đệm PKCS#7), chi phí lưu trữ phát sinh không đáng kể.

Tốc độ & Thời gian:Thời gian xử lý tăng tuyến tính theo kích thước file ($O(n)$) (ví dụ mã hóa 1 GB chỉ mất khoảng 1,22 giây.Tốc độ mã hóa ổn định ở mức 700–900 MB/s). 

Giải mã thường nhanh hơn mã hóa (đạt tới ~1,49 GB/s ở file 1 GB) do tính chất song song của chế độ CBC.Bộ nhớ (RAM): Sử dụng cơ chế đọc/ghi theo luồng (buffer 1 MB), giúp lượng RAM tiêu thụ luôn thấp và ổn định, không phụ thuộc vào dung lượng file
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-24 174428" src="https://github.com/user-attachments/assets/6a4fb35c-d3f4-404f-8ea4-47b496d07042" />


Bài 2:

1 và 2. 
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 204527" src="https://github.com/user-attachments/assets/1be334f3-d373-4c8c-b3fd-8f12dde7d101" />

<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 212054" src="https://github.com/user-attachments/assets/66b2651c-9444-433c-870f-81a494a84abe" />

3.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 212347" src="https://github.com/user-attachments/assets/23ab68f6-4dff-46f8-bed8-499660b16f92" />
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 212428" src="https://github.com/user-attachments/assets/f8be8392-2d4b-41f3-b358-03fe23090482" />

4.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 212531" src="https://github.com/user-attachments/assets/7ca74995-e601-4da9-bdea-6029a8e0ac5f" />

<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 212639" src="https://github.com/user-attachments/assets/bec92426-7cec-4e60-a62d-81a38eeb9f37" />

5.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 212931" src="https://github.com/user-attachments/assets/098e03a7-4e28-41aa-9cd3-faf86969f2f7" />

6.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 213129" src="https://github.com/user-attachments/assets/191c940e-5409-4916-9aea-e49b4dada85c" />

7. 
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 213725" src="https://github.com/user-attachments/assets/e801b890-8500-4359-acbd-9545c09eb36b" />

8.
<img width="2559" height="1599" alt="Ảnh chụp màn hình 2026-10-23 213957" src="https://github.com/user-attachments/assets/202ed526-9887-408c-9bdc-bb17d56ba07d" />









