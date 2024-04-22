# Filter Plaintext

## [1] TỔNG QUAN
- Đề yêu cầu kết nối tới server `challs.nusgreyhats.org` với port `32223`
- Khi kết nối tới server, nhận được yêu cầu nhập vào đoạn văn bản (dưới dạng mã hex) đã được mã hoá
- Bài này flag bị mã hoá với key là `secret_key` mà `secret_key` là mã MD5 của `secret`
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/69bb8f47-51d5-4f49-a0ff-f091953a4ea1)
  => Để giải được flag, cần tìm được `secret`
- Phân tích:
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/81eabe16-7722-4559-b62b-2b91b0d31453)
- Nếu nhập đúng `Encrypted secret` mà server trả về thì sẽ bị câu lệnh rẽ nhánh if trong vòng for loại bỏ toàn bộ, cuối cùng, server sẽ không in ra gì cả
- Nhận xét thấy vòng lặp for có thể mô tả lại như sau:
  > * Giả sử `Encrypted secret` chỉ có 2 block và "res" là `c[]`, "tmp" là `b[]` còn "block" là `a[i*2+1]` và "cipher.decrypt(block)" là `a[i*2+2]`
  > * Ta có công thức XOR sau:
  >   * c[1] = a[2] ^ b[1]
  >   * b[2] = a[1] ^ c[1]
  >   * c[2] = a[4] ^ b[2]
  >   * b[3] = a[3] ^ c[2]
  > * Nếu c[1] và c[2] không có trong `secret` thì server sẽ trả về c[1]c[2]
  > * Như vậy, những biến có thể biết được giá trị là c[] và a[i*2+1] còn các giá trị b[] ngay từ đầu là random và a[i*2+2] là các decrypted block không có key nên không thể biết được giá trị
  > * 
## [3] SOLVE
