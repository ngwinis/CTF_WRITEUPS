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
  > * Giả sử `Encrypted secret` chỉ có 3 block, và các biến "res" là `c[]`, "tmp" là `b[]` còn "block" là `a[i*2+1]` và "cipher.decrypt(block)" là `a[i*2+2]`
  > * Ta có công thức XOR sau:
  >   * c[1] = a[2] ^ b[1]
  >   * b[2] = a[1] ^ c[1]
  >   * c[2] = a[4] ^ b[2]
  >   * b[3] = a[3] ^ c[2]
  >   * c[3] = a[6] ^ b[3]
  >   * b[4] = a[5] ^ c[3]
  > * Nếu `c[1]`, `c[2]` và `c[3]` không có trong `secret` thì server sẽ trả về `c[1]c[2]c[3]`
  > * Như vậy, những biến có thể biết được giá trị là `c[]` và `a[i*2+1]` còn các giá trị `b[]` ngay từ đầu là random và `a[i*2+2]` là các decrypted block không có key nên không thể biết được giá trị
  > * Tuy nhiên, nếu input là `a[i*2+1]` thì ngay cả các giá trị `c[]` chúng ta cũng không thể biết được do chúng không được in ra
- Như vậy, mục tiêu cần đạt được là vừa phải biết được các giá trị `c[]` vừa phải tìm được các giá trị `b[]`
## [2] SOLVE
- Phép XOR có tính chất `x ^ y = z` <=> `x ^ z = y` <=> `y ^ z = x` và `x ^ x = 0` <=> `x ^ 0 = x`
- Lại có nhận xét như sau:
  > * Các block nhập vào sẽ sử dụng các block của `Encrypted secret` theo thứ tự lần lượt
  > * Vẫn sử dụng cách đặt tên biến như trên
  > * Gấp đôi block thứ 2 của `Encrypted secret` còn các block khác giữ nguyên
  > * Ta có công thức XOR sau:
  >   * c[1] = a[2] ^ b[1]
  >   * b[2] = a[1] ^ c[1] 
  >   * c[2] = a[4] ^ b[2]
  >   * b[3] = a[3] ^ c[2]
  >  
  >   *
  >   * c[3] = a[4] ^ b[3] = a[4] ^ a[3] ^ c[2] = a[4] ^ a[3] ^ a[4] ^ b[2] = a[3] ^ b[2]
  >   * b[4] = a[3] ^ c[3] `= b[2]`
  >   * c[4] = a[6] ^ b[2]
  >   * b[5] = a[5] ^ c[4]
  >
  > * Tương tự ta sẽ gấp đôi block thứ 3 của `Encrypted secret` còn các block khác giữ nguyên

- ***Nhận xét***:
  * c[1] và c[2] sau khi XOR thấy trùng với `secret` nên bị loại bỏ, decrypted block được in ra sẽ bắt đầu từ `c[3]`
  * Sau khi có được `c[3]` thì `b[4]` được tạo ra bởi `a[3] ^ c[3]` đều là 2 biến có thể biết được
  * Lại có `c[3] = a[3] ^ b[2]`, mà theo tính chất, ta có `b[2]` = `a[3] ^ c[3]` nên rút ra kết luận rằng `b[4] = b[2]`
  * Quay trở lại dòng thứ 2 `b[2] = a[1] ^ c[1]`. Ở đây, chỉ có duy nhất `c[1]` là không thể biết do không được in ra
  * Như vậy, ta chỉ cần thực hiện phép XOR `c[1] = a[1] ^ b[2]` là ta tìm được `c[1]`
  * Tương tự, ta lại gửi lên server đoạn mã hex với block thứ 3 được nhân đôi
  * Thực hiện quá trình tương tự ta nhận được `c[2]`

- ***Rút ra kết luận***: Để tìm được các `c[]` chúng ta chỉ cần gấp đôi block phía sau để tìm `b[]` và XOR lại
  * Tuy nhiên, ta chỉ giả sử có 3 block duy nhất, nên block cuối cùng được gấp đôi là block thứ 3, tức là chỉ tìm được `c[1]` và `c[2]` thiếu `c[3]` để có thể tìm được `secret_enc`
  * Để giải quyết vấn đề này, ta chỉ cần tạo ra 1 block bất kỳ có độ dài tương đương các block khác chèn thêm vào input và gấp đôi block đó lên sẽ tìm được `c[3]`

- `Flag: grey{pcbc_d3crypt10n_0r4cl3_3p1c_f41l}`
  
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/32e2de6f-8d18-4ff4-9a72-07576509870e)

## [3] PAYLOAD
  - Để thuận tiện hơn trong việc xử lý các dữ liệu gửi và nhận từ server, có thể sử dụng [Payload](distribution/decrypt.py)
