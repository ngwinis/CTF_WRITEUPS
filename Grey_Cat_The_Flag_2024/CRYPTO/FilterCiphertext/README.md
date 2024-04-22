# Filter Ciphertext

## [1] TỔNG QUAN
- Đề yêu cầu kết nối tới server `challs.nusgreyhats.org` với port `32222`
- Nếu giải được bài này thì bài tiếp theo Filter Plaintext sẽ được mở ra và có ý tưởng gần tương tự
- Khi kết nối tới server, nhận được yêu cầu nhập vào đoạn văn bản (dạng mã hex) đã bị mã hoá, server sẽ giải mã và gửi lại cho user
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/fcb916d3-5bbf-4545-a48a-e20f0c31aa72)
  
- Đoạn mã hex mà server gửi tới giống như password (đã bị mã hoá) để server có thể gửi được flag

## [2] PHÂN TÍCH
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/fd5e9b80-a39c-46d2-b8b7-0b252d34fb15)
  
- Nếu nhập vào đúng `Encrypted secret` thì server sẽ trả về "Nice try.", ngược lại, input sẽ được giải mã thông qua hàm `decrypt()`
- Nếu giải mã input ra đúng với `secret` (được tạo random) thì sẽ trả về flag, nếu không thì sẽ in ra mã hex đã được giải mã.
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/0fbfbb5c-6a74-4c86-9259-9c893cedd789)
  
- Ở đây có thể dễ dàng nhận thấy thuật toán mã hoá cho `secret` là AES với mode ECB (chia plaintext thành chuỗi các khối 16 bytes)
- Ở vòng for đầu tiên, hàm kiểm tra xem input mà user nhập vào có block nào trùng với đoạn con bất kì của `secret_enc` hay không, nếu có sẽ loại bỏ block đó
- Vòng for thứ 2 sẽ giải mã input nhập vào
=> Cần bypass được vòng for trên mà vẫn giữ được `secret_enc` để vòng for dưới giải mã ra đúng `secret`

## [3] SOVLE
- Giả sử `secret_enc` được cho như hình dưới, ta chỉ cần chia xâu đó thành các block, mỗi block có 16 bytes
- `Nhập 1 xâu với mỗi block được nhân 2`<br>
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/ac548dfc-55bf-4a36-b882-7a4431fd207a)

  ***Giải thích***

  ```
    secret_enc = fb7b2f08cfcc02096c80baeb4092b2419e389d9734983e8ff83547882f40130ecede764867a620d6ebbbf9dfb8465ebaabcc0558979882478900c1052965b51050519402a275deb28ca151bdd30afda4
    Blocks:
      - fb7b2f08cfcc02096c80baeb4092b241
      - 9e389d9734983e8ff83547882f40130e
      - cede764867a620d6ebbbf9dfb8465eba
      - abcc0558979882478900c1052965b510
      - 50519402a275deb28ca151bdd30afda4
    Input cần nhập: fb7b2f08cfcc02096c80baeb4092b241fb7b2f08cfcc02096c80baeb4092b2419e389d9734983e8ff83547882f40130e9e389d9734983e8ff83547882f40130ecede764867a620d6ebbbf9dfb8465ebacede764867a620d6ebbbf9dfb8465ebaabcc0558979882478900c1052965b510abcc0558979882478900c1052965b51050519402a275deb28ca151bdd30afda450519402a275deb28ca151bdd30afda4
  ```
  - Mỗi block có độ dài 16 bytes, mỗi byte ứng với 2 ký tự mã hex nên 1 block có 32 ký tự
  - Lý do mỗi block nhân 2 là nằm ở vòng for đầu tiên của hàm `decrypt()`
  - Mỗi lần remove phần tử đầu tiên của mảng, các phần tử khác sẽ được dồn lên, lần duyệt vòng for tiếp theo sẽ không duyệt lại phần tử có chỉ số trước đó => Cuối cùng input còn lại đúng với `secret_enc`
  ```
  secret_enc = a[1, 2, 3, 4, 5, 6]
  input = a[1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6]
  
  a[0] = 1 => có trong block => remove(a[0]) => a[1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6]
  a[0] = 1
  a[1] = 2 => có trong block => remove(a[1]) => a[1, 2, 3, 3, 4, 4, 5, 5, 6, 6]
  a[1] = 2
  a[2] = 3 => có trong block => remove(a[2]) => a[1, 2, 3, 4, 4, 5, 5, 6, 6]
  a[2] = 3
  ...
  
  => a[1, 2, 3, 4, 5, 6]
  ```
## [4] PAYLOAD
  [Payload](distribution/decrypt.py)
