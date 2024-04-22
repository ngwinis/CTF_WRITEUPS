# Filter Ciphertext

## TỔNG QUAN
![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/786befab-7c31-4645-95ca-e0eddf246902)

- Đề yêu cầu kết nối tới server `challs.nusgreyhats.org` với port `32222`
- Nếu giải được bài này thì bài tiếp theo Filter Plaintext sẽ được mở ra và có ý tưởng gần tương tự
- Khi kết nối tới server, nhận được yêu cầu nhập vào đoạn văn bản (dạng mã hex) đã bị mã hoá, server sẽ giải mã và gửi lại cho user
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/fcb916d3-5bbf-4545-a48a-e20f0c31aa72)
- Đoạn mã hex mà server gửi tới là 
