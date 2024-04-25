# Cashhat The Ripper

## [1] TỔNG QUAN

- Đề gửi 1 file zip, sau khi giải nén lại thấy 1 file zip nữa có password protected
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/eda7491c-3ace-48bb-98e2-df64e3479f01)

- Để tìm được flag ở bài này, chúng ta cần phải unzip được file challenge.zip vì có thể trong file zip này có chứa flag
- Tuy nhiên, password để unzip không được cung cấp

## [2] SOLVE

- Sử dụng kỹ thuật brute force để unzip file
- Tool được sử dụng: `fcrackzip`
- File password được sử dụng: `rockyou.txt`
- Command: `fcrackzip -D -p rockyou.txt -u challenge.txt`
- Pass giải nén: `123mango`
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/3c4e571c-9da5-4100-aa52-b55bb78d69da)

- Flag: `flag{W34k_P4ssw0rds_St4Nd_n0_Ch4nc3}`
