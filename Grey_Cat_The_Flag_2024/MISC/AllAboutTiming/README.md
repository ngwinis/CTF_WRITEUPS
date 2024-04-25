# All About Timing

## [1] TỔNG QUAN

- Đề yêu cầu kết nối tới server `challs.nusgreyhats.org` với port `31111`
- Khi kết nối tới server, ta nhận được yêu cầu đoán 1 số và nhập vào, server sẽ kiểm tra xem có đúng với số trên server hay không<br>
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/5762ef2b-8667-4287-9dfa-0567273a6a99)

## [2] PHÂN TÍCH

- File code python được gửi kèm mô tả cách hoạt động trên server:<br>
  ![image](https://github.com/ngwinis/CTF_WRITEUPS/assets/127127056/24b1cb61-9dae-4589-8086-592d812e9857)

- Số `n` random được cung cấp 1 `seed` là số int của thời gian thực
- Điều đó có nghĩa là ta cần phải tìm được số random được server sinh ra vào thời gian thực đó để có thể lấy được flag
## [3] SOLVE

- Đặc điểm của việc tạo random với `seed` là khi cung cấp 1 số bất kì cho `seed` thì sẽ `random.randint()` sẽ chỉ sinh ra 1 số ngẫu nhiên duy nhất
- Ở đây `seed` được cung cấp 1 số nguyên biểu diễn thời gian chương trình bắt đầu được thực thi
- Mục tiêu: Tìm được thời gian thực khi server chạy chương trình đó
- Muốn làm được điều đó chúng ta chỉ cần tạo 1 chương trình tạo random tương tự với code trên rồi gửi số random nhận được lên server sẽ ra flag

- Flag: `grey{t1m3_i5_a_s0c1al_coNstRucT}`
## [4] PAYLOAD

Để thuận tiện hơn trong việc xử lý các dữ liệu gửi và nhận từ server, có thể sử dụng [Payload](distribution/payload.py)
