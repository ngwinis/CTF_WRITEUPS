# explorer

## Tổng quan

- Challenge: `explorer`
- Category: Reverse Engineering
- Files chính:
  - [`dist/bzImage`](./dist/bzImage)
  - [`dist/initramfs.cpio`](./dist/initramfs.cpio)
  - [`solve.c`](./solve.c)
  - [`upload.py`](./upload.py)

## Hướng tiếp cận

Đây không phải kiểu challenge chỉ cần mở binary bằng IDA rồi lần theo một hàm check duy nhất. Bộ file phát cho mình là một **Linux kernel image** kèm **initramfs**, còn service remote chỉ cho mình vào qua:

```text
nc explorer.chals.dicec.tf 1337
```

Ý tưởng đúng vì thế là:

1. Bóc `initramfs` để xem môi trường boot.
2. Tìm component nào tạo ra challenge thật sự.
3. Reverse driver đứng sau `/dev/challenge`.
4. Viết solver chạy **bên trong guest**, rồi upload nó lên remote để lấy flag.

Điểm quan trọng nhất của challenge là: **không nói chuyện trực tiếp với server để lấy flag**. Socket remote chỉ là console của VM. Muốn solve thì phải vào được shell trong guest rồi tương tác với `/dev/challenge` từ bên trong.

## 1. Môi trường khởi động chỉ là vỏ bọc

Sau khi giải nén `initramfs.cpio`, phần đáng chú ý nhất là script `/init`. Nó chỉ làm vài việc cơ bản như mount các pseudo-filesystem cần thiết, tạo device node cho challenge, rồi đưa mình vào shell của user thường.

Nói cách khác, phần logic kiểm tra flag **không nằm trong userland**, mà nằm ở phía kernel.

Từ đây có thể chốt khá nhanh:

- `bzImage` mới là file cần reverse chính,
- `initramfs` chủ yếu để dựng môi trường tối giản,
- trọng tâm bài toán là `/dev/challenge`.

## 2. Driver challenge nằm trong kernel và được viết bằng Rust

Khi lần theo strings và các thành phần được nhúng trong kernel, có thể thấy challenge device được cài dưới dạng một **misc device** viết bằng **Rust**.

Điều này giải thích luôn tên flag và cảm giác “lạ tay” khi reverse: logic không nằm trong một binary C quen thuộc, mà ở một Rust kernel module được build thẳng vào image.

Driver quản lý một mê cung 3 chiều và expose state của nó qua các lệnh `ioctl`. Thay vì nhập một chuỗi input cố định, mình phải thăm dò map, di chuyển trong mê cung, tránh trap room, rồi tới đúng room đích để đọc flag.

## 3. Interface của `/dev/challenge`

Sau khi bóc phần ioctl handler, có thể khôi phục được bộ command chính như sau:

```c
0x80046480  -> get seed
0x80046481  -> get dim_x
0x80046482  -> get dim_y
0x80046483  -> get dim_z
0x80046484  -> get step_count
0x80046485  -> get room_status
0x80046486  -> get exits_bitmask
0x80406487  -> get flag buffer (64 bytes)
0x40046488  -> move(direction)
0x00006489  -> reset
```

Trong đó:

- `room_status = 0`: room thường
- `room_status = 1`: room đích
- `room_status = 2`: trap room

Các hướng di chuyển được encode như sau:

- `0 = -Y`
- `1 = +X`
- `2 = +Y`
- `3 = -X`
- `4 = +Z`
- `5 = -Z`

`get_exits_bitmask` trả về bitmask 6 bit cho biết từ room hiện tại có thể đi theo hướng nào.

Nhìn đến đây thì bài toán đã khá rõ: đây là một bài **maze exploration** trên graph 3D, còn device chỉ là giao diện để query trạng thái cục bộ của room hiện tại.

## 4. Vì sao không thể chỉ viết script chạy từ máy mình

Lúc đầu rất dễ nghĩ rằng chỉ cần viết một script Python dùng socket tới `explorer.chals.dicec.tf:1337` là đủ. Nhưng cách đó không đúng.

Lý do là remote service không expose giao thức tùy biến nào cho mê cung cả; nó chỉ nối console của máy ảo ra ngoài. Tức là:

- từ máy mình chỉ thấy một shell remote,
- còn `/dev/challenge` chỉ tồn tại **bên trong** guest,
- nên solver phải được upload vào guest rồi chạy tại đó.

Đây cũng là lý do trong thư mục mình giữ riêng:

- [`solve.c`](./solve.c): solver tương tác với `/dev/challenge`
- [`upload.py`](./upload.py): script kết nối tới remote, upload binary và chạy solver

## 5. Mô hình của mê cung

Mỗi lần mở device, driver tạo ra một mê cung 3D với kích thước có thể đọc được qua các ioctl `get_dim_*`.

Từ góc nhìn người giải, không cần phục dựng lại toàn bộ thuật toán sinh map ở phía kernel. Chỉ cần tận dụng đúng interface mà driver cho sẵn:

1. `reset` về room gốc,
2. hỏi `room_status`,
3. hỏi `exits_bitmask`,
4. thử đi từng hướng hợp lệ,
5. nếu gặp trap thì quay lại trạng thái trước,
6. nếu gặp room đích thì gọi `get_flag`.

Vì graph của bài là một mê cung trên lưới 3D, mình có thể gán cho mỗi room một tọa độ tương đối `(x, y, z)` kể từ điểm xuất phát. Điều đó đủ để đánh dấu `visited` mà không cần biết internal ID của room trong kernel.

## 6. Hướng solve hiệu quả

Có hai hướng tự nhiên:

- BFS bằng cách `reset + replay path` cho từng node,
- hoặc DFS trực tiếp trên device và chỉ replay khi cần recover từ trap.

Mình chọn cách thứ hai vì gọn hơn và ít tốn chi phí hơn khi chạy trong môi trường remote.

Ý tưởng của solver trong [`solve.c`](./solve.c):

- mở `/dev/challenge`,
- đọc kích thước map,
- DFS trên mê cung,
- lưu stack đường đi hiện tại,
- nếu bước vào `trap room` thì `reset` rồi replay lại stack hiện tại,
- nếu gặp `room_status == 1` thì gọi `get_flag` và in ra stdout.

Cách làm này đủ ổn định vì driver luôn cho mình biết đầy đủ exits ở room hiện tại, còn trap room chỉ cần coi là node không mở rộng tiếp.

## 7. Upload solver lên remote

Sau khi có solver, bước còn lại là đưa nó vào guest. Remote shell là BusyBox rất tối giản, nên cách dễ dùng nhất là upload binary dưới dạng base64 rồi decode lại trong `/tmp`.

Script [`upload.py`](./upload.py) làm đúng việc đó:

1. connect tới `explorer.chals.dicec.tf:1337`,
2. chờ shell của guest sẵn sàng,
3. upload binary `solve`,
4. decode ra `/tmp/solve`,
5. `chmod +x`,
6. chạy `/tmp/solve` và đọc flag.

Điểm cần lưu ý ở challenge này là parser shell khá khó chịu vì console có echo, prompt xen vào output và đôi lúc còn kèm escape sequence. Vì vậy uploader cần xử lý stream cẩn thận, nếu không rất dễ tưởng command fail trong khi thực ra shell đã chạy xong.

## 8. Một chi tiết dễ gây nhiễu khi reverse local

Khi reverse bản local trong `bzImage`, chuỗi trả về ở nhánh `get_flag` có thể xuất hiện như một placeholder kiểu test flag. Điều này rất dễ khiến mình nghĩ rằng challenge chỉ có fake flag.

Thực tế, phần quan trọng của bài không nằm ở chuỗi hardcode đó mà nằm ở:

- việc xác định đúng interface ioctl,
- hiểu mê cung được encode ra sao,
- và viết solver đủ ổn định để chạy trên remote.

Khi upload solver lên server thật và để nó tự dò đường trong mê cung, output thu được là flag chính xác của challenge.

## 9. Build và chạy

Build solver tĩnh:

```bash
musl-gcc -static -O2 -s solve.c -o solve
```

Sau đó upload và chạy trên remote:

```bash
python3 upload.py BIN=./solve
```

## Solve

- Solver: [`solve.c`](./solve.c)
- Uploader: [`upload.py`](./upload.py)

> **Flag**: `dice{twisty_rusty_kernel_maze}`
