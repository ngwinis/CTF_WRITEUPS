# bedtime

## Tổng quan

- File challenge: [`bedtime`](./bedtime)

## Hướng tiếp cận

Lúc mới chạy thử binary, chương trình chỉ đọc một dòng input rồi trả về:

```text
> Error: "bad"
```

Binary là **ELF 64-bit, static PIE, stripped**, đồng thời có khá nhiều dấu vết của **Rust**. Vì file bị strip sạch symbol và còn static, nếu đi theo hướng decompile toàn bộ từ đầu thì sẽ rất mất thời gian. Cách làm hiệu quả hơn là:

1. Tìm format input thật sự,
2. Bóc cấu trúc dữ liệu mà chương trình khởi tạo sẵn,
3. Hiểu bài toán lõi mà hàm kiểm tra đang giải,
4. Đọc flag trực tiếp từ trạng thái của các test đó.

## 1. Format input không phải chuỗi ký tự thường

Sau khi lần theo đoạn parse đầu vào, có thể thấy chương trình **không đọc flag dưới dạng string**. Nó đọc một dãy **số nguyên thập phân**, sau đó tách chúng thành nhiều nhóm bằng giá trị đặc biệt:

```text
9999
```

Nói cách khác, input có dạng kiểu như:

```text
x x x 9999 y y 9999 z z z ...
```

Mỗi đoạn nằm giữa hai dấu `9999` được xem như **một group độc lập**.

Điểm quan trọng là binary tạo ra đúng **384 group** để kiểm tra.

Vì 384 = 48 * 8, đây là dấu hiệu rất rõ rằng kết quả cuối cùng nhiều khả năng sẽ được pack thành **48 byte**, tức đúng cỡ của một flag ASCII tương đối dài.

---

## 2. Dữ liệu khởi tạo gồm 384 thành phần

Khi tách vùng dữ liệu mà chương trình nạp vào trước khi xác minh, mỗi entry có kích thước **32 byte** và có thể đọc thành dạng:

```c
struct Item {
    u64 len;
    u64 ptr;
    u64 len_again;
    u64 m;
};
```

Trong đó:

- `ptr` trỏ tới một mảng số nguyên,
- `len` là số phần tử của mảng đó,
- `m` là một tham số riêng của entry.

Nếu dereference `ptr`, ta thu được một danh sách số, ví dụ kiểu như:

```text
[272, 32, 807, 559, 295, 47, 822, 574, 326, 78]
```

và đi kèm với nó là một giá trị `m`, ví dụ `11`.

Nhìn vào cấu trúc này, có thể đoán rằng mỗi item biểu diễn một **game state** gồm:

- nhiều heap / pile,
- mỗi lượt được rút tối đa `m` quân trên **một** heap.

## 3. Nhận diện bài toán

Khi kiểm tra hàm lõi, phần “nước đi tối ưu” của chương trình có dạng rất quen thuộc: nó tìm một heap và một lượng rút sao cho trạng thái sau bước đi trở thành trạng thái thua cho đối thủ.

Với trò chơi:

- có nhiều heap,
- mỗi lượt chọn **một** heap,
- rút từ `1..m` phần tử,

thì mỗi heap sẽ có giá trị:

```text
heap % (m + 1)
```

và trạng thái thua (cold / losing position) là khi:

```text
(heap[0] % (m+1)) ^ (heap[1] % (m+1)) ^ ... ^ (heap[n-1] % (m+1)) == 0
```

Đây chính là điều kiện mà binary đang kiểm tra.

Nói ngắn gọn: mỗi item thực chất là **một subtraction game** độc lập, và binary quan tâm tới việc trạng thái ban đầu của game đó là **thắng hay thua**.

---

## 4. Phần input chỉ để đánh lạc hướng

Đoạn xác minh nhận từng group số nguyên từ input, rồi dùng chúng như một chuỗi nước đi cho từng game. Tuy nhiên, nếu mục tiêu cuối cùng chỉ là lấy flag thì không cần dựng lại toàn bộ chuỗi input hợp lệ.

Lý do là:

- Binary đã khởi tạo sẵn **384 game state**,
- Với mỗi game, chỉ cần biết nó là **cold** hay **hot**,
- Thông tin thắng/thua đó đã đủ để suy ra bit tương ứng trong output cuối.

Vì vậy thay vì solve theo kiểu “tìm đúng toàn bộ dãy số để chương trình in ra flag”, ta đi thẳng vào phần **encoding flag** mà tác giả đã nhúng trong danh sách 384 game.

## 5. Từ 384 game sang 384 bit

Với từng item:

1. Lấy mảng heap `arr`,
2. Lấy giới hạn `m`,
3. Tính:

    ```python
    x = 0
    for v in arr:
        x ^= v % (m + 1)
    ```

4. nếu `x == 0` thì đây là **cold position**,
5. ngược lại là **winning position**.

Mapping đúng ở đây là:

- `cold`  -> bit `1`
- `hot`   -> bit `0`

Làm việc đó cho toàn bộ **384 item**, ta thu được **384 bit**.

## 6. Pack bit thành byte

Sau khi có 384 bit, chương trình pack chúng theo thứ tự **MSB-first**, tức cứ 8 bit sẽ ghép thành 1 byte:

```python
out = []
for i in range(0, 384, 8):
    byte = 0
    for b in bits[i:i+8]:
        byte = (byte << 1) | b
    out.append(byte)
```

## 7. Solve
- Script: 

> **Flag**: `dice{regularly_runs_like_mad_to_game_of_matches}`