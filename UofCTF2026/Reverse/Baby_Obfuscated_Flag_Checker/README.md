# Baby (Obfuscated) Flag Checker

## [1] TỔNG QUAN

Trong file `baby.py`, phần lớn code là **state machine** `while True` + `if` lồng nhau để gây nhiễu. Tuy nhiên có đoạn tạo chuỗi bằng cách:

- lấy một list số,
- XOR từng số với `GgS`,
- `chr()` rồi `join()` lại. 

## [2] PHÂN TÍCH

Trong logic của chương trình, ta thấy 4 hàm đặt tên loạn xạ nhưng **đều làm đúng 1 việc: XOR**:

```py
def g0GOsquiD(a, b): return a ^ b
def G0g0sQu1D_116510(a, b): return a ^ b
def gOg0sQuId(a, b): return a ^ b
def G0G0SQU1D(a, b): return a ^ b
```



Vì vậy mọi biểu thức kiểu `G0G0SQU1D(gOg0sQuId(g0GOsquiD(...)))` thực chất chỉ là **XOR của các hằng số** → rút gọn về số nhỏ (index / key / data).

---

## Khôi phục key `GgS`

Solver tính `GgS` từ 4 hằng `t1..t4` theo công thức:

```py
GgS = (t1 ^ t2) + t3 & t4
```



Lưu ý độ ưu tiên toán tử Python khiến biểu thức trên tương đương:

[
GgS = (((t1 \oplus t2) + t3)\ &\ t4)
]

Với dữ liệu bài này, kết quả ra `GgS = 125` (0x7d).

---

## Giải mã và ghép flag

Bài chia flag thành nhiều “mảnh” số trong `G0gosQu1D`, và một list `SqUId` quyết định thứ tự ghép. Vòng lặp cốt lõi:

```py
flag = ""
for idx in SqUId:
    segment = "".join(chr(val ^ GgS) for val in G0gosQu1D[idx])
    flag += segment
print(flag)
```



Chạy ra flag như comment trong solver: 

---

## Flag

`uoftctf{d1d_y0u_m0nk3Y_p4TcH_d3BuG_r3v_0r_0n3_sh07_th15_w17h_4n_1LM_XD???}`

---

### File đính kèm

* Challenge gốc: 
* Solver (đã rút gọn/khôi phục): 
*
