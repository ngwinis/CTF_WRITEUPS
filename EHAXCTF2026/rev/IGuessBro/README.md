# I Guess Bro

## **[1] TỔNG QUAN**

* Challenge cung cấp 1 file ELF64 (RISC-V) tên `chall`.

* Khi chạy thử:

  ```bash
  $ ./chall
  RISC-V Crackme Challenge
  'I Guess Bro' - Hard Mode
  Enter the flag:
  ```

* Nếu nhập sai:

  ```
  I Guess Bro...
  ```

* Trong binary có xuất hiện 2 chuỗi giống flag:

  ```
  EH4X{n0t_th3_r34l_fl4g}
  EH4X{try_h4rd3r_buddy}
  ```

  → Đây là **fake flag**.

* Format flag chuẩn: `EH4X{...}`

---

## **[2] PHÂN TÍCH**

### **[2.1] Kiểm tra độ dài input**

Trong hàm `main`:

```c
len = strlen(input);
if (len != 0x23)
    puts("Wrong length!");
```

* `0x23 = 35`
  → Flag phải có **35 ký tự**.

Điều này loại bỏ khả năng 2 fake flag vì độ dài không khớp.

---

### **[2.2] Hàm check chính**

Luồng kiểm tra:

```
main
 └── check(input)
       ├── strcmp(fake_flag_1)
       ├── strcmp(fake_flag_2)
       └── real_check(input)
```

Nếu trùng fake flag → in message troll.
Nếu không → đi vào hàm thực sự kiểm tra (tại offset ~0x105cc).

---

### **[2.3] Vùng dữ liệu encode trong `.rodata`**

Trong `.rodata` có 35 byte liên tiếp:

```
VA: 0x57bc8 → 0x57beb
```

Đúng bằng 0x23 byte.

Dữ liệu này ciphertext của flag.

---

### **[2.4] Thuật toán giải mã**

Phân tích asm trong hàm `real_check`:

```c
k = 0;
for (i = 0; i < 0x23; i++) {
    tmp = enc[i] ^ (k & 0xff) ^ 0xA5;
    buf[i] = tmp;
    k += 7;
}
```

Sau đó:

```c
strcmp(buf, input)
```

Tức là:

```
decoded[i] = enc[i] XOR ( (7*i) & 0xFF ) XOR 0xA5
```

Vì:

```
k ban đầu = 0
mỗi vòng += 7
→ k = 7*i
```

Đây chỉ là XOR tuyến tính theo index → đảo ngược rất dễ.

---

### **[2.5] Giải mã flag**

Chỉ cần lấy 35 byte trong `.rodata` rồi áp dụng:

```python
decoded[i] = enc[i] ^ ((7*i) & 0xff) ^ 0xA5
```


## **[3] SOLVE**

Script: [solve.py](solve.py)

> **Flag:** `EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}`
