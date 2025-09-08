# Comparing

## [1] PHÂN TÍCH
- Challenge này cho 1 đoạn code C++ khá đơn giản.
- Đầu tiên, chương trình này lấy lần lượt 2 ký tự một rồi push vào 1 hàng đợi ưu tiên, cùng với chỉ số i có thứ tự từ `0` đến `len(flag)//2`.

    ```C++
    for (int i = 0; i < flag.size() / 2; i++) {
        tuple<char, char, int> x = { flag[i * 2],flag[i * 2 + 1],i };
        pq.push(x);
    }
    ```

- Tiếp theo, chương trình này pop lần lượt theo thứ tự push vừa rồi và thực hiện mã hoá sau đó push vào vector như sau:
    - Với chỉ số chẵn, mã hoá theo hàm `even()`, hàm này đầu tiên push 2 mã ascii và chỉ số vào, sau đó đảo ngược kí tự chữ số của mỗi mã ascii đó rồi push vào ngay sau đó.
    - Với chỉ số lẻ, mã hoá theo hàm `odd()`, hàm này thì y hệt hàm `even()`, chỉ không có nhiệm vụ đảo ngược phía sau.

    ```C++
    while (!pq.empty()) {
        int val1 = static_cast<int>(get<0>(pq.top()));
        int val2 = static_cast<int>(get<1>(pq.top()));
        int i1 = get<2>(pq.top());
        pq.pop();
        int val3 = static_cast<int>(get<0>(pq.top()));
        int val4 = static_cast<int>(get<1>(pq.top()));
        int i2 = get<2>(pq.top());
        pq.pop();
        if (i1 % 2 == 0) { out.push_back(even(val1, val3, i1)); }
        else { out.push_back(odd(val1, val3, i1)); }
        if (i2 % 2 == 0) { out.push_back(even(val2, val4, i2)); }
        else { out.push_back(odd(val2, val4, i2)); }
    }
    ```

    ```C++
    string even(int val1, int val3, int ii) {
        string out = to_string(val1) + to_string(val3) + to_string(ii);
        string x = to_string(val1) + to_string(val3);
        for (int i = x.size() - 1; i >= 0; i--) {
            out += x[i];
        }
        return out;
    }

    string odd(int val1, int val3, int ii) {
        int out = stoi(to_string(val1) + to_string(val3) + to_string(ii));
        int i = 0;
        int addend = 0;
        while (i < 100) { addend += i; i++; }
        i--;
        while (i >= 0) { addend -= i; i--; }
        return to_string(out + addend);
    }
    ```

- Và đây là output được cung cấp:

    ```
    9548128459
    491095
    1014813
    561097
    10211614611201
    5748108475
    1171123
    516484615
    114959
    649969946
    1051160611501
    991021
    1231012101321
    9912515
    11411511
    1151164611511
    ```

- Nhìn vào output, có thể tách ra một cách thủ công như sau:

    ```
    95 48 12 84 59  // đây là mã hoá theo hàm even(),
                    // chỉ số của byte flag đầu tiên
                    // là 12*2=24, byte flag thứ 2 là 25
    49 109 5        // đây là mã hoá theo hàm odd(),
                    // chỉ số của byte flag đầu tiên
                    // là 5*2=10, byte flag thứ 2 là 11
    101 48 13       // ...
    56 109 7        // ...
    ```

- Cần lưu ý rằng các số ascii có thể đọc được chỉ có giới hạn từ `32` đến `127`, vì thế khi tách các số trong ciphertext, nếu lấy 2 kí tự chữ số của số thứ nhất hoặc số thứ 2 mà chỉ có "10", "11", "12" thì sẽ tự động lấy tiếp kí tự chữ số tiếp theo để được 1 kí tự ascii đúng, còn số thứ 3 là chỉ số thì có thể nhỏ hơn 32. Từ đó mình có solve như phần bên dưới

## [2] SOLVE
```python
def solve_reversing_challenge():
    output = [
        "9548128459",
        "491095",
        "1014813",
        "561097",
        "10211614611201",
        "5748108475",
        "1171123",
        "516484615",
        "114959",
        "649969946",
        "1051160611501",
        "991021",
        "1231012101321",
        "9912515",
        "11411511",
        "1151164611511",
    ]

    flag = [0] * 32

    def split_vals(s_vals):
        for i in range(1, len(s_vals)):
            s1, s2 = s_vals[:i], s_vals[i:]
            v1, v2 = int(s1), int(s2)
            # Giả định các ký tự là ASCII có thể in được
            if 32 <= v1 <= 126 and 32 <= v2 <= 126:
                return v1, v2
        return None, None

    def parse_line(line):
        for i_len in [1, 2]:
            if len(line) > i_len and (len(line) - i_len) % 2 == 0:
                x_len = (len(line) - i_len) // 2
                x_str = line[:x_len]
                idx_str = line[x_len : x_len + i_len]
                rev_x_str = line[x_len + i_len:]
                if x_str == rev_x_str[::-1] and idx_str.isdigit():
                    val1, val2 = split_vals(x_str)
                    if val1 is not None:
                        return val1, val2, int(idx_str)

        for i_len in [1, 2]:
            if len(line) > i_len:
                idx_str = line[-i_len:]
                vals_str = line[:-i_len]
                if idx_str.isdigit():
                    val1, val2 = split_vals(vals_str)
                    if val1 is not None:
                        return val1, val2, int(idx_str)
        return None, None, None

    for i in range(0, len(output), 2):
        line1 = output[i]
        line2 = output[i+1]

        v1, v3, i1 = parse_line(line1)
        v2, v4, i2 = parse_line(line2)

        if i1 is not None and i2 is not None:
            flag[i1 * 2] = v1
            flag[i1 * 2 + 1] = v2

            flag[i2 * 2] = v3
            flag[i2 * 2 + 1] = v4

    final_flag = "".join(chr(c) for c in flag)
    print(f"[*] Phân tích hoàn tất.")
    print(f"[*] Flag được tìm thấy là: {final_flag}")

solve_reversing_challenge()

```
> **Flag:** `ictf{cu3st0m_c0mp@r@t0rs_1e8f9e}`