def solve_reversing_challenge():
    """
    Hàm này đảo ngược logic của đoạn mã C++ để tìm ra flag
    từ một output cho trước.
    """
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

    # Flag có 32 ký tự, tương ứng với 16 cặp và 16 dòng output
    flag = [0] * 32

    def split_vals(s_vals):
        """Tách một chuỗi số thành hai giá trị ASCII hợp lệ."""
        for i in range(1, len(s_vals)):
            s1, s2 = s_vals[:i], s_vals[i:]
            v1, v2 = int(s1), int(s2)
            # Giả định các ký tự là ASCII có thể in được
            if 32 <= v1 <= 126 and 32 <= v2 <= 126:
                return v1, v2
        return None, None

    def parse_line(line):
        """Phân tích một dòng output để trích xuất hai giá trị và chỉ số."""
        # Thử phân tích theo logic của hàm 'even'
        # Chỉ số có thể có 1 hoặc 2 chữ số
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

        # Thử phân tích theo logic của hàm 'odd'
        for i_len in [1, 2]:
            if len(line) > i_len:
                idx_str = line[-i_len:]
                vals_str = line[:-i_len]
                if idx_str.isdigit():
                    val1, val2 = split_vals(vals_str)
                    if val1 is not None:
                        return val1, val2, int(idx_str)
        return None, None, None

    # Xử lý output theo từng cặp dòng
    for i in range(0, len(output), 2):
        line1 = output[i]
        line2 = output[i+1]

        # Dòng 1 chứa (val1, val3, i1)
        v1, v3, i1 = parse_line(line1)
        # Dòng 2 chứa (val2, val4, i2)
        v2, v4, i2 = parse_line(line2)

        # Sắp xếp lại các giá trị vào mảng flag
        if i1 is not None and i2 is not None:
            # T1 ban đầu là (flag[i1*2], flag[i1*2+1], i1)
            flag[i1 * 2] = v1
            flag[i1 * 2 + 1] = v2

            # T2 ban đầu là (flag[i2*2], flag[i2*2+1], i2)
            flag[i2 * 2] = v3
            flag[i2 * 2 + 1] = v4

    # Chuyển đổi mã ASCII thành ký tự và ghép lại
    final_flag = "".join(chr(c) for c in flag)
    print(f"[*] Phân tích hoàn tất.")
    print(f"[*] Flag được tìm thấy là: {final_flag}")

# Chạy hàm giải mã
solve_reversing_challenge()

# Flag: ictf{cu3st0m_c0mp@r@t0rs_1e8f9e}