def unpack():
    # Đọc dữ liệu từ file đã nén
    with open('output.txt', 'r') as f:
        data = f.read().strip()

    # Xóa ký tự EOF '~' nếu có
    if data.endswith('~'):
        data = data[:-1]

    # Tách các dòng bằng ký tự '}'
    encoded_lines = data.split('}')
    
    decoded_image = []

    for line in encoded_lines:
        if not line:
            continue
            
        row1 = ""
        row2 = ""
        
        for char in line:
            # Đảo ngược bước nén: trừ đi 32 để lấy lại giá trị 6-bit
            val = ord(char) - 32
            
            # Format thành chuỗi nhị phân 6 ký tự (vd: 5 -> '000101')
            bin_str = f"{val:06b}"
            
            # 3 bit đầu thuộc về hàng trên, 3 bit sau thuộc về hàng dưới
            row1 += bin_str[:3]
            row2 += bin_str[3:]
            
        decoded_image.append(row1)
        decoded_image.append(row2)

    # In ảnh ra terminal để đọc flag
    for row in decoded_image:
        # Thay thế '1' bằng block và '0' bằng khoảng trắng để tạo ASCII art dễ đọc
        readable_row = row.replace('1', '█').replace('0', ' ')
        print(readable_row)

if __name__ == '__main__':
    unpack()

# DawgCTF{Th1s_w4s_1nspIr3d_By_UND3RT4L3!}