# flagchecker3

## [1] TỔNG QUAN
- Đầu tiên mình mở thử file apk này trên android thì thấy có phần yêu cầu nhập mã PIN như thế này:

    ![alt text](images/flagchecker3_00.jpg)

- Vì quá lười ngồi brute mật khẩu nên mình đã thử kiểm tra các file được pack vào apk. Các bài dạng apk mình từng gặp thường sẽ lưu logic tính toán ở trong file lib, vì thế mình đã extract file apk rồi thử grep 1 số chuỗi thường gặp trong các dạng flag checker như form flag hay chính chuỗi "flag" thì mình thấy có file `libveilcore.so` có chứa các chuỗi này

    ```ps
    $ grep -ri "vsl" .
    grep: ./classes.dex: binary file matches
    grep: ./lib/arm64-v8a/libveilcore.so: binary file matches
    grep: ./lib/arm64-v8a/libveilcore.so.i64: binary file matches
    grep: ./lib/armeabi-v7a/libveilcore.so: binary file matches
    grep: ./lib/x86/libveilcore.so: binary file matches
    grep: ./lib/x86_64/libc++_shared.so: binary file matches
    grep: ./lib/x86_64/libveilcore.so: binary file matches
    grep: ./lib/x86_64/libveilcore.so.i64: binary file matches
    grep: ./lib/x86_64/libveilcore.so.id0: Permission denied
    grep: ./lib/x86_64/libveilcore.so.id1: Permission denied
    grep: ./lib/x86_64/libveilcore.so.nam: Permission denied
    grep: ./resources.arsc: binary file matches
    ```

    ```ps
    $ grep -ri "flag" .
    grep: ./classes.dex: binary file matches
    grep: ./lib/arm64-v8a/libveilcore.so: binary file matches
    grep: ./lib/arm64-v8a/libveilcore.so.i64: binary file matches
    grep: ./lib/armeabi-v7a/libveilcore.so: binary file matches
    grep: ./lib/x86/libveilcore.so: binary file matches
    grep: ./lib/x86_64/libveilcore.so: binary file matches
    grep: ./lib/x86_64/libveilcore.so.i64: binary file matches
    grep: ./lib/x86_64/libveilcore.so.id0: Permission denied
    grep: ./lib/x86_64/libveilcore.so.id1: Permission denied
    grep: ./lib/x86_64/libveilcore.so.nam: Permission denied
    grep: ./lib/x86_64/libveilcore.so.til: binary file matches
    grep: ./resources.arsc: binary file matches
    ```

- Tìm trong bảng strings thấy có dấu hiệu khá đặc trưng của logic check flag:

    ![alt text](images/flagchecker3_01.png)

- Từ đây mình follow theo thì tìm thấy hàm `Java_com_vsl_flagchecker_MainActivity_validateFlag()` có hàm logic check gì đó (vì param inp vừa được gán lại bằng 0 ở phía trên) rồi in ra "Incorrect" hay "Correct".

    ![alt text](images/flagchecker3_02.png)

## [2] PHÂN TÍCH
- Những phần phía trên của hàm `checker` mà mình vừa phát hiện ra chủ yếu là để anti-debug, không đụng gì đến biến `inp` nên mình sẽ bỏ qua.
- Mình tiếp tục focus vào hàm `sub_52A0()` này để xem nó làm gì với `inp`:

    ```C
    __int64 __fastcall sub_52A0(unsigned int *a1)
    {
    int v1; // eax

    if ( !byte_D960 )
    {
        qword_D160[42] = (__int64)&loc_541B;
        qword_D160[94] = (__int64)&loc_576D;
        qword_D160[109] = (__int64)&loc_55D7;
        qword_D160[156] = (__int64)&loc_55F3;
        qword_D160[19] = (__int64)&loc_5558;
        qword_D160[113] = (__int64)&loc_57B2;
        qword_D160[31] = (__int64)&loc_58E8;
        qword_D160[62] = (__int64)&loc_56B0;
        qword_D160[98] = (__int64)&loc_5989;
        qword_D160[168] = (__int64)&loc_55A7;
        qword_D160[178] = (__int64)&loc_5930;
        qword_D160[8] = (__int64)&loc_54E3;
        qword_D160[209] = (__int64)&loc_587C;
        qword_D160[68] = (__int64)&loc_58D1;
        qword_D160[153] = (__int64)&loc_54BF;
        qword_D160[227] = (__int64)&loc_55EE;
        qword_D160[254] = (__int64)sub_6774;
        byte_D960 = 1;
    }
    v1 = *a1;
    if ( *a1 <= 3561 )
    {
        *a1 = v1 + 1;
        if ( qword_D160[byte_23B0[v1] ^ 0xE0u] )
        __asm { jmp     rsi }
    }
    return 0LL;
    }
    ```

- Nhìn vào đoạn pseudocode này thì có lẽ chúng ta sẽ dễ bị đánh lừa vì nó chẳng thực thi thêm gì và không rõ phần return nào khác ngoài `return 0` nên mình đã kiểm tra assembly thì thấy ở giao diện graph còn khá nhiều logic phức tạp khác, trong đó chỉ có các phần sau là được disassemble:

    ![alt text](images/flagchecker3_03.png)

- Sau khi đọc mã asm từ đầu hàm thì mình hiểu logic như sau:
    - Ở đoạn đầu hàm chương trình gán các địa chỉ vào 1 mảng mình gọi là mảng con trỏ `qword_D160[]`:

        ```C
        if ( !byte_D960 )
        {
            qword_D160[42] = (__int64)&loc_541B;
            qword_D160[94] = (__int64)&loc_576D;
            qword_D160[109] = (__int64)&loc_55D7;
            qword_D160[156] = (__int64)&loc_55F3;
            qword_D160[19] = (__int64)&loc_5558;
            qword_D160[113] = (__int64)&loc_57B2;
            qword_D160[31] = (__int64)&loc_58E8;
            qword_D160[62] = (__int64)&loc_56B0;
            qword_D160[98] = (__int64)&loc_5989;
            qword_D160[168] = (__int64)&loc_55A7;
            qword_D160[178] = (__int64)&loc_5930;
            qword_D160[8] = (__int64)&loc_54E3;
            qword_D160[209] = (__int64)&loc_587C;
            qword_D160[68] = (__int64)&loc_58D1;
            qword_D160[153] = (__int64)&loc_54BF;
            qword_D160[227] = (__int64)&loc_55EE;
            qword_D160[254] = (__int64)sub_6774;
            byte_D960 = 1;
        }
        ```

    - Ở đoạn `if ( *a1 <= 3561 )` thực chất là 1 vòng lặp, nhưng để lặp được thì nó sẽ sử dụng lệnh `jmp` với label `loc_53F0` chính là đoạn rẽ nhánh `if` này.

        ![alt text](images/flagchecker3_04.png)

    - Trong thân của vòng lặp này, chương trình sẽ kiểm tra lần lượt từng byte của mảng `byte_23B0[]` xor với `0xE0`. Đoạn này ida không disassemble đúng cách nên nó chỉ hiển thị giá trị ban đầu là `0xE0`, thực tế khi soi chiếu vào asm thì nó đang xor với thanh ghi `r12d`, mà thanh ghi này được cập nhật sau mỗi đoạn `loc_xxxx` mà mình sắp phân tích bên dưới. Kết quả của phép xor này mình gọi là index vì nó đang biểu diễn chỉ số của 
    - Cần nói thêm, thanh ghi `rsi` ở đoạn này đang được gán là địa chỉ của mảng `qword_D160` tại index, mà mảng `qword_D160` chứa các địa chỉ của các `loc_xxxx` được gán phía trên, sau đó có lệnh `jmp rsi` là để jump tới các địa chỉ đó. Hay nói cách khác, các `loc_xxxx` phía trên sẽ lần lượt được thực thi thông qua cách này.