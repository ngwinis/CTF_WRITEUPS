# interpreter-required

## Tổng quan

- Challenge: `interpreter-required`
- Category: Reverse Engineering
- Files:
  - [`interpreter`](./interpreter)
  - [`flag_riddle.txt`](./flag_riddle.txt)
  - [`solve_interpreter_required.py`](./solve_interpreter_required.py)

## Ý tưởng

Mô tả challenge đã gợi ý rất rõ: **đừng chạy thẳng interpreter**, vì nó sẽ ngốn bộ nhớ đến mức OOM. Vậy hướng đúng không phải là “thông dịch toàn bộ ngôn ngữ”, mà là:

1. Đọc `flag_riddle.txt`,
2. Hiểu phần ngữ pháp vừa đủ,
3. Rút gọn các biểu thức về số nguyên,
4. Lần theo biến `旗` để khôi phục chuỗi output cuối cùng.

## Phân tích

`flag_riddle.txt` nhìn như một đoạn văn lẫn thơ với rất nhiều ký tự CJK. Nhưng nếu bỏ hết phần chữ giải thích bằng tiếng Anh và chỉ nhìn phần “code”, ta sẽ thấy file này thực chất là một ngôn ngữ lambda-calculus mini dùng ký tự Hán để biểu diễn.

Các định nghĩa đầu tiên:

```text
真以矛盾而为矛矣
假以矛盾而为盾矣
正以人而为人矣
```

Nếu đã quen Church encoding thì nhìn ra ngay:

- `真` là `true`
- `假` là `false`
- `正` là identity

Ngay sau đó là các primitive cho pair / option / list node:

```text
双以不得了而为了不得矣
本以欲而为欲以戶戸而戶矣
末以欲而为欲以戸戶而戶矣
有以事而为双真事矣
无为双假正矣
在以物而为物真矣
用以物而为物假矣
为双无有矣完
```

Ở đây chỉ cần chú ý:

- `双` tạo pair
- `本`, `末` lần lượt là `fst`, `snd`
- `有`, `无` là kiểu `Some` / `None`
- `完` là sentinel kết thúc danh sách

Tức là về bản chất, output cuối cùng rất có thể được lưu dưới dạng một linked list gồm nhiều node `有 <giá trị>`.

=> Chỗ quan trọng nhất: block sinh dữ liệu phía dưới không còn là lambda phức tạp

Sau phần đầu, file xuất hiện một block cực dài bắt đầu từ các biến kiểu `㐀`, `㐁`, `㐂`, ...

Nhìn kỹ sẽ thấy các biểu thức ở block này chỉ còn vài dạng rất đều:

- `朝...暮`
- `合xy`
- `销xy`
- `次xy`
- `分xy`
- `幂xy`
- `阶x`

Tức là sau khi định nghĩa xong primitive, phần còn lại chỉ là chương trình thuần tạo ra các số nguyên trung gian. Vì vậy không cần thông dịch lambda-calculus tổng quát nữa; chỉ cần map các operator này về phép toán thường là đủ.

## Giải mã `朝 ... 暮`

Từ đoạn trên ta có:

- `春` và `秋` là hai ký hiệu bit
- `朝 ... 暮` là cách viết literal nhị phân

Thử decode vài giá trị đầu:

```text
㐀为朝春秋春秋暮
㐁为朝秋春秋秋秋秋暮
```

Nếu lấy:

- `春 = 0`
- `秋 = 1`
- đọc theo **little-endian**

thì:

- `朝春秋春秋暮`  -> bits `0 1 0 1` -> `10` -> `\n`
- `朝秋春秋秋秋秋暮` -> bits `1 0 1 1 1 1` -> `61` -> `'='`

Chuỗi đầu ra bắt đầu bằng `\n===`, nên cách hiểu này khớp hoàn toàn.

Đây là mấu chốt để xác nhận rằng toàn bộ block `㐀`, `㐁`, ... thực ra là các mã ký tự được tính toán dần dần.

## Ý nghĩa các toán tử còn lại

Từ ngữ nghĩa của đoạn trên và từ kết quả thực nghiệm khi khôi phục output, có thể rút ra mapping sau:

- `合(a, b) = a + b`
- `销(a, b) = max(a - b, 0)`
- `次(a, b) = a * b`
- `分(a, b) = a // b`
- `幂(a, b) = a ** b`
- `阶(a) = factorial(a)`

Như vậy mỗi biến `㐀`, `㐁`, ... chỉ còn là một biểu thức số học phụ thuộc vào các biến trước đó.

Do các định nghĩa xuất hiện theo thứ tự xuôi, ta chỉ cần duyệt từ trên xuống, gặp biến nào thì tính luôn biến đó.

## Solve

Không cần parse toàn bộ ngôn ngữ từ đầu file. Cách làm gọn hơn là:

### 1. Lọc source

Bỏ hết:

- khoảng trắng
- xuống dòng
- dấu câu ASCII/CJK
- phần prose tiếng Anh

Giữ lại các ký tự non-ASCII có ý nghĩa cho ngôn ngữ.

### 2. Bắt đầu parse từ `㐀为`

Đây là nơi block dữ liệu lớn thực sự bắt đầu.

### 3. Tách từng định nghĩa bằng cách đếm cặp `为 ... 矣`

Mỗi định nghĩa có dạng:

```text
<biến>为<biểu_thức>矣
```

Nhưng vì trong biểu thức cũng có thể lồng tiếp `为 ... 矣`, nên không thể split bừa theo `矣`. Vì thế, mình đã làm theo cách:

- gặp `为` thì `depth += 1`
- gặp `矣` thì `depth -= 1`
- khi `depth` quay về `0` thì kết thúc một định nghĩa

Sau khi scan hết các định nghĩa trung gian, đến cuối file sẽ gặp `旗`.

Dạng của nó là một chuỗi lồng pair rất dài, kiểu:

```text
旗为双为有㐀矣于双为有㐁矣于双为有㐂矣于...
```

Điểm đáng chú ý là mỗi node đều có dạng `有<biến>`.

Vì ta đã biết:

- `有` là node chứa giá trị
- `完` là sentinel cuối danh sách

nên `旗` chỉ đơn giản là danh sách các biến ký tự cần in ra theo thứ tự. Không cần mô phỏng cấu trúc Church pair đầy đủ; chỉ cần quét các cụm có chứa `旗`, lấy tất cả biến đứng ngay sau `有`, rồi convert từng giá trị sang `chr()` là có được toàn bộ output.

## Script solve

[`solve.py`](./solve_interpreter_required.py)

> **Flag**: `dice{y0u_int3rpret3d_Th3_CJK_gr4mMaR_succ3ssfully}`
