# Battleship

- python extracted: [battleship](battleship.pyc_Decompiled.py)
- Solve:
  - Hướng di chuyển của AI: [(2, 4), (2, 3), (2, 1), (0, 0), (1, 1), (3, 1), (3, 4), (2, 2), (0, 4), (3, 3)]
  - Giải mã tọa độ bằng Polybius Square:
    ||0|1|2|3|4
    |-|-|-|-|-|-|
    |0|A|B|C|D|E|
    |1|F|G|H|I/J|K|
    |2|L|M|N|O|P|
    |3|Q|R|S|T|U|
    |4|V|W|X|Y|Z|
  - Giải mã ra được:
    - `(2, 4)` ➜ Hàng 2, Cột 4 = P
    - `(2, 3)` ➜ Hàng 2, Cột 3 = O
    - `(2, 1)` ➜ Hàng 2, Cột 1 = M
    - `(0, 0)` ➜ Hàng 0, Cột 0 = A
    - `(1, 1)` ➜ Hàng 1, Cột 1 = G
    - `(3, 1)` ➜ Hàng 3, Cột 1 = R
    - `(3, 4)` ➜ Hàng 3, Cột 4 = U
    - `(2, 2)` ➜ Hàng 2, Cột 2 = N
    - `(0, 4)` ➜ Hàng 0, Cột 4 = E
    - `(3, 3)` ➜ Hàng 3, Cột 3 = T

> **Flag:** `DawgCTF{POMAGRUNET}`