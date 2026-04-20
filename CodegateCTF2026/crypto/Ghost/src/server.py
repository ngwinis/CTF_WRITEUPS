#!/usr/bin/env python3

import secrets
from utils import dm_compress, hex_to_words, round_core
from secret import SBOXES, BANNER, FLAG

def main():
    iv = secrets.randbits(64)
    chances = 2**7

    print(BANNER)
    print(f"IV = {iv:016x}")
    print(f"Chances = {chances}/{2**7}")

    while True:
        print(
            "\n"
            "[1] query\n"
            "[2] submit\n"
            "[3] quit"
        )

        choice = input("> ")

        if choice == "1":
            if chances <= 0:
                print("Nope!\n")
                continue

            right_s = input("right > ")
            key_s = input("subkey > ")

            try:
                right = int(right_s, 16)
                subkey = int(key_s, 16)
            except:
                print("Bad input\n")
                continue

            chances -= 1
            y = round_core(right, subkey, SBOXES)

            print(f"core = {y:08x}")

        elif choice == "2":
            m1s = input("m1 > ")
            m2s = input("m2 > ")

            try:
                w1 = hex_to_words(m1s)
                w2 = hex_to_words(m2s)
            except Exception as e:
                continue

            if w1 == w2:
                print("Blocks must differ\n")
                continue

            h1 = dm_compress(iv, w1, SBOXES)
            h2 = dm_compress(iv, w2, SBOXES)

            if h1 == h2:
                print("Good!")
                print(f"flag = {FLAG()}\n")
            else:
                print("Nope!")

            return

        elif choice == "3":
            print("Bye!\n")
            return
        
        else:
            print("Only 1,2,3 are allowed\n")

if __name__ == "__main__":
    main()