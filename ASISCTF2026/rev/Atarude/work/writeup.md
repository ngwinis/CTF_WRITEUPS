# Solution

## Challenge summary

- Category: reverse engineering / crypto.
- Artifacts:
  - `Atarude_e39d6ecbf3f6d04dee16fc4a9046770fa3bdd9f3.txz`
  - extracted `Atarude`
  - extracted `flag.enc`
- Flag format: `ASIS{...}`.

## Hashes

| File | SHA256 | MD5 |
| --- | --- | --- |
| `Atarude_e39d6ecbf3f6d04dee16fc4a9046770fa3bdd9f3.txz` | `416d7ea8165eba3e5d9a0b2f47337ddeeef552fecc7f57eeae5eac541f65e4e2` | `ae9e8a3d9fc98011018083e6ffaab20a` |
| `Atarude` | `a9ae09a1056b2350b863f9668d462b330a3a087a0dd4aa4322cb791244a9c829` | `870e12a7784d1cfb0a475e0f4af57ef7` |
| `flag.enc` | `2468045a254092a7edbad0bd30376dacaf963ffdaa5e83af8dea6a819d0d719e` | `2feb9e1d43646622d047dfb9a7c695f5` |

## Triage

- `Atarude` is a stripped 64-bit little-endian x86-64 PIE ELF built from Rust.
- Useful strings include `source/main.rs`, `rustc version 1.91.1 (ed61e7d7e 2025-11-07)`, and `LLD 21.1.2`.
- `.rodata` starts at file offset and VA `0x3140`; `.text` is loaded at VA `0xc24170` from file offset `0xc23170`.
- The challenge logic reads whitespace-separated commands from stdin, but the protected flag is ultimately decrypted from `flag.enc`.

## Analysis path

The binary accepts records in this shape:

```text
<index> <mode> <hex-bytes>
```

- `index` is decimal `0..5`.
- `mode` is either `e` or `s`.
- `e` records decode to `0xa0` raw bytes.
- `s` records decode to `0xb0` raw bytes.
- Each lane requires two prior `e` records before accepting an `s` record.
- After six accepted `s` records, the program concatenates the internal records into 66 AES-sized blocks and computes a 16-byte gate value.
- The gate must equal the constant at `.rodata+0x160`: `10fe0df1471d48b5226d8b3b9e3559f3`.

The central routine at `0xc24570` is an AES-based compression function:

1. Derive a 16-byte base key from a large `.rodata` table using a xorshift64 loop.
2. For each input block, encrypt `block XOR state XOR tweak` with AES-128-ECB under the fixed base key.
3. Return `AES-128-ECB(key=final_state, plaintext=base_key)`.

The derived base key is:

```text
37ad32cedc53ab283dd99c435f46f95e
```

The flag parser/decryptor at `0xc255c0` reuses the same primitive. Since the main gate fixes the previous stage output to `10fe0df1471d48b5226d8b3b9e3559f3`, the `flag.enc` decryption key can be derived directly from the gate constant and nearby `.rodata` constants.

The `flag.enc` format is:

```text
a6 3c                  magic
00 32                  big-endian ciphertext length, 50 bytes
52 cf d5 ... ff a1 06  ciphertext
6f f7 fe ... 6c 17 eb  16-byte authentication tag
```

The derived flag stream key is:

```text
aa0b580da7bff66686e98e7ed8f1ba93
```

## Solver

The solver is:

```text
work/scripts/solve_atarude.py
```

Run from the challenge directory:

```powershell
python .\work\scripts\solve_atarude.py
```

It:

1. reads the extracted ELF and `flag.enc`;
2. rebuilds the AES compression function;
3. derives the flag decryption key from the fixed gate constant;
4. verifies the `flag.enc` tag with seed `0x3c`;
5. decrypts the ciphertext with AES-ECB counter keystream.

## Validation

The computed `flag.enc` tag equals the embedded tag:

```text
6ff7fe35fd3a3c14b422d681ab6c17eb
```

The solver was run successfully and printed the final flag.

## Final flag

```text
ASIS{_iZ_c0p1eD_m4sk5_m4Ke_3Ven_Spl!c3s_vAn1sh!!?}
```
