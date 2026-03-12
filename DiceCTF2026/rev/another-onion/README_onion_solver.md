# another-onion solver

This is a **generic local solver** for the `another-onion` challenge family.

It does **not** try to statically reverse all 512 bytes at once. Instead it uses the intended practical workflow:

1. run the binary with the known key prefix,
2. attach while the current stage is blocked in `read()`,
3. dump the process memory,
4. execute the current plaintext stage natively from the dump,
5. brute-force the next 2-byte chunk until the next stage decrypts to the expected stage prologue,
6. repeat until the real binary prints the token.

## Files

- `solve_onion.py`: main solver

## Requirements

- Linux x86_64
- `gcc`
- `python3`
- `ptrace` must be allowed for your user/session
- CPU should support the SHA-NI instructions used by the challenge binary

## Basic usage

```bash
python3 solve_onion.py ./another_onion
```

If you already know part of the key, resume with:

```bash
python3 solve_onion.py ./another_onion --prefix-hex deadbeef...
```

The script writes intermediate results into `solver_work/`:

- `solver_work/key.bin`
- `solver_work/key.hex`
- dump files for the current stage snapshot
- an auto-compiled helper binary used for replay/bruteforce

## After the key is recovered

Run the real binary with the recovered key to print the token:

```bash
./another_onion < solver_work/key.bin
```

Then submit the token:

```bash
ncat --ssl <submission-host> 1337
```

## Important caveat

I could syntax-check this script here, but I could **not** fully end-to-end validate it in this sandbox because `ptrace` is blocked in the environment.
So treat it as a strong starting point / solve framework for the exact `another-onion` family, not as a claim that it was fully run to completion inside this container.
