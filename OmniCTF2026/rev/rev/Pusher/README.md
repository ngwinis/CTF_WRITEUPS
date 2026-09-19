# Solution

## Challenge summary
- Category: reverse engineering
- Artifacts:
  - `challenge`
  - `server.py`
  - `Pusher-handout.tar.gz`
- Hashes:
  - `challenge` SHA256: `bc929891d1c341103013f7b60f9873bc72ff2050f2a1debb2c89d4ec2aaecfdf`
  - `Pusher-handout.tar.gz` SHA256: `5b9af7dad261862d2bc0bb04a6cef6b780daea3815dde88c0597cba01577531e`
  - `server.py` SHA256: `e486e221add434a9cf55e92e074ba4941c76f26f74861e9abb34164db0c7f7a2`
- Flag format: `OMNICTF{...}`

## Triage
- `challenge` is an ELF 32-bit i386 dynamically linked executable, not stripped.
- The binary is movfuscated/signal-dispatch style, with most logic expressed through table-driven `mov` blocks.
- Useful symbols still present:
  - `applyMove` at `0x0804964a`
  - `isWin` at `0x08054795`
  - `loadFlag` at `0x08056e8b`
  - `win` at `0x0805a17b`
- Important globals:
  - `hz_sp` at `0x0880d420`
  - `hz_slots` at `0x0880d430`, initialized to `[1,1,1,2,1,1,1,2,3]`
  - `hz_r1First` at `0x0880d454`
  - `hz_slot` at `0x0880d458`
  - `hz_lastPush` at `0x0880d45c`
  - `hz_sub` at `0x0880d460`
  - `hz_flag` at `0x0880d470`
  - `hz_stk` at `0x0880d570`
  - `hz_target` at `0x0880dd70`

## Analysis path
- `server.py` only exposes the binary over TCP. It runs `challenge` with cwd beside the binary so the binary can read `./flag.txt`.
- The win path calls `loadFlag()`, then prints `Congrats!!!The flag is : %s`.
- If `flag.txt` is absent, `loadFlag()` uses the fallback string `OMNICTF{no_flag_file_here}`.
- The handout target stored in the binary is:

```text
OMNICTF{G3T_R3A1_0N_R3M0TE_B0z0_TH1S_1S_NOT_A_HAND0UT}
```

- `isWin()` compares a generated stack string against `hz_target` through `strcmp`.
- Runtime tracing under `qemu-i386` plus `gdb` confirmed:
  - choice `1` pushes a supplied character when the current slot permits it.
  - choice `2` pops/backtracks when valid.
  - choice `3` is an invalid/no-op path for this solve.
  - choice `4` performs a check/no-op.
- The slot pattern creates a DFS-like pusher. A full cycle explores dummy branches, keeps the 4th branch character as a durable prefix, then backtracks to that prefix:

```text
1X 2, 1X 2, 1X 2, 1K, 1X 2, 1X 2, 1X 2, 1X, 1X, 1X, 2, 2, 2
```

After this, only `K` remains appended to the stack. Repeating this cycle builds a target prefix one character at a time.

## Solver
- Script: `work/scripts/solve_pusher.py`
- Payload: `work/outputs/pusher_payload.txt`

For the 54-byte target, the solver:
1. Runs 50 full cycles to make the first 50 bytes durable on the stack.
2. Runs a final partial cycle that leaves the last 4 bytes transiently on the stack.
3. Stops at the compare where the generated buffer equals `hz_target`.

Local validation:

```bash
python3 solve_pusher.py --local
```

Remote usage:

```bash
python3 solve_pusher.py --host HOST --port PORT
```

## Validation
- A local qemu/i386 rootfs was prepared under `work/dumps/i386-rootfs`.
- Running the solver twice with dummy local `flag.txt` values reached `win()` and printed the file contents:

```text
Congrats!!!The flag is : OMNICTF{LOCAL_VALIDATION_FLAG}
Congrats!!!The flag is : OMNICTF{SECOND_LOCAL_CHECK}
```

This proves the generated payload satisfies the binary's real validation path.

## Final flag
The real flag is not present in the handout. The handout binary reads `./flag.txt` only after the pusher state matches the embedded target. Use `work/scripts/solve_pusher.py --host HOST --port PORT` against the challenge service to retrieve the real remote flag.
