#!/usr/bin/env python3
import os, shutil, subprocess, tempfile, hashlib, collections, pathlib

CHALL = "./chall"
INIT = "./chall.sh"

# (head_n, timeout_seconds)
ACTIONS = [
    (2, 1), (2, 2), (2, 3), (2, 4), (2, 5),
    (1, 5), (3, 5),
]

MAX_DEPTH = 4
PROBE_TIMEOUT = 25

def run_cut(state_bytes, head_n, secs):
    td = tempfile.mkdtemp(prefix="kyoto_state_")
    shutil.copy(CHALL, td + "/chall")
    os.chmod(td + "/chall", 0o755)
    pathlib.Path(td + "/chall.sh").write_bytes(state_bytes)
    os.chmod(td + "/chall.sh", 0o755)

    cmd = f"timeout {secs}s bash -lc \"printf 'aaa\\n' | bash ./chall.sh | head -n {head_n}\""
    subprocess.run(["bash", "-lc", cmd], cwd=td, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    new_state = pathlib.Path(td + "/chall.sh").read_bytes()
    return td, new_state

def probe_state(state_bytes):
    td = tempfile.mkdtemp(prefix="kyoto_probe_")
    shutil.copy(CHALL, td + "/chall")
    os.chmod(td + "/chall", 0o755)
    pathlib.Path(td + "/chall.sh").write_bytes(state_bytes)
    os.chmod(td + "/chall.sh", 0o755)

    cmd = f"timeout {PROBE_TIMEOUT}s bash -x chall.sh <<< 'aaa' >out 2>trace"
    subprocess.run(["bash", "-lc", cmd], cwd=td)

    trace = pathlib.Path(td + "/trace").read_text("latin1", errors="ignore")
    hits = []
    for needle in [
        "export g_7965=",
        "export g_1829=",
        "export g_2184=",
        "Correct!",
        "flag.txt",
        "export key=",
    ]:
        if needle in trace:
            hits.append(needle)

    tail = "\n".join(trace.splitlines()[-20:])
    return td, hits, tail

init = pathlib.Path(INIT).read_bytes()
seen = {hashlib.sha256(init).hexdigest(): ()}
q = collections.deque([(init, ())])

while q:
    state, path = q.popleft()
    if len(path) >= MAX_DEPTH:
        continue

    for action in ACTIONS:
        cut_td, new_state = run_cut(state, *action)
        h = hashlib.sha256(new_state).hexdigest()
        if h in seen:
            shutil.rmtree(cut_td, ignore_errors=True)
            continue

        new_path = path + (action,)
        seen[h] = new_path

        probe_td, hits, tail = probe_state(new_state)
        print(f"[+] path={new_path} lines={new_state.count(b'\\n')} hits={hits}")

        if hits:
            print("=== HIT PATH ===")
            print(new_path)
            print("=== TRACE TAIL ===")
            print(tail)
            print(f"state dir: {cut_td}")
            print(f"probe dir: {probe_td}")
            raise SystemExit(0)

        q.append((new_state, new_path))

print("[-] no hit yet")