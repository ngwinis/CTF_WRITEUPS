import os, time, signal, shutil, hashlib, subprocess, tempfile

SRC_DIR = os.getcwd()
WORK = tempfile.mkdtemp(prefix="kyoto_trace_")

shutil.copy(os.path.join(SRC_DIR, "chall"), os.path.join(WORK, "chall"))
shutil.copy(os.path.join(SRC_DIR, "chall.sh"), os.path.join(WORK, "chall.sh"))
os.chmod(os.path.join(WORK, "chall"), 0o755)
os.chmod(os.path.join(WORK, "chall.sh"), 0o755)

cmd = r"printf 'aaa\n' | bash ./chall.sh | /usr/bin/head -n 2"
p = subprocess.Popen(
    ["bash", "-lc", cmd],
    cwd=WORK,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    preexec_fn=os.setsid,
)

last = None
start = time.time()

try:
    while time.time() - start < 40:
        time.sleep(0.05)
        path = os.path.join(WORK, "chall.sh")
        data = open(path, "rb").read()
        h = hashlib.sha256(data).hexdigest()
        if h == last:
            continue
        last = h

        txt = data.decode("latin1", "ignore")
        lines = []
        for ln in txt.splitlines():
            s = ln.strip("\x00 ").strip()
            if s.startswith(("export ", "echo ", "read ", "./chall ")):
                lines.append(s)

        if lines:
            print(lines[-1])

        joined = "\n".join(lines)
        if any(x in joined for x in [
            "8408", "8234", "6917", "Correct!", "Incorrect!",
            "export key=", "cat flag.txt"
        ]):
            print("\n[+] HIT")
            print(joined)
            break
finally:
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except:
        pass

print(f"\n[WORK] {WORK}")
