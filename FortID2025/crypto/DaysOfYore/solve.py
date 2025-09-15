from pathlib import Path
import re, itertools, sys

CIPH_PATH = Path("ciphertext.txt")
COVER_PATH = Path("cover.txt")

# đọc permutation và độ dài từng dòng
nums_by_line = [list(map(int, re.findall(r'\d+', ln)))
                for ln in CIPH_PATH.read_text(encoding="utf-8").strip().splitlines()]
perm = list(itertools.chain.from_iterable(nums_by_line))
need_len = max(perm)  # 1878
line_lens = [len(x) for x in nums_by_line]

base_raw = COVER_PATH.read_text(encoding="utf-8")
have_len = len(base_raw)

print(f"[i] Need cover length = {need_len}, your cover.txt length = {have_len}")
print(f"[i] Expected line lengths (54 lines): {line_lens}")

if have_len != need_len:
    sys.exit("[!] Độ dài cover chưa khớp. Hãy copy lại đúng như hướng dẫn (bao gồm tiêu đề, emoji, nút...).")

# giải theo hướng 'pull': out[j] = base[perm[j]-1]
out_lines, pos = [], 0
for ln in line_lens:
    out_lines.append("".join(base_raw[i-1] for i in perm[pos:pos+ln]))
    out_lines.append("\n")
    pos += ln
res = "".join(out_lines)

# săn flag
import re
cands = re.findall(r"[A-Za-z0-9_]{2,25}\{[^{}\n]{4,200}\}", res)
print("\n=== Output preview (first 500 chars) ===")
print(res[:500])
print("\n=== Flag candidates ===")
print(cands or "Không thấy — nhưng nếu length đã khớp thì mở file out để xem thủ công.")
Path("decoded.txt").write_text(res, encoding="utf-8")
print("[i] Saved -> decoded.txt")
