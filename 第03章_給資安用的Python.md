# 第 3 章：給資安用的 Python

## 學習目標
1. 用 `socket` 寫 TCP 伺服器與用戶端，理解「資料是一串位元組流」
2. 用 `requests` 處理 Session、Cookie、轉址、逾時與 JSON
3. 用正規表示式（`re`）從文字中抽取結構化資料
4. 用 `ThreadPoolExecutor` 並行處理，並加上速率限制
5. 用 `argparse` 把腳本做成好用的命令列工具
6. 完成兩支工具：**HTTP 安全標頭檢查器**、**Web 存取紀錄（access log）分析器**

> 本章大部分練習只在**自己的電腦**（`127.0.0.1`）上進行；需要連線的部分只對第 1 章的靶場（Juice Shop、DVWA、msf2）使用，而且每支工具都會先經過第 0 章的 `scope_checker`。

---

## 3.1 攻擊者的思考方式：為什麼要自己寫工具？

現成工具很強，但真實情況常常是：

- 工具輸出太多，你只想要其中一個欄位 → 寫幾行 Python 過濾
- 同一個檢查要對 50 個目標做 → 自動化
- 遇到工具不支援的協定或格式 → 自己寫用戶端
- 想知道工具「到底送了什麼」 → 自己寫一次就懂了

藍隊也一樣：分析 log、比對 IOC、產生報表，幾乎都是 Python。**能寫工具的人，才能真正理解工具。**

### 專業工具的基本習慣（本章所有程式都會遵守）
| 習慣 | 原因 |
|---|---|
| 送封包前先檢查範圍 | 避免打到範圍外的目標（第 0 章） |
| 所有網路操作都設逾時 | 避免程式卡死 |
| 控制速率 | 避免把目標打掛，也符合 ROE |
| 錯誤要處理，不要整支程式崩潰 | 掃 100 個目標，不能因為第 3 個失敗就全部中斷 |
| 輸出可以給機器讀（JSON） | 方便串接其他工具、寫進報告 |

---

## 3.2 專案結構

延續第 1 章的資料夾：
```
~/pentest/
├── scope.txt               # 第 0 章
├── scope_checker.py        # 第 0 章（擴充版，含 load_scope、check）
├── lab_health.py           # 第 1 章
├── ch2_lab.pcap            # 第 2 章
├── echo_server.py          # 3.3
├── echo_client.py          # 3.3
├── banner.py               # 3.3
├── ratelimit.py            # 3.6
├── http_header_audit.py    # 3.8 實作一
├── gen_sample_log.py       # 3.9 實作二
└── log_analyzer.py         # 3.9 實作二
```

```bash
cd ~/pentest && source ~/pentest-venv/bin/activate
python --version     # Kali 目前是 Python 3.12 以上
```

---

## 3.3 socket：最底層的網路程式

### 先在自己電腦上寫一對伺服器與用戶端

**`echo_server.py`**
```python
"""最簡單的 TCP echo 伺服器：收到什麼就回什麼。只綁定 127.0.0.1。"""
import socket

HOST, PORT = "127.0.0.1", 9000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen()
    print(f"[*] listening on {HOST}:{PORT}，按 Ctrl+C 結束")
    while True:
        conn, addr = srv.accept()            # 等待連線（會卡在這裡）
        with conn:
            print(f"[+] connection from {addr[0]}:{addr[1]}")
            while True:
                data = conn.recv(1024)
                if not data:                 # 收到空 bytes = 對方關閉連線（FIN）
                    break
                conn.sendall(b"ECHO: " + data)
```

**`echo_client.py`**
```python
import socket

with socket.create_connection(("127.0.0.1", 9000), timeout=3) as s:
    s.sendall(b"hello\n")
    print(s.recv(1024))      # b'ECHO: hello\n'
```

| 呼叫 | 意義 |
|---|---|
| `AF_INET` / `SOCK_STREAM` | IPv4 / TCP（UDP 是 `SOCK_DGRAM`） |
| `setsockopt(... SO_REUSEADDR ...)` | 程式重啟時可以馬上重用同一個埠，不用等 TIME_WAIT 結束 |
| `bind` / `listen` / `accept` | 綁定位址 → 開始監聽 → 接受一條連線 |
| `create_connection` | 用戶端的便利函式：解析名稱、連線、設逾時一次完成（背後就是第 2 章的三向交握） |
| `sendall` | 保證全部送出（`send` 可能只送一部分） |
| `recv(1024)` | **最多**收 1024 bytes，可能比較少 |

開兩個終端機，一個跑 server、一個跑 client。可以再開第三個用 `sudo tcpdump -i lo -n port 9000` 看看三向交握（`lo` 是本機迴路網卡）。

### 重要觀念：TCP 是「位元組流」，不是「訊息」

你送兩次 `sendall(b"abc")`，對方可能一次收到 `b"abcabc"`，也可能分三次收到 `b"ab"`、`b"ca"`、`b"bc"`。**TCP 不保留訊息邊界。** 所以要自己定義「一則訊息到哪裡結束」，最常見的是用換行：

```python
def recv_line(sock, max_bytes=65536):
    """一直收，直到遇到換行或超過上限。"""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            raise ValueError("line too long")
    return buf
```

> `max_bytes` 是防禦性寫法：如果對方一直送資料不換行，沒有上限的話程式會把記憶體吃光。

### 應用：讀取服務的 Banner

很多服務一連上就會先「自我介紹」，這叫 banner。下面這支只對靶機使用：

**`banner.py`**
```python
import socket
import sys

from scope_checker import check, load_scope


def grab_banner(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            try:
                return s.recv(1024).decode(errors="replace").strip() or "(連線成功，但服務沒有主動送資料)"
            except socket.timeout:
                return "(連線成功，但服務沒有主動送資料)"
    except OSError as e:
        return f"(無法連線：{e.__class__.__name__})"


if __name__ == "__main__":
    host = sys.argv[1]
    allow, deny, window = load_scope("scope.txt")
    _, status = check(host, allow, deny, window)
    if status != "✅ IN SCOPE":
        sys.exit(f"{host}: {status}，停止")
    for port in (21, 22, 25, 80):
        print(f"{port:<6}{grab_banner(host, port)}")
```

```bash
python banner.py 192.168.56.102
```
預期輸出：
```
21    220 (vsFTPd 2.3.4)
22    SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
25    220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
80    (連線成功，但服務沒有主動送資料)
```

**觀察：** FTP、SSH、SMTP 這類協定是「伺服器先說話」，HTTP 則是「用戶端先說話」，所以 80 埠什麼都收不到。第 5 章的服務版本辨識（`nmap -sV`）就是在這個基礎上，針對不同協定送出不同的探測請求。

**防禦方法：** 能改 banner 的服務就改掉版本號（例如 Postfix 的 `smtpd_banner`、vsftpd 的 `ftpd_banner`）。這不會修補漏洞，但會提高偵察成本。

---

## 3.4 requests：HTTP 用戶端

以下都對本機的 Juice Shop（`127.0.0.1:3000`）和 DVWA（`127.0.0.1:4280`）操作。

### 基本用法
```python
import requests

s = requests.Session()                                # 重用連線、自動保存 Cookie
s.headers["User-Agent"] = "pentest-notes/0.1 (lab)"   # 自訂 UA，在 log 裡好辨認

r = s.get("http://127.0.0.1:3000/rest/products/search",
          params={"q": "apple"},                      # 自動做 URL 編碼：?q=apple
          timeout=5)
print(r.status_code)                     # 200
print(r.headers["Content-Type"])         # application/json; charset=utf-8
data = r.json()
print([p["name"] for p in data["data"]]) # 產品名稱清單
```

### 轉址與 Cookie
```python
r = s.get("http://127.0.0.1:4280/", timeout=5)
print(r.url)                                        # 最後停在 .../login.php
print([(h.status_code, h.headers["Location"]) for h in r.history])  # [(302, 'login.php')]
print(s.cookies.get_dict())                         # 例如 {'PHPSESSID': '...', 'security': 'low'}

r = s.get("http://127.0.0.1:4280/", allow_redirects=False, timeout=5)
print(r.status_code, r.headers.get("Location"))     # 302 login.php
```

### 常用參數與屬性

| 寫法 | 用途 |
|---|---|
| `params={...}` | 查詢字串，自動編碼 |
| `data={...}` | 表單（`application/x-www-form-urlencoded`） |
| `json={...}` | JSON body，自動加上 `Content-Type: application/json` |
| `headers={...}` | 自訂標頭 |
| `timeout=5` 或 `(3, 10)` | **一定要設**。單一數字，或（連線逾時, 讀取逾時） |
| `allow_redirects=False` | 不自動跟隨轉址，才看得到原始的 3xx |
| `r.status_code` / `r.headers` / `r.text` / `r.content` / `r.json()` | 狀態碼 / 標頭（不分大小寫）/ 文字 / bytes / 解析 JSON |
| `r.history` | 轉址過程中的每一個回應 |
| `r.elapsed` | 回應時間 |
| `r.raw.headers.getlist("Set-Cookie")` | 取得**每一個** Set-Cookie 原始字串（`r.headers` 會把多個合併） |

### 例外處理
```python
try:
    r = s.get(url, timeout=5)
    r.raise_for_status()           # 4xx、5xx 會丟出 HTTPError
except requests.Timeout:
    ...
except requests.ConnectionError:
    ...
except requests.RequestException as e:   # 上面所有例外的父類別
    ...
```

### 搭配 BeautifulSoup 解析 HTML
```python
from bs4 import BeautifulSoup

r = s.get("http://127.0.0.1:4280/login.php", timeout=5)
soup = BeautifulSoup(r.text, "html.parser")
form = soup.find("form")
print(form.get("action"), form.get("method"))
for inp in form.find_all("input"):
    print(inp.get("type"), inp.get("name"), inp.get("value"))
```
你會看到登入表單裡除了帳號密碼，還有一個隱藏欄位 `user_token`，這是 **Anti-CSRF Token**。第 7、11 章會說明它的用途，以及自動化工具為什麼要先抓到它才能正常送出表單。

---

## 3.5 正規表示式

### 速查表

| 語法 | 意義 | 範例 |
|---|---|---|
| `\d` `\w` `\s` | 數字 / 英數字底線 / 空白 | `\d{3}` 符合 `404` |
| `\S` | 非空白 | `\S+` 符合一整個「詞」 |
| `.` | 任意字元（不含換行） | |
| `*` `+` `?` `{m,n}` | 0 次以上 / 1 次以上 / 0 或 1 次 / m 到 n 次 | |
| `*?` `+?` | **非貪婪**：盡量少比對 | |
| `[^"]` | 除了 `"` 以外的字元 | `"[^"]*"` 比對一段引號字串 |
| `(?P<name>...)` | 具名群組 | `m.group("ip")` |
| `^` `$` | 行首 / 行尾 | |
| `re.I` | 不分大小寫 | |

### 貪婪與非貪婪的差別
```python
import re
line = '"GET / HTTP/1.1" 200 "Mozilla/5.0"'
re.search(r'"(.*)"', line).group(1)    # 'GET / HTTP/1.1" 200 "Mozilla/5.0'  ← 貪婪，吃太多
re.search(r'"(.*?)"', line).group(1)   # 'GET / HTTP/1.1'                    ← 非貪婪
re.search(r'"([^"]*)"', line).group(1) # 'GET / HTTP/1.1'                    ← 更明確，也更快
```

### 解析 Apache Combined Log Format
```
192.168.56.101 - - [09/Nov/2026:21:15:02 +0800] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"
```
```python
LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
m = LOG_RE.match(line)
if m:
    rec = m.groupdict()      # {'ip': '192.168.56.101', 'time': '09/Nov/2026:21:15:02 +0800', ...}
```

> 先 `re.compile` 一次再重複使用，比每一行都呼叫 `re.search(pattern, ...)` 清楚，也省去重複查快取的成本。

---

## 3.6 並行處理與速率限制

### 為什麼網路工具用執行緒就有效？
Python 有 GIL（全域直譯器鎖），同一時間只有一個執行緒在跑 Python 程式碼。但**等待網路 I/O 時會釋放 GIL**，所以「大部分時間在等回應」的網路工具，用執行緒就能大幅加速。CPU 密集的工作（例如計算雜湊，第 16 章）才需要考慮 `multiprocessing`。

### ThreadPoolExecutor
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def work(x):
    ...
    return result

with ThreadPoolExecutor(max_workers=10) as pool:
    futures = {pool.submit(work, x): x for x in items}
    for fut in as_completed(futures):      # 誰先完成就先處理誰
        x = futures[fut]
        try:
            print(x, fut.result())
        except Exception as e:             # 單一工作失敗不影響其他
            print(x, "error:", e)
```

| | `pool.map(fn, items)` | `submit` + `as_completed` |
|---|---|---|
| 結果順序 | 依輸入順序 | 依完成順序 |
| 例外處理 | 讀到那個結果時才丟出，後面的結果就拿不到了 | 每個工作可以個別處理 |
| 適合 | 簡單、要照順序輸出 | 需要即時顯示進度、容錯 |

### 速率限制器

**`ratelimit.py`**
```python
import threading
import time


class RateLimiter:
    """多個執行緒共用，整體每秒最多 per_second 次。"""

    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second
        self.lock = threading.Lock()
        self.next_time = time.monotonic()

    def wait(self):
        with self.lock:                       # 只在鎖內「預約時段」
            now = time.monotonic()
            slot = max(now, self.next_time)
            self.next_time = slot + self.interval
        time.sleep(max(0.0, slot - now))      # 在鎖外睡，不會擋住其他執行緒預約
```
- 用 `time.monotonic()` 而不是 `time.time()`：系統時間被調整時，monotonic 不會倒退
- 每次送請求前呼叫 `limiter.wait()` 即可

---

## 3.7 argparse：做成命令列工具

```python
import argparse

ap = argparse.ArgumentParser(description="工具說明")
ap.add_argument("targets", nargs="+", help="一個或多個目標")              # 位置參數
ap.add_argument("-t", "--threads", type=int, default=5, help="執行緒數")
ap.add_argument("--rate", type=float, default=5.0, help="每秒請求數上限")
ap.add_argument("--json", action="store_true", help="輸出 JSON")
ap.add_argument("--scope", default="scope.txt")
args = ap.parse_args()
```
`python tool.py -h` 會自動產生說明。之後所有工具都用這個模式：**位置參數放目標，選項放行為，預設值要安全**（例如速率預設偏低）。

---

## 3.8 實作一：HTTP 安全標頭檢查器

**目的：** 檢查網站回應中有沒有該有的安全標頭、有沒有洩漏版本資訊、Cookie 有沒有設好安全屬性。這是每份 Web 滲透測試報告幾乎都會出現的「低風險但必寫」項目，也是開發人員最容易修的。

### 要檢查的項目

| 標頭 | 作用 | 相關章節 |
|---|---|---|
| `Content-Security-Policy` | 限制頁面能載入哪些來源的腳本與資源，降低 XSS 的影響 | 第 10 章 |
| `Strict-Transport-Security` | 強制瀏覽器之後只用 HTTPS 連線（只在 HTTPS 回應中有效） | 第 2 章 |
| `X-Content-Type-Options: nosniff` | 禁止瀏覽器自行猜測檔案類型 | 第 12 章 |
| `X-Frame-Options` 或 CSP `frame-ancestors` | 防止頁面被嵌入 iframe（點擊劫持） | |
| `Referrer-Policy` | 控制跳到其他網站時，`Referer` 會帶出多少網址資訊 | |
| `Permissions-Policy` | 限制相機、麥克風、定位等瀏覽器功能 | |
| `Server`、`X-Powered-By` 含版本號 | 資訊洩漏 | 第 5、17 章 |
| Cookie 的 `Secure`、`HttpOnly`、`SameSite` | 防止 Cookie 被竊取或在跨站請求中被帶出 | 第 6、11 章 |

**`http_header_audit.py`**
```python
"""HTTP 安全標頭檢查器：只檢查 scope 內的目標。"""
import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from ratelimit import RateLimiter
from scope_checker import check, load_scope

SECURITY_HEADERS = {
    "Content-Security-Policy": "缺少 CSP，XSS 發生時沒有第二道防線",
    "X-Content-Type-Options": "缺少 nosniff，瀏覽器可能錯判檔案類型",
    "Referrer-Policy": "缺少 Referrer-Policy，網址參數可能經由 Referer 外洩",
    "Permissions-Policy": "缺少 Permissions-Policy",
}
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
VERSION_RE = re.compile(r"\d+\.\d+")


def audit_cookie(raw: str, is_https: bool):
    name = raw.split("=", 1)[0].strip()
    attrs = [a.strip().lower() for a in raw.split(";")[1:]]
    issues = []
    if "httponly" not in attrs:
        issues.append("缺少 HttpOnly（JavaScript 讀得到，XSS 可竊取）")
    if is_https and "secure" not in attrs:
        issues.append("缺少 Secure（可能經由 HTTP 明文送出）")
    samesite = next((a.split("=", 1)[1] for a in attrs if a.startswith("samesite=")), None)
    if samesite is None:
        issues.append("未設定 SameSite（依賴瀏覽器預設值）")
    elif samesite == "none" and "secure" not in attrs:
        issues.append("SameSite=None 但沒有 Secure，瀏覽器會拒絕")
    return name, issues


def audit(url: str, limiter: RateLimiter, timeout: float):
    limiter.wait()
    r = requests.get(url, timeout=timeout,
                     headers={"User-Agent": "pentest-notes-header-audit/0.1 (lab)"})
    is_https = urlparse(r.url).scheme == "https"
    h = r.headers
    findings = []

    for name, msg in SECURITY_HEADERS.items():
        if name not in h:
            findings.append(("missing", name, msg))

    csp = h.get("Content-Security-Policy", "")
    if "X-Frame-Options" not in h and "frame-ancestors" not in csp:
        findings.append(("missing", "X-Frame-Options",
                         "缺少 X-Frame-Options / frame-ancestors，可能被嵌入 iframe（點擊劫持）"))

    if is_https and "Strict-Transport-Security" not in h:
        findings.append(("missing", "Strict-Transport-Security", "HTTPS 網站缺少 HSTS"))

    for name in LEAKY_HEADERS:
        if name in h and VERSION_RE.search(h[name]):
            findings.append(("leak", name, f"洩漏版本資訊：{h[name]}"))

    for raw in r.raw.headers.getlist("Set-Cookie"):
        cname, issues = audit_cookie(raw, is_https)
        for issue in issues:
            findings.append(("cookie", cname, issue))

    return {"url": url, "final_url": r.url, "status": r.status_code, "findings": findings}


def main():
    ap = argparse.ArgumentParser(description="HTTP 安全標頭檢查器")
    ap.add_argument("urls", nargs="+")
    ap.add_argument("-t", "--threads", type=int, default=5)
    ap.add_argument("--rate", type=float, default=5.0, help="每秒請求數上限")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--scope", default="scope.txt")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    allow, deny, window = load_scope(args.scope)
    targets = []
    for url in args.urls:
        host = urlparse(url).hostname
        _, status = check(host, allow, deny, window)
        if status == "✅ IN SCOPE":
            targets.append(url)
        else:
            print(f"[skip] {url}: {status}", file=sys.stderr)

    limiter = RateLimiter(args.rate)
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(audit, u, limiter, args.timeout): u for u in targets}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                results.append(fut.result())
            except requests.RequestException as e:
                results.append({"url": url, "error": e.__class__.__name__, "findings": []})

    results.sort(key=lambda x: args.urls.index(x["url"]))   # 照輸入順序輸出

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return
    icons = {"missing": "⚠️ ", "leak": "🔎", "cookie": "🍪"}
    for res in results:
        print(f"\n=== {res['url']} ===")
        if "error" in res:
            print(f"  ❌ 連線失敗：{res['error']}")
            continue
        print(f"  最終網址：{res['final_url']}（HTTP {res['status']}）")
        if not res["findings"]:
            print("  ✅ 沒有發現問題")
        for kind, name, msg in res["findings"]:
            print(f"  {icons[kind]} {name:<26}{msg}")


if __name__ == "__main__":
    main()
```

**執行：**
```bash
python http_header_audit.py http://127.0.0.1:3000/ http://127.0.0.1:4280/ http://192.168.56.102/ http://8.8.8.8/
```

**預期輸出（大致如下，實際項目依靶場版本不同）：**
```
[skip] http://8.8.8.8/: ⛔ OUT OF SCOPE

=== http://127.0.0.1:3000/ ===
  最終網址：http://127.0.0.1:3000/（HTTP 200）
  ⚠️  Content-Security-Policy   缺少 CSP，XSS 發生時沒有第二道防線
  ⚠️  Referrer-Policy           缺少 Referrer-Policy，網址參數可能經由 Referer 外洩
  ⚠️  Permissions-Policy        缺少 Permissions-Policy

=== http://127.0.0.1:4280/ ===
  最終網址：http://127.0.0.1:4280/login.php（HTTP 200）
  ⚠️  Content-Security-Policy   缺少 CSP，XSS 發生時沒有第二道防線
  ...
  🔎 Server                    洩漏版本資訊：Apache/2.4.x (Debian)
  🍪 security                  缺少 HttpOnly（JavaScript 讀得到，XSS 可竊取）

=== http://192.168.56.102/ ===
  最終網址：http://192.168.56.102/（HTTP 200）
  ⚠️  Content-Security-Policy   缺少 CSP，XSS 發生時沒有第二道防線
  ...
  🔎 Server                    洩漏版本資訊：Apache/2.2.8 (Ubuntu) DAV/2
  🔎 X-Powered-By              洩漏版本資訊：PHP/5.2.4-2ubuntu5.10
```

**小提醒：** 缺少這些標頭本身通常只是低風險或資訊類（Informational）的發現，報告裡不要誇大。它們的價值在於「發生其他漏洞時降低影響」。

---

## 3.9 實作二：Web 存取紀錄分析器（藍隊視角）

**目的：** 第 5–15 章你會對靶場做各種測試，而這些行為都會留在伺服器的 access log 裡。這支工具讓你從**防守方**的角度，看看攻擊行為在 log 中長什麼樣子。

這次完全在自己電腦上進行：先產生一份模擬的 log，再分析它。

### 步驟 1：產生模擬 log

**`gen_sample_log.py`**
```python
"""產生一份模擬的 Apache access log，包含正常流量與幾種可疑行為。"""
import random
from datetime import datetime, timedelta, timezone

random.seed(42)                      # 固定亂數種子，每次產生的內容都一樣
TZ = timezone(timedelta(hours=8))
start = datetime(2026, 11, 9, 21, 0, 0, tzinfo=TZ)
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
lines = []


def log(t, ip, method, path, status, ua=BROWSER, size=None):
    size = size if size is not None else random.randint(200, 5000)
    ts = t.strftime("%d/%b/%Y:%H:%M:%S %z")
    lines.append((t, f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'))


# 1. 正常使用者
normal_paths = ["/", "/index.php", "/about.php", "/products.php?id=3", "/css/site.css", "/js/app.js"]
for i in range(300):
    ip = f"192.168.56.{random.randint(110, 130)}"
    log(start + timedelta(seconds=random.randint(0, 3600)), ip, "GET", random.choice(normal_paths), 200)

# 2. 目錄探測：短時間內大量 404
scanner = "192.168.56.150"
for i, p in enumerate(["/admin/", "/.git/config", "/backup.zip", "/phpmyadmin/", "/wp-login.php",
                       "/.env", "/server-status", "/test.php", "/old/", "/config.bak"] * 3):
    log(start + timedelta(minutes=10, seconds=i), scanner, "GET", p, 404,
        ua="Mozilla/5.0 (compatible; Nikto/2.5.0)")

# 3. 帶有攻擊特徵的參數（URL 編碼過）
attacker = "192.168.56.151"
payload_paths = [
    "/products.php?id=3%27%20OR%20%271%27%3D%271",
    "/products.php?id=3%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/search.php?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "/download.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "/ping.php?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd",
]
for i, p in enumerate(payload_paths):
    log(start + timedelta(minutes=20, seconds=i * 7), attacker, "GET", p, 200)
log(start + timedelta(minutes=21), attacker, "GET", "/products.php?id=1", 200, ua="sqlmap/1.8#stable")

# 4. 登入暴力嘗試：同一個 IP 一分鐘內大量 POST 登入頁
brute = "192.168.56.152"
for i in range(40):
    log(start + timedelta(minutes=30, seconds=i), brute, "POST", "/login.php", 200, size=1520)

lines.sort()
with open("access.log", "w", encoding="utf-8") as f:
    f.writelines(l + "\n" for _, l in lines)
print(f"wrote {len(lines)} lines to access.log")
```

```bash
python gen_sample_log.py      # wrote 376 lines to access.log
head -3 access.log
```

> `.gitignore` 已經排除 `*.log`，這份檔案不會被 commit。

### 步驟 2：分析器

**`log_analyzer.py`**
```python
"""Apache access log 分析器：找出可疑請求、掃描行為與登入暴力嘗試。"""
import argparse
import json
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# (規則名稱, 正規表示式)。比對前會先 URL 解碼並轉小寫
SIGNATURES = [
    ("SQLi",              re.compile(r"('|%27)\s*or\s+'?\d|union\s+select|--\s*$|;\s*drop\s")),
    ("XSS",               re.compile(r"<script|javascript:|onerror\s*=|onload\s*=")),
    ("Path Traversal",    re.compile(r"\.\./|/etc/passwd|win\.ini")),
    ("Command Injection", re.compile(r"[;|&`]\s*(cat|id|whoami|uname|ls)\b")),
]
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|gobuster|ffuf|dirbuster|wpscan|nuclei", re.I)


def parse(path):
    records, bad = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LOG_RE.match(line)
            if not m:
                bad += 1
                continue
            rec = m.groupdict()
            rec["dt"] = datetime.strptime(rec["time"], "%d/%b/%Y:%H:%M:%S %z")
            rec["status"] = int(rec["status"])
            records.append(rec)
    return records, bad


def detect_signatures(records):
    hits = []
    for r in records:
        decoded = unquote_plus(r["path"]).lower()
        for name, rx in SIGNATURES:
            if rx.search(decoded):
                hits.append({"rule": name, "ip": r["ip"], "time": r["time"],
                             "path": unquote_plus(r["path"])})
    return hits


def detect_scanner_ua(records):
    return Counter((r["ip"], r["ua"]) for r in records if SCANNER_UA.search(r["ua"]))


def detect_404_burst(records, threshold):
    c = Counter(r["ip"] for r in records if r["status"] == 404)
    return {ip: n for ip, n in c.items() if n >= threshold}


def detect_login_burst(records, threshold, window_sec):
    """滑動視窗：同一個 IP 在 window_sec 秒內 POST 登入頁超過 threshold 次。"""
    per_ip = defaultdict(deque)
    alerts = {}
    for r in sorted(records, key=lambda x: x["dt"]):
        if r["method"] != "POST" or "login" not in r["path"].lower():
            continue
        q = per_ip[r["ip"]]
        q.append(r["dt"])
        while q and r["dt"] - q[0] > timedelta(seconds=window_sec):
            q.popleft()
        if len(q) >= threshold:
            alerts[r["ip"]] = max(alerts.get(r["ip"], 0), len(q))
    return alerts


def main():
    ap = argparse.ArgumentParser(description="Apache access log 分析器")
    ap.add_argument("logfile")
    ap.add_argument("--404-threshold", dest="t404", type=int, default=20)
    ap.add_argument("--login-threshold", type=int, default=10)
    ap.add_argument("--window", type=int, default=60, help="登入偵測視窗（秒）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    records, bad = parse(args.logfile)
    report = {
        "total": len(records),
        "unparsed": bad,
        "signatures": detect_signatures(records),
        "scanner_ua": [{"ip": ip, "ua": ua, "count": n}
                       for (ip, ua), n in detect_scanner_ua(records).items()],
        "404_burst": detect_404_burst(records, args.t404),
        "login_burst": detect_login_burst(records, args.login_threshold, args.window),
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    print(f"共 {report['total']} 筆，無法解析 {report['unparsed']} 筆\n")
    print("== 攻擊特徵 ==")
    for h in report["signatures"]:
        print(f"  [{h['rule']:<17}] {h['ip']:<16} {h['path']}")
    print("\n== 掃描工具 User-Agent ==")
    for s in report["scanner_ua"]:
        print(f"  {s['ip']:<16} {s['count']:>4} 次  {s['ua']}")
    print(f"\n== 大量 404（>= {args.t404}） ==")
    for ip, n in report["404_burst"].items():
        print(f"  {ip:<16} {n} 次")
    print(f"\n== 登入暴力嘗試（{args.window} 秒內 >= {args.login_threshold} 次） ==")
    for ip, n in report["login_burst"].items():
        print(f"  {ip:<16} 最高 {n} 次 / {args.window} 秒")


if __name__ == "__main__":
    main()
```

**執行：**
```bash
python log_analyzer.py access.log
```

**預期輸出：**
```
共 376 筆，無法解析 0 筆

== 攻擊特徵 ==
  [SQLi             ] 192.168.56.151   /products.php?id=3' OR '1'='1
  [SQLi             ] 192.168.56.151   /products.php?id=3 UNION SELECT username,password FROM users--
  [XSS              ] 192.168.56.151   /search.php?q=<script>alert(1)</script>
  [Path Traversal   ] 192.168.56.151   /download.php?file=../../../../etc/passwd
  [Path Traversal   ] 192.168.56.151   /ping.php?host=127.0.0.1;cat /etc/passwd
  [Command Injection] 192.168.56.151   /ping.php?host=127.0.0.1;cat /etc/passwd

== 掃描工具 User-Agent ==
  192.168.56.150     30 次  Mozilla/5.0 (compatible; Nikto/2.5.0)
  192.168.56.151      1 次  sqlmap/1.8#stable

== 大量 404（>= 20） ==
  192.168.56.150   30 次

== 登入暴力嘗試（60 秒內 >= 10 次） ==
  192.168.56.152   最高 40 次 / 60 秒
```

**觀察：** 最後一筆同時觸發了 Path Traversal 和 Command Injection，因為 payload 裡有 `/etc/passwd`。真實的偵測規則也常有這種重疊，分析人員要自己判斷「主要」是哪一種。

### 這種偵測方式的限制（很重要）
| 限制 | 說明 |
|---|---|
| 看不到 POST body | access log 只記錄網址，表單和 JSON 內容裡的攻擊完全看不到 |
| 編碼變形 | 雙重 URL 編碼、大小寫混用、註解插入，都可能繞過簡單的字串比對 |
| User-Agent 可以隨便改 | 只靠 UA 判斷掃描工具，很容易被繞過 |
| 只看得到「請求」 | 看不出攻擊有沒有成功；回應狀態 200 不代表攻擊成功 |
| 誤判 | 正常的搜尋字串也可能含有 `select`、`<` 等字元 |

所以實務上會搭配 WAF（例如 ModSecurity + OWASP CRS）、應用程式自己的安全 log、以及 SIEM 做關聯分析。

---

## 3.10 測驗

1. 為什麼 `sock.recv(1024)` 通常要放在迴圈裡？只呼叫一次會有什麼問題？
2. `requests.get(url)` 沒有設定 `timeout` 會發生什麼事？
3. Python 有 GIL，為什麼用執行緒寫的網路工具還是會變快？什麼情況下執行緒沒有幫助？
4. 在自己的靶場練習，為什麼也要加上速率限制？
5. 用 `"(.*)"` 解析 log 中的引號欄位會出什麼問題？要怎麼改？
6. 為什麼 log 分析時要先 URL 解碼再比對特徵？
7. 為什麼 HSTS 標頭出現在 HTTP（非 HTTPS）回應中時，瀏覽器會忽略它？
8. `r.headers["Set-Cookie"]` 和 `r.raw.headers.getlist("Set-Cookie")` 有什麼差別？

## 3.11 實作挑戰

1. **（基礎）** 完成 3.8、3.9，貼上兩支工具對靶場和 `access.log` 的輸出。
2. **（socket）** 擴充 `banner.py`：
   - 用 argparse 接受 `--ports 21,22,25,80`
   - 用 `ThreadPoolExecutor` 並行，並套用 `RateLimiter`
   - 對「沒有主動送資料」的埠，改送 `HEAD / HTTP/1.0\r\n\r\n` 再讀一次回應
3. **（log 分析）** 擴充 `log_analyzer.py`：
   - 加上 `--follow` 模式：像 `tail -f` 一樣持續讀取新寫入的行，即時告警
   - 把 DVWA 容器的真實 log 拿來分析：`docker logs dvwa 2>/dev/null > dvwa_access.log`（容器名稱用 `docker ps` 確認），之後每做完一章 Web 練習，就回來看看自己的攻擊在 log 裡長什麼樣子
4. **（防禦）** 根據 `http_header_audit.py` 對 msf2 的結果，寫出一段 Apache 2.4 設定（`mod_headers`）和 PHP 設定，修掉你找到的所有項目。
5. **（思考）** 你是藍隊。攻擊者知道你用 3.9 的規則偵測，他可能怎麼避開？針對每一種避開方式，你會怎麼補強？

---

## 參考資料
- Python 官方文件：`socket`、`re`、`concurrent.futures`、`argparse`（https://docs.python.org/3/library/）
- Python Socket Programming HOWTO：https://docs.python.org/3/howto/sockets.html
- Requests 文件：https://requests.readthedocs.io
- Beautiful Soup 文件：https://www.crummy.com/software/BeautifulSoup/bs4/doc/
- regex101（線上測試正規表示式，可選 Python 語法）：https://regex101.com
- OWASP Secure Headers Project：https://owasp.org/www-project-secure-headers/
- MDN HTTP 標頭說明：https://developer.mozilla.org/docs/Web/HTTP/Headers
- Apache 紀錄格式：https://httpd.apache.org/docs/2.4/logs.html
- OWASP Core Rule Set（WAF 規則）：https://coreruleset.org

---

<details>
<summary><b>📖 解答（建議先自己做完再看）</b></summary>

### 測驗解答
1. TCP 是位元組流，`recv(1024)` 只保證「最多」1024 bytes，可能只收到一部分，也可能把兩則訊息黏在一起收到。只呼叫一次，資料大一點或網路慢一點就會讀不完整。要在迴圈中一直收，直到遇到自己定義的結束條件（換行、長度欄位、對方關閉連線）。
2. 預設沒有逾時，如果對方接受連線卻不回應，程式會**永遠卡住**。在多執行緒工具中，卡住的執行緒會佔住 pool 的名額，最後整支工具停擺。
3. 執行緒在等待網路 I/O 時會釋放 GIL，其他執行緒可以趁這段時間送出請求，所以總時間大幅縮短。如果工作是 CPU 密集的（雜湊計算、壓縮、大量字串處理），GIL 會讓多執行緒幾乎沒有加速效果，要改用 `multiprocessing` 或 `ProcessPoolExecutor`。
4. (1) msf2 只有 512MB 記憶體，打太快可能讓服務當掉，影響後續練習；(2) 養成習慣，真實案件的 ROE 通常會限制速率，或禁止影響服務；(3) 速率太快時，錯誤和逾時會變多，結果反而不準。
5. `.*` 是貪婪比對，會一路吃到「最後一個」引號，把好幾個欄位吃在一起。改成非貪婪 `"(.*?)"`，或更明確的 `"([^"]*)"`。
6. 攻擊字串在網址中通常是 URL 編碼的，例如 `'` 會變成 `%27`、空白變成 `%20` 或 `+`。不先解碼，`' OR` 這種規則根本比對不到。
7. 如果攻擊者能竄改 HTTP 明文回應（中間人），他也能偽造 HSTS 標頭，例如設定一個極長的時間讓網站無法降回 HTTP，或刪掉它。所以規範（RFC 6797）規定瀏覽器只接受經由 HTTPS 安全傳輸的 HSTS 標頭。
8. 一個回應可能有多個 `Set-Cookie`。`r.headers` 會把同名標頭用逗號合併成一個字串，但 Cookie 的 `Expires` 屬性本身就含有逗號，合併後很難正確切開。`getlist` 會分別取出每一個原始值。

### 挑戰 2 參考解答
```python
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

from ratelimit import RateLimiter
from scope_checker import check, load_scope


def grab(host, port, limiter, timeout=3):
    limiter.wait()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            try:
                data = s.recv(1024)
            except socket.timeout:
                data = b""
            if not data:   # 用戶端先說話的協定（例如 HTTP），主動送一個最小的請求
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                try:
                    data = s.recv(1024)
                except socket.timeout:
                    data = b""
            text = data.decode(errors="replace").strip()
            return port, text.splitlines()[0] if text else "(open, no banner)"
    except OSError as e:
        return port, f"(closed/filtered: {e.__class__.__name__})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--ports", default="21,22,25,80")
    ap.add_argument("--rate", type=float, default=5.0)
    ap.add_argument("--scope", default="scope.txt")
    args = ap.parse_args()

    allow, deny, window = load_scope(args.scope)
    _, status = check(args.host, allow, deny, window)
    if status != "✅ IN SCOPE":
        sys.exit(f"{args.host}: {status}")

    ports = [int(p) for p in args.ports.split(",")]
    limiter = RateLimiter(args.rate)
    with ThreadPoolExecutor(max_workers=10) as pool:
        for port, banner in pool.map(lambda p: grab(args.host, p, limiter), ports):
            print(f"{port:<6}{banner}")


if __name__ == "__main__":
    main()
```
80 埠現在會顯示 `HTTP/1.1 200 OK` 這類狀態行。想看 `Server` 標頭，可以把整段回應印出來，而不是只取第一行。

### 挑戰 3 參考解答（`--follow` 部分）
```python
import time

def follow(path):
    """類似 tail -f：從檔案結尾開始，持續讀取新行。"""
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)                    # 移到檔案結尾
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

# 在 main() 中：
# if args.follow:
#     for line in follow(args.logfile):
#         m = LOG_RE.match(line)
#         if not m:
#             continue
#         rec = m.groupdict()
#         for h in detect_signatures([rec]):
#             print(f"[ALERT] {h['rule']} from {h['ip']}: {h['path']}", flush=True)
```
即時模式下只做「單筆就能判斷」的特徵比對最簡單；404 次數和登入暴力這類需要累積的規則，要另外為每個 IP 維護狀態（例如沿用 `deque` 滑動視窗）。

### 挑戰 4 參考解答
```apache
# /etc/apache2/conf-available/security.conf
ServerTokens Prod          # Server 標頭只顯示 "Apache"
ServerSignature Off        # 錯誤頁面不顯示版本
TraceEnable Off

# 需要先啟用：a2enmod headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'none'"
    Header unset X-Powered-By
    # 只有在全站 HTTPS 時才加：
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</IfModule>
```
```ini
; php.ini
expose_php = Off                 ; 不送出 X-Powered-By
session.cookie_httponly = 1
session.cookie_samesite = "Lax"
session.cookie_secure = 1        ; 只在 HTTPS 環境啟用
```
注意：CSP 要依網站實際使用的資源調整，直接套用 `default-src 'self'` 可能讓頁面壞掉。實務上會先用 `Content-Security-Policy-Report-Only` 觀察一段時間。另外，msf2 的 Apache 2.2.8 和 PHP 5.2 早已停止維護，真正的修補是升級。

### 挑戰 5 參考解答
| 避開方式 | 補強方法 |
|---|---|
| 把攻擊放在 POST body 或 JSON 裡 | 在 WAF 或應用程式層記錄並檢查請求內容 |
| 雙重編碼、大小寫混用、插入註解（`UN/**/ION`） | 反覆解碼到不再變化、正規化後再比對；使用成熟的規則集（OWASP CRS）而不是自己寫字串比對 |
| 改掉 User-Agent | 不依賴 UA，改看行為：請求速率、404 比例、路徑多樣性 |
| 放慢速度，避開次數門檻 | 拉長觀察時間窗（例如 24 小時內的總失敗次數），並以帳號為單位計算，而不只是以 IP |
| 換很多 IP（代理、雲端主機） | 以「目標帳號」為中心偵測暴力嘗試；搭配 IP 信譽資料 |
| 攻擊成功後刪 log | log 即時送到另一台主機（syslog、SIEM），攻擊者碰不到 |

重點是：**特徵比對只能抓到「不小心」的攻擊者**，要搭配行為分析、多來源關聯和集中式 log 才有意義。

</details>
