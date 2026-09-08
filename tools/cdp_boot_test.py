#!/usr/bin/env python3
"""Headless-Chrome CDP boot test for the demo page.

Serves demo/, loads system/index.html, clicks a run button, waits for
expected terminal text. Usage:
  cdp_boot_test.py <button-id> <expect-regex> [timeout-s]
Exits 0 on match, 1 on timeout/error.
"""
import json
import re
import subprocess
import sys
import time
import urllib.request

import websocket

CHROME = "google-chrome"
PORT = 9331


def cdp(method, params=None, wid=1):
    msg = {"id": wid, "method": method}
    if params:
        msg["params"] = params
    ws.send(json.dumps(msg))
    while True:
        r = json.loads(ws.recv())
        if r.get("id") == wid:
            return r.get("result", {})


button, expect = sys.argv[1], sys.argv[2]
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 280

srv = subprocess.Popen(
    [sys.executable, "tools/dev-server.py", "--directory", "demo",
     "--bind", "127.0.0.1", "--port", "8932"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)
chrome = subprocess.Popen(
    [CHROME, "--headless", "--no-sandbox", "--disable-gpu",
     "--remote-allow-origins=*",
     f"--remote-debugging-port={PORT}", "--user-data-dir=/tmp/cdp-prof",
     "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    tabs = None
    for _ in range(30):
        try:
            tabs = json.load(urllib.request.urlopen(
                f"http://127.0.0.1:{PORT}/json/list", timeout=5))
            break
        except Exception:
            time.sleep(1)
    if not tabs:
        print("no devtools endpoint");
        sys.exit(2)
    pages = [t for t in tabs if t.get("type") == "page"]
    if not pages:
        nt = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/json/new?about:blank", timeout=5))
        pages = [nt]
    ws = websocket.create_connection(pages[0]["webSocketDebuggerUrl"],
                                     timeout=30)
    cdp("Page.enable")
    cdp("Runtime.enable")
    cdp("Page.navigate",
        {"url": "http://127.0.0.1:8932/system/index.html"})
    time.sleep(8)
    # wait for buttons enabled (runtime ready), then click
    clicked = False
    for _ in range(60):
        r = cdp("Runtime.evaluate",
                {"expression": f"document.getElementById('{button}')?.disabled",
                 "returnByValue": True}, wid=99)
        if r.get("result", {}).get("value") is False:
            cdp("Runtime.evaluate",
                {"expression": f"document.getElementById('{button}').click()"})
            clicked = True
            break
        time.sleep(2)
    if not clicked:
        print("button never enabled");
        sys.exit(2)
    # poll terminal text for the expected string (xterm canvas: read the
    # scrollback buffer via the exposed handle)
    pat = re.compile(expect)
    term_js = ("(() => { const t = window.__espTerm; if (!t) return '';"
               " const b = t.buffer.active; let s = '';"
               " for (let i = 0; i < b.length; i++)"
               " { const l = b.getLine(i); if (l) s += l.translateToString() + '\\n'; }"
               " return s.slice(-6000); })()")
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(10)
        r = cdp("Runtime.evaluate", {"expression": term_js,
                                     "returnByValue": True}, wid=100)
        txt = r.get("result", {}).get("value", "") or ""
        if pat.search(txt):
            print(f"MATCH after {time.time()-t0:.0f}s")
            sys.exit(0)
    print("TIMEOUT waiting for match")
    sys.exit(1)
finally:
    chrome.terminate()
    srv.terminate()
