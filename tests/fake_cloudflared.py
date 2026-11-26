"""Stand-in for cloudflared in tests. Behaviour chosen by FAKE_CF_MODE:
ok (default) | fail | silent | api_only | die_after_<seconds> | ignore_term"""
import os
import random
import signal
import sys
import time

if "--version" in sys.argv:
    print("cloudflared version 2099.1.0 (built fake)")
    sys.exit(0)

mode = os.environ.get("FAKE_CF_MODE", "ok")
words = ["mild", "owl", "tree", "sky", "quiet", "fox", "lake", "moss", "brave", "cat", "pine", "dew"]
host = "-".join(random.sample(words, 4)) + ".trycloudflare.com"

if mode == "ignore_term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)      # a hung cloudflared: only SIGKILL stops it (set BEFORE printing the URL)
print("2026-11-23T00:00:00Z INF Thank you for trying Cloudflare Tunnel.", flush=True)
print("2026-11-23T00:00:00Z INF Requesting new quick Tunnel on trycloudflare.com...", flush=True)
if mode == "fail":
    print("ERR failed to request quick Tunnel: Post https://api.trycloudflare.com/tunnel: dial tcp: i/o timeout", flush=True)
    sys.exit(1)
if mode == "api_only":
    print("ERR see https://api.trycloudflare.com/tunnel for details", flush=True)
elif mode != "silent":
    print("+--------------------------------------------------------------------+", flush=True)
    print(f"|  Your quick Tunnel has been created! Visit it at:                  |", flush=True)
    print(f"|  https://{host}                                  |", flush=True)
    print("+--------------------------------------------------------------------+", flush=True)
if mode.startswith("die_after_"):
    time.sleep(float(mode.split("_")[-1]))
    sys.exit(3)
while True:
    time.sleep(0.2)
