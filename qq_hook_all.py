# -*- coding: utf-8 -*-
"""qq_hook_all.py — 给所有现有 QQ.exe 进程挂 hook, 并监视新进程"""
import time

import frida
import psutil

JS = open(r".\qq_hook.js", "r", encoding="utf-8").read()
OUT = r".\qq_keys_live.txt"
device = frida.get_local_device()
done = set()


def make_handler(label):
    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("type") == "key" and data:
                key = bytes(data)
                line = f"{label}\t{p.get('db','?')}\t{key.hex()}\n"
                print("KEY:", line.strip(), flush=True)
                with open(OUT, "a", encoding="utf-8") as f:
                    f.write(line)
        elif msg.get("type") == "error":
            print(f"[{label}] err:", msg.get("description"), flush=True)
    return on_message


def try_hook(pid, label="main"):
    if pid in done:
        return True
    try:
        s = device.attach(pid)
        sc = s.create_script(JS)
        sc.on("message", make_handler(f"{label}:{pid}"))
        sc.load()
        done.add(pid)
        print(f"hooked {pid}", flush=True)
        return True
    except Exception as e:
        print(f"hook {pid} fail: {e}", flush=True)
        return False


t0 = time.time()
while time.time() - t0 < 900:
    pids = [p.pid for p in psutil.process_iter(["name"])
            if p.info["name"] and p.info["name"].lower() == "qq.exe"]
    for pid in pids:
        try_hook(pid, "relogin")
    time.sleep(0.5)
print("done", flush=True)
