# -*- coding: utf-8 -*-
"""qq_hook_run.py — 启动 QQ 并用 Frida hook 捕获数据库 passphrase
用法: python qq_hook_run.py spawn | attach <pid>
"""
import sys
import time

import frida

QQ_EXE = r"D:\qq\QQ.exe"
OUT = r".\qq_keys_live.txt"
JS = open(r".\qq_hook.js", "r", encoding="utf-8").read()

mode = sys.argv[1] if len(sys.argv) > 1 else "spawn"

if mode == "spawn":
    pid = frida.spawn([QQ_EXE])
    print("spawned pid:", pid, flush=True)
    session = frida.attach(pid)
else:
    pid = int(sys.argv[2])
    session = frida.attach(pid)
    print("attached pid:", pid, flush=True)

script = session.create_script(JS)
captured = []

def on_message(msg, data):
    if msg.get("type") == "send":
        p = msg["payload"]
        print("[msg]", p, flush=True)
        if p.get("type") == "key" and data:
            key = bytes(data)
            print("KEY CAPTURED:", key.hex(), key, flush=True)
            captured.append(key)
            with open(OUT, "a", encoding="utf-8") as f:
                f.write(f"{p.get('db','?')}\t{key.hex()}\n")
    elif msg.get("type") == "error":
        print("[error]", msg.get("description"), flush=True)

script.on("message", on_message)
script.load()
if mode == "spawn":
    frida.resume(pid)

# 子进程也全部附加挂钩 (db 可能由其它 QQ.exe 进程打开)
import threading

def watch_children():
    import psutil
    seen = {pid}
    while time.time() - t0 < 600:
        try:
            for pr in psutil.process_iter(["name"]):
                try:
                    if pr.info["name"] and pr.info["name"].lower() == "qq.exe" and pr.pid not in seen:
                        seen.add(pr.pid)
                        print("attaching child:", pr.pid, flush=True)
                        try:
                            s2 = frida.attach(pr.pid)
                            sc2 = session.create_script(JS)  # 同一脚本重新编译一份
                            sc2.on("message", on_message)
                            sc2.load()
                        except Exception as e:
                            print("child attach fail:", pr.pid, e, flush=True)
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(0.3)

_t0_ = time.time()
t0 = _t0_
threading.Thread(target=watch_children, daemon=True).start()
print("running... (Ctrl+C 结束)", flush=True)

t0 = time.time()
try:
    while time.time() - t0 < 600:
        time.sleep(1)
except KeyboardInterrupt:
    pass
print("captured:", captured, flush=True)
