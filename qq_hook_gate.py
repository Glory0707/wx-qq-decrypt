# -*- coding: utf-8 -*-
"""qq_hook_gate.py — child gating 版 Frida hook: QQ 主进程与所有子进程启动即挂钩。

适用场景: 开库发生在子进程、且早于脚本完成 attach 时，用 spawn + enable_child_gating
让每个子进程在首条指令前就被挂上，杜绝竞态。抓到的 passphrase 逐行写入 --out。

用法:
    python qq_hook_gate.py --qq "C:\\Program Files\\Tencent\\QQNT\\QQ.exe" \
        --script qq_hook.js --out qq_keys_live.txt
然后完成自动登录（或扫码），观察输出中的 KEY: 行。
"""
import argparse
import time

import frida


def main():
    ap = argparse.ArgumentParser(description="QQ NT 全进程 child-gating hook")
    ap.add_argument("--qq", default="QQ.exe", help="QQ.exe 路径")
    ap.add_argument("--script", default="qq_hook.js", help="Frida hook 脚本")
    ap.add_argument("--out", default="qq_keys_live.txt", help="passphrase 输出文件")
    ap.add_argument("--wait", type=int, default=420, help="挂机秒数")
    args = ap.parse_args()

    with open(args.script, "r", encoding="utf-8") as f:
        js = f.read()

    device = frida.get_local_device()
    hooks = {}

    def make_handler(pid_label):
        def on_message(msg, data):
            if msg.get("type") == "send":
                p = msg["payload"]
                if p.get("type") == "key" and data:
                    key = bytes(data)
                    line = f"{pid_label}\t{p.get('db', '?')}\t{key.hex()}\n"
                    print("KEY:", line.strip(), flush=True)
                    with open(args.out, "a", encoding="utf-8") as f:
                        f.write(line)
                else:
                    print(f"[{pid_label}]", p, flush=True)
            elif msg.get("type") == "error":
                print(f"[{pid_label}][error]", msg.get("description"), flush=True)
        return on_message

    def hook_pid(pid, label, gated=False):
        if pid in hooks:
            return
        try:
            s = device.attach(pid)
            sc = s.create_script(js)
            sc.on("message", make_handler(f"{label}:{pid}"))
            sc.load()
            hooks[pid] = s
            print(f"hooked {label} pid={pid}", flush=True)
            if gated:
                device.resume(pid)
                print(f"resumed gated child {pid}", flush=True)
        except Exception as e:
            print(f"hook {pid} fail: {e}", flush=True)

    def on_child_added(child):
        print("child-added:", child.pid, flush=True)
        hook_pid(child.pid, "child", gated=True)

    device.on("child-added", on_child_added)

    pid = device.spawn([args.qq])
    print("spawned:", pid, flush=True)
    hook_pid(pid, "main")
    hooks[pid].enable_child_gating()
    device.resume(pid)
    print("main resumed with child gating", flush=True)

    t0 = time.time()
    while time.time() - t0 < args.wait:
        time.sleep(1)
    print("done", flush=True)


if __name__ == "__main__":
    main()
