# -*- coding: utf-8 -*-
"""extract_meta.py — 无需解密的微信明文元数据信号探针（文件名/时间/体量）。

只读文件系统元数据（文件名、按月目录、mtime），不读任何聊天内容、不需要密钥。
用于在拿到密钥之前先评估数据体量与时间跨度。

用法:
    python extract_meta.py --root "D:\\...\\xwechat_files\\wxid_xxx_00c2" \
        [--root "D:\\...\\WeChat Files"] [--out _wx_meta_digest.md]
"""
import argparse
import glob
import os
import re
import time
from collections import Counter

# 文件名主题关键词（按需自定义）
kw_pat = re.compile(
    r"(报告|总结|论文|文档|方案|数据|代码|项目|会议|简历|证书|成绩|"
    r"PDF|pdf|docx|xlsx|pptx|zip|7z)")

# 有信息量的文件名样本筛选（按需自定义）
notable_pat = re.compile(r"(简历|证书|成绩|论文|报告|申请|合同|offer)", re.I)


def scan_files(roots):
    by_month = Counter()
    kw = Counter()
    notable = []
    total = 0
    for root in roots:
        # 微信 4.x: msg/file/YYYY-MM ; 微信 3.x: FileStorage/YYYY-MM
        cands = []
        if os.path.isdir(os.path.join(root, "msg", "file")):
            cands += glob.glob(os.path.join(root, "msg", "file", "[0-9]" * 4 + "-[0-9][0-9]"))
        fs = os.path.join(root, "FileStorage")
        if os.path.isdir(fs):
            cands += [d for d in glob.glob(os.path.join(fs, "*"))
                      if re.search(r"\d{4}-\d{2}$", os.path.basename(d))]
        for month_dir in cands:
            month = os.path.basename(month_dir)
            for dirpath, dirs, files in os.walk(month_dir):
                for f in files:
                    if f.startswith((" THUMB", ".")):
                        continue
                    total += 1
                    by_month[month] += 1
                    for m in kw_pat.finditer(f):
                        kw[m.group(1)] += 1
                    if notable_pat.search(f) and len(notable) < 80:
                        try:
                            mt = time.strftime(
                                "%Y-%m-%d",
                                time.localtime(os.path.getmtime(os.path.join(dirpath, f))))
                        except Exception:
                            mt = "?"
                        notable.append((mt, f[:80]))
    return by_month, kw, sorted(notable), total


def scan_media_volume(roots):
    """attach/video/FileStorage 目录体量: 按月 mtime 聚合（不含文件名）"""
    vol = Counter()
    for root in roots:
        for sub in (os.path.join("msg", "attach"), os.path.join("msg", "video"), "FileStorage"):
            p = os.path.join(root, sub)
            if not os.path.isdir(p):
                continue
            for dirpath, dirs, files in os.walk(p):
                for f in files:
                    try:
                        mt = time.strftime(
                            "%Y-%m",
                            time.localtime(os.path.getmtime(os.path.join(dirpath, f))))
                        vol[mt] += 1
                    except Exception:
                        pass
    return vol


def main():
    ap = argparse.ArgumentParser(description="微信明文元数据信号探针（无需解密）")
    ap.add_argument("--root", action="append", required=True,
                    help="微信数据目录（wxid_xxx_00c2 或 WeChat Files），可多次传入")
    ap.add_argument("--out", default="_wx_meta_digest.md", help="输出 Markdown 路径")
    args = ap.parse_args()

    by_month, kw, notable, total = scan_files(args.root)
    vol = scan_media_volume(args.root)

    lines = ["# 微信明文元数据信号（文件名/时间线，无需解密）", ""]
    lines.append(f"## 收发文件总数: {total}")
    lines.append("## 按月分布（有文件名的收发文件）")
    for m in sorted(by_month):
        lines.append(f"- {m}: {by_month[m]}")
    lines.append("")
    lines.append("## 文件名关键词频次")
    for k, v in kw.most_common(40):
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("## 重点文件名样本")
    for mt, f in notable:
        lines.append(f"- [{mt}] {f}")
    lines.append("")
    lines.append("## 全部媒体活跃度（含图片/视频，按月，含聊天缓存）")
    for m in sorted(vol):
        lines.append(f"- {m}: {vol[m]}")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("written", args.out, len(lines), "lines, files:", total)


if __name__ == "__main__":
    main()
