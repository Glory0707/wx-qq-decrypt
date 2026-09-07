"""
配置加载器 - 从 config.json 读取路径配置
首次运行时自动生成 config.json 模板
"""
import json
import os
import sys

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

_DEFAULT = {
    "db_dir": r"D:\xwechat_files\your_wxid\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "decoded_image_dir": "decoded_images",
    "wechat_process": "Weixin.exe",
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(_DEFAULT, f, indent=4)
        print(f"[!] 已生成配置文件: {CONFIG_FILE}")
        print("    请修改 config.json 中的路径后重新运行")
        sys.exit(1)

    with open(CONFIG_FILE) as f:
        cfg = json.load(f)

    # 将相对路径转为绝对路径
    base = os.path.dirname(os.path.abspath(__file__))
    for key in ("keys_file", "decrypted_dir", "decoded_image_dir"):
        if key in cfg and not os.path.isabs(cfg[key]):
            cfg[key] = os.path.join(base, cfg[key])

    # 自动推导微信数据根目录（db_dir 的上级目录）
    # db_dir 格式: D:\xwechat_files\<wxid>\db_storage
    # base_dir 格式: D:\xwechat_files\<wxid>
    db_dir = cfg.get("db_dir", "")
    if db_dir and os.path.basename(db_dir) == "db_storage":
        cfg["wechat_base_dir"] = os.path.dirname(db_dir)
    else:
        cfg["wechat_base_dir"] = db_dir

    # decoded_image_dir 默认值
    if "decoded_image_dir" not in cfg:
        cfg["decoded_image_dir"] = os.path.join(base, "decoded_images")

    return cfg
