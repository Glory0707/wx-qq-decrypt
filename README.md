# wx-qq-decrypt

Windows 端微信 4.x / QQ NT（9.9.35 实测）本地聊天记录解密管线。

> 本项目是**本机自有账号数据**的解密与备份工具，仅供学习研究与个人数据自主管理。
> 请勿用于任何违法用途或他人设备；使用产生的风险自负。

## 背景：为什么"老方法"都失效了

| | 微信 3.x / 微信 4.0 早期 | **微信 4.1.x** | **QQ NT 9.9.3x 早期** | **QQ NT 9.9.35** |
|---|---|---|---|---|
| 密钥获取 | 内存扫 `x'<hex>'` | ❌ 内存会被主动清空 | 内存扫 16 位 passphrase | ❌ passphrase 每库独立、登录后清内存 |
| 可行方案 | ReadProcessMemory | **DLL/代码注入 hook 开库函数** | hook / 调试器 | **Frida hook + 已知明文内存搜派生密钥** |

本项目对两个"新一代"场景给出完整可复现管线。

## 微信 4.x（实测 4.1.13.12）

### 原理

- 数据库为 SQLCipher 4 页加密：`盐=文件头16B`，`enc=PBKDF2-SHA512(passphrase,盐,256000)`，
  `mac=PBKDF2-SHA512(enc,盐^0x3a,2)`，每页 `[密文][IV16][HMAC-SHA512 64]`
- 密钥（32B raw）以 `{指针, len=0x20, cap}` 堆描述符存在主进程内存，但**长时间运行后会被清空**
- 因此用 wx_key（DLL 注入，hook 开库调用）在登录瞬间抓 passphrase；wx_key 项目已删库，
  本仓库 `tools/wx_key-2.0.1` 的获取方式见下方"致谢"

### 用法

```bash
python wx4.py keyscan    # 或使用 wx_key 抓取后写入 wx_keys.txt（行格式: <64hex>\tkdf=True）
python wx4.py decrypt    # 全库解密到 decrypted/
python extract_me.py     # （可选）聚合摘要，需自行修改个人关键词
```

要求：微信已登录（重登窗口期抓钥最稳）；解密参数已实测对 4.1.13 全部 27 库 HMAC 通过。

## QQ NT（实测 9.9.35-52892）

### 原理（三层递进）

1. **hook `nt_sqlite3_key_v2`**（`qq_hook.js` + `qq_hook_run.py`）
   - 离线用 capstone 对 `wrapper.node` 定位：字符串 `nt_sqlite3_key_v2: db=%p zDb=%s` → LEA 交叉引用 →
     `.pdata` 异常目录回溯函数起点（9.9.35 为 RVA `0x21B8C80`，函数序言 `mov esi,r9d / mov rdi,r8` 即 pKey/nKey）
   - Frida spawn 挂钩后自动登录，开库瞬间读 `r8`/`r9` 得 passphrase
   - ⚠️ passphrase 为服务器按账号下发（本机实测 20 字节，二进制与 ASCII 混合，每库可不同）
2. **已知明文搜派生密钥**（`scan_derived.py` / `qq_scan_db.py`）
   - 真库验证失败的根源：持库进程与可注入进程不一定是同一个
   - 利用 SQLite 页 1 明文头指纹（`10 00 02 02 50 40 20 20`，即页 4096 / WAL / 保留 0x50），
     对**任意可读进程**内存做 32 字节滑窗 AES 解密匹配 —— 直接找到**派生后的 AES-256 密钥**，绕过 passphrase
   - 多进程时先用页缓存明文指纹（`group_msg_table` 等）定位持库进程
   - 📄 原理细节与实测结论见 [docs/known_plaintext_key_recovery.md](docs/known_plaintext_key_recovery.md)
3. **整库解密**（`qq_decrypt_db.py`）
   - 文件头 1024B 私有头（protobuf，含 `key_meta`）剥离
   - 每页 `[密文 4048][IV 16][填充 12][HMAC-SHA1 20]`，`enc=PBKDF2-SHA512(passphrase,盐,4000)`
   - 也可用 `sqlcipher3`（PyPI 有 Windows wheel）直接 PRAGMA 解密

### 用法

```bash
# 1) 重启 QQ 抓登录期 passphrase（部分版本/进程可跳过）
python qq_hook_run.py spawn

# 2) 找到持库进程（页缓存明文指纹），对目标库搜派生密钥
python qq_scan_db.py nt_msg.db <持库pid>

# 3) 解密（qq_derived_keys/<db>.key 中存放 hex 密钥）
python qq_decrypt_db.py nt_msg.db
# 或官方 sqlcipher3 等价物：
#   PRAGMA cipher_page_size=4096; PRAGMA key='...'; PRAGMA kdf_iter=4000;
#   PRAGMA cipher_hmac_algorithm=HMAC_SHA1; PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512;
# ⚠️ 坑: sqlcipher 连接上的 VACUUM INTO 产物仍是同密钥加密库;
#    明文导出须 ATTACH 明文库(KEY='') + SELECT sqlcipher_export('plain');
```

实测产出：`nt_msg_plain.db` 私聊 75,632 条 + 群聊 1,542,705 条，`PRAGMA integrity_check` = ok。

### 消息体解析（40800 列 protobuf → 明文）

```bash
python qq_parse_msg.py                 # 单聊+群聊全量导出为可读 txt（约 1.5 分钟 / 160 万条）
python qq_parse_msg.py --json out.json # 另存结构化 JSON
```

输出示例：
```
[2023-06-13 15:47:07] 群1108894296 某某(123456): [引用] 必须振作 | @某人 |  啥时候学驾驶？
```

解码器 v2：单字段解析失败时**字节 +1 重同步**恢复前缀，文本走
`utf-8 优先 → GBK 修复`双解码链（带二次乱码指纹门槛，防 UTF-8 中文被误按 GBK 解）。
实测 161 万条仅 2 条解析失败（0.0001%）。字段表参考 miniyu157/qq-dump 的
`proto_maps.py`（~260 个字段语义），本脚本已内联并自带无 schema 递归解码器，无 blackboxprotobuf 依赖。

### 关键发现：QQ NT 9.9.35 每库密钥独立

对同一账号同一登录会话内的四个库（nt_msg / group_info / profile_info / collection）分别
恢复派生密钥，得到 **4 个互不相同的 32 字节 AES 密钥**（跨进程重启但同会话时值保持稳定）。

这与社区文档描述的旧版行为（一个账号一把 16 字符 passphrase 共享全部库）不同：
旧版"抓到一把钥匙解所有库"的方法在新版上天然失效，必须逐库恢复密钥。
验证方式见 [docs/known_plaintext_key_recovery.md](docs/known_plaintext_key_recovery.md)。

## 文件

| 文件 | 用途 |
|---|---|
| `wx4.py` | 微信 4.x 密钥验证 / 内存扫描 / 批量页解密 |
| `qqnt.py` | QQ NT 库结构（1024B 头剥离、SQLCipher 参数）解密 |
| `qq_hook.js` / `qq_hook_run.py` / `qq_hook_all.py` / `qq_hook_gate.py` | Frida hook（单进程 / 全进程 / child gating） |
| `scan_derived.py` / `qq_scan_db.py` | 已知明文派生密钥内存搜索 |
| `qq_decrypt_db.py` / `qq_decrypt_all.py` | QQ 库批量解密 |
| `find_holder.py` | 句柄枚举，定位持有目标库的进程 |
| `qq_parse_msg.py` | 消息体 protobuf（40800 列）→ 可读文本；支持单聊/群聊、无 schema 递归解码、uid→昵称映射、多元素渲染（引用/表情/图片/文件/红包/灰条等） |

## 依赖

```
pip install pycryptodome psutil frida sqlcipher3 capstone pefile
```

- `sqlcipher3` 0.6.2 提供 Windows wheel（官方 NTQQ 解密教程同款）
- frida 需与本机 Python/Node 匹配；对拒绝注入的受保护进程，改用内存读取类脚本即可

## 致谢与参考

- [QQBackup/qq-win-db-key](https://github.com/QQBackup/qq-win-db-key) 与 [QQDecrypt 文档](https://qqbackup.github.io/QQDecrypt/)：QQ NT 解密体系、`nt_sqlite3_key_v2` 定位思路
- [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis)（含 vendor 的 wx_key wheel）：微信 4.x 密钥结构描述符与 KDF 参数
- [ycccccccy/wx_key]、[0xlane/wechat-dump-rs]：早期开创性工作（仓库均已删库）
- QQDecrypt 研究笔记：`key_meta` / OIDB `0xcde` 密钥下发机制

## License

MIT
