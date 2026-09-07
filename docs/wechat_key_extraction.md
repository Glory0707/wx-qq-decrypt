# 微信 4.1.x 密钥提取与全库解密

> 适用：微信 4.1.x（实测 4.1.13.12，Windows）。3.x / 4.0 早期版本沿用老的内存扫描
> `x'<64hex>'` 字符串方案即可，本文不赘述。

## 为什么 4.1.x 内存扫描失效

微信 4.x 的数据库密钥（32 字节 raw AES-256）不再以字符串形式常驻内存，而是以
**堆描述符** 形态存在：

```
{指针 → 32B key, len = 0x20, capacity}   # 三连 8 字节结构
```

且登录完成后客户端会**主动清零**该缓冲区——启动后过了登录窗口才去扫内存，
扫到的只有清零后的空洞。这就是 `x'<hex>'` 特征串扫描和 "xx" 描述符扫描
在 4.1.x 上双双失效的原因。

**结论：必须在"密钥还在内存里"的时间窗内拿钥，即 hook 开库调用（DLL 注入），
或登录瞬间并发扫描。**

## SQLCipher 参数（实测）

| 参数 | 值 |
|---|---|
| 页大小 | 4096 |
| KDF | PBKDF2-HMAC-SHA512，**256000** 轮，盐 = 库文件头 16B |
| MAC | HMAC-SHA512，mac key = PBKDF2-SHA512(enc key, 盐^0x3a, 2 轮) |
| 页布局 | `[密文 4032][IV 16][HMAC 64]`（reserve = 80） |

`wx4.py keyscan` 用页 1 HMAC 校验钥匙正确性，全 27 库 HMAC 通过即为有效钥匙。

## 流程

```
1. wx_key（DLL 注入 wheel，hook 开库调用）在登录瞬间抓 passphrase
   → 写入 wx_keys.txt（行格式: <64hex>\tkdf=True）
   （wx_key 原仓库已删库，可从 LifeArchiveProject/WeChatDataAnalysis 的
    vendor 目录获取，见 README 致谢）
2. python wx4.py keyscan   # 校验钥匙（页1 HMAC）
3. python wx4.py decrypt   # 批量页解密 → local/decrypted/
4. python extract_me.py    # 可选: 本人消息聚合摘要
```

要点：

- 抓钥时 **重新登录一次**（退出→登录）最稳，登录窗口期钥匙必然在内存
- 钥匙是**全账号一把**：27 个库（contact / message / session / sns / favorite ...）
  共用，抓一次即可全量解密——与 QQ NT 的每库一钥完全不同
- 解密后库为标准 SQLite，可用任何 sqlite3 工具直接打开

## 解密库中的消息内容编码

微信 4.x 用 WCDB，`message_content` 列有配套的 `WCDB_CT_message_content` 标记列：

| 标记值 | 内容编码 |
|---|---|
| 0 / 缺列 | 明文 text |
| 4 | **zstd 压缩**的 UTF-8，需先解压 |

`extract_me.py` 的 `get_text()` 已内置 zstd / zlib 双尝试兜底。

## 与 QQ NT 的对比

| | 微信 4.x | QQ NT 9.9.35 |
|---|---|---|
| 密钥粒度 | 一账号一把，全库共用 | **每库独立一把** |
| 获取方式 | DLL 注入 hook（登录窗口） | Frida hook + 已知明文搜派生密钥 |
| 库结构 | 标准 SQLCipher，文件头即盐 | 前 1024B 私有头（protobuf key_meta），剥离后才进 SQLCipher |

详见 [known_plaintext_key_recovery.md](known_plaintext_key_recovery.md)。
