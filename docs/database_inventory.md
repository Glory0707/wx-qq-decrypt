# 解密产物清单（微信 4.x / QQ NT 9.9.35）

> 实测环境：Windows 11，微信 4.1.13.12，QQ NT 9.9.35-52892，本机自有账号。
> 路径与标识符均为相对/示例形态；`*_plain.db` 为解密后明文库，
> `integrity_check` 均 ok。

## 微信 4.x（27 库，一钥全解）

`wx4.py decrypt` 产出 `local/decrypted/`，目录结构与客户端原始布局一致：

| 库 | 内容 |
|---|---|
| `message/message_0..4.db` | **聊天消息**（Msg_VXX 表 = md5(对方wxid)，`message_content` 支持 zstd） |
| `message/biz_message_0..2.db` | 公众号/企业号消息 |
| `message/media_0..1.db` | 消息媒体索引 |
| `message/message_fts.db` | 全文搜索索引 |
| `message/message_resource.db` / `weclaw.db` | 消息资源/附属 |
| `contact/contact.db` | **联系人**（username / nick / remark，14301 条量级） |
| `contact/contact_fts.db` | 联系人搜索索引 |
| `session/session.db` | 会话列表（置顶/未读/最后消息摘要） |
| `sns/sns.db` | 朋友圈 |
| `favorite/favorite.db` (+fts) | 收藏 |
| `emoticon/emoticon.db` | 表情 |
| `head_image/head_image.db` | 头像 |
| `general/general.db` | 杂项设置/键值 |
| `hardlink/hardlink.db` | 文件硬链接索引 |
| `bizchat/bizchat.db` | 企业微信互通 |
| `chatbot/chatbot_message.db` | 智能对话 |
| `solitaire/solitaire.db` | 接龙 |
| `third_app_icon/third_app_icon.db` | 第三方应用图标 |

后续产物示例（`extract_me.py`）：本人消息聚合摘要
（高频对话 Top-N / 发文小时分布 / 关键词频次 / 长文本样本），
以及 `extract_meta.py` 的免解密文件名时间线探针。

## QQ NT（12 库，每库独立密钥）

`qq_decrypt_db.py` / `qq_decrypt_all.py` 产出 `*_plain.db`（源文件 → 剥 1024B 私有头 → SQLCipher 解密）：

| 库 | 内容 | 备注 |
|---|---|---|
| `nt_msg_plain.db` | **聊天消息**：`c2c_msg_table` 75,632 条 + `group_msg_table` 1,542,705 条 | 密钥经已知明文法恢复 |
| `group_info_plain.db` | 群资料/群成员 | 独立钥 |
| `profile_info_plain.db` | 个人/好友资料（uid→昵称映射源） | 独立钥 |
| `collection_plain.db` | 收藏 | 独立钥 |
| `files_in_chat_plain.db` | 聊天文件收发记录 | 冷门库：连接按需打开，需先在 UI 触发（如打开"文件"标签页）再扫钥；二进制 passphrase 可直接作字符串使用 |
| `recent_contact` | 会话列表缓存 | 实测为空壳——真实会话数据在 nt_msg，无需单独处理 |
| `emoji_plain.db` | 表情 | |
| `rich_media_plain.db` | 图片/视频等富媒体索引 | |
| `guild_msg_plain.db` | 频道消息 | |
| `file_assistant_plain.db` | 文件助手 | |
| `nt_flash_transfer_plain.db` | 闪传 | |
| `misc_plain.db` / `settings_plain.db` | 杂项/设置 | |

配套文件：

- `local/qq_derived_keys/<db>.key` —— 每库独立派生 AES-256 密钥（hex）
- 消息体导出（`qq_parse_msg.py`）：
  - `QQ_聊天记录_c2c_msg_table.txt` —— 单聊全文（约 7.5 万行）
  - `QQ_聊天记录_group_msg_table.txt` —— 群聊全文（约 154 万行）
  - `--json` 可另存结构化 JSON

## 复验命令

```bash
sqlite3 nt_msg_plain.db "PRAGMA integrity_check;"          # → ok
sqlite3 nt_msg_plain.db "SELECT count(*) FROM group_msg_table;"
python qq_parse_msg.py        # 重建全文导出
python extract_me.py --decrypted local/decrypted
```
