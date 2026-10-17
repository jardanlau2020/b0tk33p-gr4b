# b0tk33p-gr4b — Botkeep 抢机（私人）

来源：`gxjxzgx/openworld-gh`（2026-10-17 版）。**只改了一处**：`EXCLUDE_NODES` 清空
（原版默认黑名单含 `node9`，会把该节点上已有的机器删掉）。

## Secrets
| 名称 | 必填 | 说明 |
|---|---|---|
| `BOTKEEP_EMAIL` | ✅ | Botkeep 账号电邮 |
| `BOTKEEP_PASSWORD` | ✅ | Botkeep 密码 |
| `TG_BOT_TOKEN` | 建议 | TG 通知 |
| `TG_CHAT_ID` | 建议 | TG chat |
| `PROXY_URL` / `NODE_LINK` | 选填 | vless/vmess/trojan/ss/socks5/http 节点；不填直连 |
| `STATE_KEY` | 选填 | 冷却缓存加密密钥 |

## 触发
`workflow_dispatch`，由 Cloudflare Worker 每 5 分钟触发（`b0tk33p-cron`）。
也可手动 Run workflow，勾 `reset` 立即重抢、勾 `reset_count` 重置计数。

## 行为
1. 登录 → 看 dashboard：**已有服务器就退出**（不重复抢）
2. 查 capabilities → 轮询 `creation-availability`（默认 240 秒 × 20 秒间隔）
3. 有名额 → `POST /panel/bots`（`Idempotency-Key` 防重）→ TG 通知
4. 抢到后 **24 小时冷却**；删机器后 10 分钟冷却（冷却状态存 Actions cache）
