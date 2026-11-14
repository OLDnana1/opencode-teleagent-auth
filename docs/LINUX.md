# Linux 适配：跨机凭据导入（路线 B）

上游插件只支持 macOS / Windows，因为它需要读本机 TeleAgent 桌面端的登录态
（macOS 钥匙串 / Windows DPAPI）。Linux 上既没有这两条解密链路，服务器上通常
也跑不起带 keyring 的 Electron 桌面端。

这个分支走**跨机凭据导入**：在一台 Windows / macOS 上登录一次，把签名需要的
值导出成 JSON，Linux 上的 magpie 直接读文件。**不需要在 Linux 上装桌面端。**

## 原理：签名只需要 5 个与机器无关的值

| 值 | 来源 | 说明 |
|---|---|---|
| `token` | `token.json` 解密后的 `<tenant>:<JWT>` | 真正的登录态，约 30 天过期 |
| `deviceId` | `app-auth/device-meta.json` | 设备指纹，参与两步 HMAC |
| `installId` | 同上 | 缺一个上游就拒 |
| `appVersion` | `app.asar` 里的 `package.json` | 放进 `X-App-Version`，并做最低版本校验 |
| `apiKey` | `app.asar` 里 `NewApi` 供应商的 `apiKey` | 网关要求，缺了回 `40105 请求疑似攻击` |

积分/签到额外需要门户 cookie（`operationToken` / `operToken`），导出时可一并带上；
不带也不影响模型调用。

## 步骤

### 1. 在 Windows / macOS 上导出

```bash
# 在插件目录里跑（只用本机文件，不联网、不发模型请求）
node scripts/export-credentials.mjs --out ./magpie-credentials.json
```

找不到安装包时手动指定：

```bash
node scripts/export-credentials.mjs --app-path "D:\TeleAgent" --out ./magpie-credentials.json
node scripts/export-credentials.mjs --app-version 3.0.1 --out ./magpie-credentials.json
```

导出多个账号：

```bash
node scripts/export-credentials.mjs --all --out ./magpie-credentials.json
```

`--no-portal` 跳过积分 cookie，`--no-api-key` 跳过网关 key（不推荐）。

### 2. 传到 Linux

```bash
scp magpie-credentials.json root@<服务器>:/root/magpie/teleagent/magpie-credentials.json
```

### 3. 让插件找到文件

按优先级（命中第一个即进入导入模式）：

1. `TELEAGENT_CREDENTIAL_FILE=/path/to/magpie-credentials.json`
2. `TELEAGENT_CREDENTIALS=/path/to/magpie-credentials.json`
3. `~/.config/TeleAgent/magpie-credentials.json`（推荐）
4. `~/.local/share/TeleAgent/magpie-credentials.json`
5. 插件根目录下的 `credentials.json`（开发用）

Docker 部署时，把文件挂进容器并设置环境变量：

```yaml
services:
  magpie:
    environment:
      - TELEAGENT_CREDENTIAL_FILE=/root/.config/TeleAgent/magpie-credentials.json
    volumes:
      - ./teleagent/magpie-credentials.json:/root/.config/TeleAgent/magpie-credentials.json:ro
```

> `~` 是**容器内**用户的主目录。挂载点要与 `TELEAGENT_CREDENTIAL_FILE` 的路径一致。

### 4. 离线自检

```bash
node scripts/verify-import.mjs
# 或
node scripts/verify-import.mjs --file /path/to/magpie-credentials.json
```

它会检查文件格式、账号、剩余天数、设备指纹、版本、apiKey，并用真实 token
生成一次签名（固定 ts/nonce）。**不联网、不消耗积分。**

输出 `自检通过` 后再进 magpie。

### 5. 安装并登录

```bash
magpie plugin add /path/to/opencode-teleagent-auth   # 本地目录
```

登录界面里选账号 → 点「读取本机 TeleAgent 登录态」。在 Linux 上它读的是导入文件，
不再是钥匙串。

## 环境变量

| 变量 | 作用 |
|---|---|
| `TELEAGENT_CREDENTIAL_FILE` | 凭据文件路径（最高优先级） |
| `TELEAGENT_CREDENTIALS` | 同上，别名 |
| `TELEAGENT_APP_VERSION` | 覆盖导出文件里的版本号 |
| `TELEAGENT_API_KEY` | 覆盖导出文件里的网关 apiKey |
| `TELEAGENT_DATA` / `TELEAGENT_CONFIG` | 改默认的数据/配置目录（与上游插件一致） |

## 文件格式

```json
{
  "format": "teleagent-credentials",
  "version": 1,
  "exportedAt": "2026-11-14T05:23:08.637Z",
  "source": { "platform": "win32", "appVersion": "3.0.1" },
  "accounts": [
    {
      "scope": "v1_public_1000000000000000000",
      "current": true,
      "token": "<tenant>:<JWT>",
      "tenant": "demo-tenant",
      "accountId": "1000000000000000000",
      "accountName": "user_demo",
      "expiresAt": 1760000000000,
      "device": { "deviceId": "...", "installId": "..." },
      "appVersion": "3.0.1",
      "apiKey": "sk-…（桌面端内置常量）",
      "portal": { "userId": "...", "operationToken": "...", "operToken": "..." }
    }
  ]
}
```

- `accounts[0]` 应是最新的当前账号；`selectAccount` 优先取 `current: true`。
- `format` / `version` 不对会拒绝加载（不会静默降级）。
- 明文文件：权限 600，不要提交 git、不要放网盘。

## 积分与签到

导出时默认带上门户 cookie（`--no-portal` 可关闭），Linux 侧功能与 Windows/macOS 一致：

- 用量页 / `magpie quota`：积分余额、最早过期时间、套餐名；
- 每日签到：设置 → 用量 → 插件 tab → TeleAgent →「每日签到」。
  签到是唯一会改服务器状态的积分操作：先查今天领没领，已领直接返回 `done`；
- agent 工具 `teleagent_points`：只读，不花积分、不触发领取。

cookie 与 JWT 是两套凭据：cookie 过期只影响积分，模型调用不受影响。
桌面端把 cookie 写在父域 `.teleai.com.cn`（不是 `agent.teleai.com.cn`），
导出器已经按父域读取；如果导出摘要显示「无积分cookie」，让桌面端打开一次积分页再导出。

## 行为变化（与上游插件的差异）

| 场景 | 上游插件 | 本分支 |
|---|---|---|
| 有 `magpie-credentials.json` | 忽略 | **优先使用它**，完全不碰钥匙串/DPAPI |
| 没有该文件 | 本机链路 | 完全保持原行为（Windows/macOS 不受影响） |
| Linux 且没有文件 | `not_macos` | 仍然 `not_macos` |
| 版本探测 | 读 `app.asar`，读不到就拦截 | 导入模式用文件里的版本，不探测安装包 |
| 积分 cookie | 读本机 SQLite 并解密 | 导入模式下只用文件里的 `portal`，不读 SQLite |
| `package.json` 的 `os` | `darwin` / `win32` | 增加 `linux` |

## 限制与风险

1. **token 约 30 天过期，没有 refresh token**。过期后回桌面端重新登录，重新导出。
   `verify-import` 会显示剩余天数。
2. **不要两台机器同时用同一账号**。插件的并发/限速/熔断是按账号本地计数的，
   两处并用等于请求量翻倍；上游对自动化流量敏感（作者记录过两次封号复盘）。
3. **积分/签到可能不可用**。导出时桌面端没打开过积分页，或导出机器缺 sqlite，
   `portal` 就是空的。模型调用不受影响。
4. **设备指纹跨机复制是预期行为**。上游只校验签名里的值是否自洽，不校验机器。
   这也意味着不要把文件给别人。
5. **导出文件与桌面端账号是绑定的**。桌面端换号后要重新导出，并更新文件。

## 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `credential_file_invalid` | JSON 坏 / format 不对 | 重新导出 |
| `credential_file_version_unsupported` | 文件版本高于插件 | 更新插件 |
| `device_missing` | 文件缺 `deviceId` / `installId` | 重新导出（不要手改） |
| `expired` | JWT 过期 | 桌面端重新登录 + 重新导出 |
| `not_signed_in` | 指定的 scope 不在文件里 | 用 `--all` 重新导出 |
| `40105 请求疑似攻击` | 网关 apiKey 缺失 | 检查导出摘要里的「含网关key」；或设 `TELEAGENT_API_KEY` |
| 积分显示「缺少 cookie」 | 导出时没读到门户 cookie（桌面端没打开过积分页，或 cookie 被清） | 桌面端切到该账号并打开积分页，重新导出 |
