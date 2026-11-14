#!/usr/bin/env node
/**
 * 在 Windows / macOS 上导出 TeleAgent 登录态，供 Linux 上的 magpie 插件导入。
 *
 * 它做三件事，全部只读本机文件、不联网、不发模型请求：
 *   1. 解密当前（或指定）账号的 JWT —— 走原插件的钥匙串 / DPAPI 链路；
 *   2. 带上设备指纹（deviceId / installId）、桌面端版本、网关 apiKey；
 *   3. 可选：解密门户 cookie，让 Linux 上也能看积分、每日签到。
 *
 * ## 用法
 *
 *   node scripts/export-credentials.mjs                       # 导出当前账号
 *   node scripts/export-credentials.mjs --all                 # 导出本机所有可解账号
 *   node scripts/export-credentials.mjs --scope v1_public_…   # 指定账号
 *   node scripts/export-credentials.mjs --out D:\tmp\cred.json
 *   node scripts/export-credentials.mjs --app-path "D:\星辰\TeleAgent"
 *   node scripts/export-credentials.mjs --app-version 3.0.1   # 读不到 app.asar 时手动指定
 *   node scripts/export-credentials.mjs --no-portal           # 不导积分 cookie
 *
 * ## 安全
 *
 * 产物是**明文**（JWT + 网关 apiKey + 可选 cookie）。脚本会把文件权限设为 600，
 * 打印摘要时**不输出任何 secret**。不要提交到 git、不要放进网盘/公开目录。
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  diagnoseCredential,
  listCredentialScopes,
  readDeviceMeta,
} from '../lib/credential.mjs'
import { checkAppVersion, checkVersion } from '../lib/installation.mjs'
import { resolveApiKey } from '../lib/apikey.mjs'
import { readPortalAuth } from '../lib/portal.mjs'
import { buildExportedAccount, buildExportDocument } from '../lib/imported.mjs'

const USAGE = `用法：node scripts/export-credentials.mjs [选项]

  -o, --out <文件>        输出路径（默认 ./magpie-credentials.json）
      --scope <scope>     只导出指定账号（目录名 v1_public_<userId>）
      --all               导出本机所有可解账号
      --app-path <路径>   TeleAgent 安装目录 / exe / resources / app.asar
      --app-version <版本> 读不到安装包时手动指定版本（如 3.0.1）
      --no-portal         不导出积分 cookie（模型调用不受影响）
      --no-api-key        不导出网关 apiKey（不推荐：会被上游回 40105）
  -h, --help              显示本帮助
`

function parseArgs(argv) {
  const opts = {
    out: path.resolve('magpie-credentials.json'),
    all: false,
    portal: true,
    apiKey: true,
    scope: undefined,
    appPath: undefined,
    appVersion: undefined,
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--out' || arg === '-o') opts.out = path.resolve(argv[++i] ?? '')
    else if (arg === '--scope') opts.scope = argv[++i]
    else if (arg === '--all') opts.all = true
    else if (arg === '--app-path') opts.appPath = argv[++i]
    else if (arg === '--app-version') opts.appVersion = argv[++i]
    else if (arg === '--no-portal') opts.portal = false
    else if (arg === '--no-api-key') opts.apiKey = false
    else if (arg === '--help' || arg === '-h') opts.help = true
    else throw new Error(`未知参数：${arg}`)
  }
  return opts
}

function fail(message) {
  console.error(`\n导出失败：${message}\n`)
  process.exitCode = 1
}

function main() {
  let opts
  try {
    opts = parseArgs(process.argv.slice(2))
  } catch (error) {
    console.error(String(error?.message ?? error))
    console.error(USAGE)
    process.exitCode = 2
    return
  }
  if (opts.help) {
    console.log(USAGE)
    return
  }

  console.log('TeleAgent 登录态导出（只读本机，不联网）\n')

  // ---------------------------------------------------------------- 版本
  const versionCheck = checkAppVersion({ imported: false, appPath: opts.appPath })
  let appVersion
  if (versionCheck.error) {
    if (opts.appVersion) {
      const forced = checkVersion(opts.appVersion)
      if (forced.error) {
        fail(forced.error)
        return
      }
      appVersion = forced.version
      console.log(`! 安装包版本读不到，使用 --app-version 指定的 ${appVersion}`)
    } else {
      fail(`${versionCheck.error}\n提示：用 --app-path 指向安装目录，或用 --app-version 手动指定版本`)
      return
    }
  } else {
    appVersion = versionCheck.version
    console.log(`桌面端版本：${appVersion}`)
  }

  // ---------------------------------------------------------------- 账号
  const scopes = listCredentialScopes(undefined, { imported: false })
  if (scopes.length === 0) {
    fail('本机没有找到任何已登录账号（缺少 app-auth/token.json）。请先在 TeleAgent 桌面端登录。')
    return
  }

  // 当前账号：能解出来的那个（current-owner 指向的目录）
  const current = diagnoseCredential(undefined, { imported: false })
  const currentScope = current.ok ? current.scope : scopes[0]

  const targets = opts.scope
    ? [opts.scope]
    : (opts.all ? scopes : [currentScope])

  // ---------------------------------------------------------------- 网关 key
  const apiKey = opts.apiKey
    ? resolveApiKey({ imported: false, appPath: opts.appPath })
    : { key: '', source: '已禁用' }

  // ---------------------------------------------------------------- 逐账号
  const accounts = []
  const skipped = []
  for (const scope of targets) {
    const diagnosis = diagnoseCredential(undefined, { scope, imported: false })
    if (!diagnosis.ok) {
      skipped.push({ scope, reason: `${diagnosis.detail}${diagnosis.remedy ? `（${diagnosis.remedy}）` : ''}` })
      continue
    }

    const device = readDeviceMeta(undefined, { scope, imported: false })
    let portal = null
    if (opts.portal) {
      try {
        portal = readPortalAuth(undefined, diagnosis.scope, { imported: false })
      } catch {
        portal = null
      }
    }

    accounts.push(buildExportedAccount({
      scope: diagnosis.scope,
      current: diagnosis.scope === currentScope,
      diagnosis,
      device,
      appVersion,
      apiKey: opts.apiKey ? apiKey.key : null,
      portal: portal
        ? { userId: portal.userId, operationToken: portal.operationToken, operToken: portal.operToken }
        : null,
    }))
  }

  if (accounts.length === 0) {
    fail(`没有账号可导出：\n${skipped.map((s) => `  - ${s.scope}：${s.reason}`).join('\n')}`)
    return
  }

  // 当前账号排第一个（导入端默认取 accounts[0]）
  accounts.sort((a, b) => (b.current ? 1 : 0) - (a.current ? 1 : 0))

  // ---------------------------------------------------------------- 写文件
  const doc = buildExportDocument({
    accounts,
    sourcePlatform: process.platform,
    sourceHome: os.homedir(),
    appVersion,
  })
  try {
    fs.mkdirSync(path.dirname(opts.out), { recursive: true })
    fs.writeFileSync(opts.out, `${JSON.stringify(doc, null, 2)}\n`, { mode: 0o600 })
    try { fs.chmodSync(opts.out, 0o600) } catch { /* Windows 上 chmod 基本是空操作 */ }
  } catch (error) {
    fail(`写文件失败：${String(error?.message ?? error)}`)
    return
  }

  // ---------------------------------------------------------------- 摘要
  console.log(`\n已导出 ${accounts.length} 个账号 → ${opts.out}`)
  for (const account of accounts) {
    const days = typeof account.expiresAt === 'number'
      ? `，剩余 ${Math.floor((account.expiresAt - Date.now()) / 86_400_000)} 天`
      : ''
    const marks = [
      account.current ? '当前' : '历史',
      account.portal ? '含积分cookie' : '无积分cookie',
      account.apiKey ? '含网关key' : '无网关key',
    ].join(' / ')
    console.log(`  - ${account.accountName ?? account.accountId ?? account.scope}（${account.scope}）${days} · ${marks}`)
  }
  console.log(`  设备指纹：deviceId=${accounts[0].device.deviceId || '<空>'}，installId=${accounts[0].device.installId ? '<已包含>' : '<空>'}`)
  console.log(`  网关 apiKey：${apiKey.key ? `已包含（来源：${apiKey.source}）` : `未包含（来源：${apiKey.source}）`}`)
  if (!opts.portal) console.log('  积分 cookie：已按 --no-portal 跳过')
  else if (!accounts.some((a) => a.portal)) {
    console.log('  积分 cookie：未读到（桌面端没打开过积分页，或本机缺 node:sqlite/sqlite3）；不影响模型调用')
  }
  if (skipped.length > 0) {
    console.log(`\n跳过 ${skipped.length} 个账号：`)
    for (const s of skipped) console.log(`  - ${s.scope}：${s.reason}`)
  }

  console.log(`
安全提醒：该文件是明文凭据（JWT + 网关 key${opts.portal ? ' + 积分 cookie' : ''}）。
  - 权限已设为 600，不要提交到 git、不要放网盘或公开目录；
  - 拷到 Linux 后放到 ~/.config/TeleAgent/magpie-credentials.json
    或设置 TELEAGENT_CREDENTIAL_FILE=/path/to/magpie-credentials.json
  - JWT 约 30 天过期（没有 refresh token）：过期后回桌面端重新登录，重新导出。`)
}

main()
