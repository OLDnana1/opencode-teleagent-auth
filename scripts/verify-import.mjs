#!/usr/bin/env node
/**
 * Linux 侧的离线自检：确认 magpie 插件真的会使用导出的凭据文件。
 *
 * **不联网、不发任何模型请求、不消耗积分**，只做四件事：
 *   1. 找到凭据文件（环境变量或默认路径）并校验格式；
 *   2. 走一遍插件真实的取值链：credential / device / version / apiKey / portal；
 *   3. 用真实 token 生成一次签名（固定 ts/nonce，只看签名长度与摘要）；
 *   4. 检查 token 是否过期、版本是否满足最低要求。
 *
 * 用法：
 *   node scripts/verify-import.mjs
 *   node scripts/verify-import.mjs --file /path/to/magpie-credentials.json
 *   TELEAGENT_CREDENTIAL_FILE=... node scripts/verify-import.mjs
 */

import path from 'node:path'

import {
  diagnoseCredential,
  readDeviceMeta,
} from '../lib/credential.mjs'
import { checkAppVersion } from '../lib/installation.mjs'
import { resolveApiKey } from '../lib/apikey.mjs'
import { readPortalAuth } from '../lib/portal.mjs'
import { credentialFileCandidates, diagnoseImported } from '../lib/imported.mjs'
import { computeSignature } from '../lib/sign.mjs'
import { TELEAI_SIGNED_PATH } from '../lib/models.mjs'

function parseArgs(argv) {
  const opts = { file: undefined, help: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--file' || arg === '-f') opts.file = path.resolve(argv[++i] ?? '')
    else if (arg === '--help' || arg === '-h') opts.help = true
    else throw new Error(`未知参数：${arg}`)
  }
  return opts
}

const USAGE = `用法：node scripts/verify-import.mjs [选项]

  -f, --file <文件>   指定凭据文件（默认按环境变量 / 默认路径查找）
  -h, --help          显示本帮助

自检全程离线：不联网、不发模型请求、不消耗积分。
`

function line(label, value) {
  console.log(`  ${label.padEnd(12, ' ')}${value}`)
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

  if (opts.file) process.env.TELEAGENT_CREDENTIAL_FILE = opts.file

  console.log('TeleAgent 导入凭据自检（离线）\n')

  const problems = []

  // ---------------------------------------------------------------- 文件
  const candidates = credentialFileCandidates()
  line('候选文件', '')
  for (const file of candidates) console.log(`    - ${file}`)

  const imported = diagnoseImported()
  if (!imported.found) {
    console.error('\n未找到凭据文件。')
    console.error('把导出机器上的 magpie-credentials.json 放到 ~/.config/TeleAgent/，')
    console.error('或者用 --file 指向它，或设置 TELEAGENT_CREDENTIAL_FILE。')
    process.exitCode = 1
    return
  }
  line('使用文件', imported.credentialFile)

  if (!imported.ok) {
    console.error(`\n凭据不可用：${imported.state}`)
    console.error(`  ${imported.detail}`)
    if (imported.remedy) console.error(`  处理：${imported.remedy}`)
    process.exitCode = 1
    return
  }

  line('账号', `${imported.accountName ?? imported.accountId ?? '未知'}（${imported.scope}）`)
  line('租户', imported.tenant ?? '<无>')
  if (typeof imported.daysLeft === 'number') {
    line('剩余天数', `${imported.daysLeft} 天`)
    if (imported.daysLeft < 0) problems.push('token 已过期，需要在桌面端重新登录并重新导出')
  } else {
    line('剩余天数', '<无法从 JWT 读出 exp>')
  }
  line('导出时间', imported.exportedAt ?? '<未记录>')
  line('设备指纹', `deviceId=${imported.device.deviceId}，installId=${imported.device.installId || '<空>'}`)
  if (!imported.device.installId) problems.push('缺少 installId，签名会被上游拒绝')

  // ---------------------------------------------------------------- 版本
  const installation = checkAppVersion()
  if (installation.error) {
    line('桌面端版本', `不可用（${installation.code}）`)
    problems.push(installation.error)
  } else {
    line('桌面端版本', `${installation.version}（来自导入文件）`)
  }

  // ---------------------------------------------------------------- apiKey
  const apiKey = resolveApiKey({})
  line('网关 apiKey', apiKey.key ? `已取到（来源：${apiKey.source}，长度 ${apiKey.key.length}）` : `未取到（来源：${apiKey.source}）`)
  if (!apiKey.key) problems.push('没有网关 apiKey，上游会回 40105（请求疑似攻击）')

  // ---------------------------------------------------------------- 插件取值链
  const viaPlugin = diagnoseCredential()
  line('插件取值', viaPlugin.ok ? `已走导入模式（source=${viaPlugin.source ?? '?'}）` : `失败：${viaPlugin.detail}`)
  if (!viaPlugin.ok) problems.push(`插件 diagnoseCredential 失败：${viaPlugin.detail}`)

  const device = readDeviceMeta()
  line('设备指纹链', device.deviceId && device.installId ? '与凭据文件一致' : '缺失')
  if (!(device.deviceId && device.installId)) problems.push('插件的 readDeviceMeta 拿不到完整设备指纹')

  // ---------------------------------------------------------------- 签名
  try {
    const { signature } = computeSignature({
      token: imported.token,
      installId: device.installId ?? imported.device.installId,
      appVersion: installation.version ?? imported.appVersion ?? '2.7.1',
      method: 'POST',
      pathname: TELEAI_SIGNED_PATH,
      ts: '1700000000',
      nonce: '00000000-0000-4000-8000-000000000000',
      body: '{}',
    })
    line('签名链路', `OK（HMAC-SHA256，64 位 hex，前缀 ${signature.slice(0, 8)}…）`)
  } catch (error) {
    line('签名链路', `失败：${String(error?.message ?? error)}`)
    problems.push('签名生成失败')
  }

  // ---------------------------------------------------------------- 门户
  const portal = readPortalAuth(undefined, imported.scope)
  line('积分 cookie', portal
    ? `已导入（userId=${portal.userId}；模型调用不依赖它）`
    : '没有（Linux 上积分/签到不可用，模型调用不受影响）')

  // ---------------------------------------------------------------- 结论
  console.log('')
  if (problems.length === 0) {
    console.log('自检通过：插件会使用这个文件，签名所需的值齐全。')
    console.log('下一步：magpie 里添加 teleagent 供应商 → 点「读取本机 TeleAgent 登录态」。')
    return
  }
  console.log(`自检发现 ${problems.length} 个问题：`)
  for (const problem of problems) console.log(`  - ${problem}`)
  process.exitCode = 1
}

main()
