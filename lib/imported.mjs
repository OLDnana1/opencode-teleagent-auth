/**
 * 跨机凭据导入（Linux 适配的路线 B）。
 *
 * 把一台 **Windows / macOS** 机器上 TeleAgent 桌面端的登录态导出成 JSON，
 * 在 Linux（或任何没有桌面端的环境）上由插件直接读取，完全跳过：
 *   - Electron safeStorage 解密（macOS 钥匙串 / Windows DPAPI / Linux libsecret）
 *   - 安装包探测与 app.asar 版本读取
 *   - Chromium cookie 库解密
 *
 * ## 为什么只需要这 5 个值
 *
 * 上游签名只依赖 `token`、`installId`、`deviceId`、`appVersion`、网关 `apiKey`
 * （见 `lib/sign.mjs`），它们都与机器无关，唯一的要求是「同一次登录」。
 * 积分/签到额外需要门户 cookie，导出时一并带上即可。
 *
 * ## 文件位置（按优先级）
 *
 *   1. `TELEAGENT_CREDENTIAL_FILE` —— 明确指定路径
 *   2. `TELEAGENT_CREDENTIALS`    —— 同义变量
 *   3. `$TELEAGENT_CONFIG/TeleAgent/magpie-credentials.json`（默认 `~/.config/TeleAgent/`）
 *   4. `$TELEAGENT_DATA/TeleAgent/magpie-credentials.json`（默认 `~/.local/share/TeleAgent/`）
 *   5. 插件根目录下的 `credentials.json`（开发/测试用）
 *
 * 命中任意一个文件就进入「导入模式」；一个都没有时完全保持原插件的本机链路。
 *
 * ## 安全
 *
 * 文件是**明文**（JWT + 网关 apiKey + 可选的门户 cookie），只应放在可信机器上，
 * 权限 600。本模块的任何返回值与错误信息都不包含 secret，日志里也不打印。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** 导出文件的格式标记与版本 */
export const IMPORT_FORMAT = 'teleagent-credentials'
export const IMPORT_VERSION = 1
export const DEFAULT_FILE_NAME = 'magpie-credentials.json'

/** 导入模式下的状态码（字符串与 `CredentialState` 对齐，另加文件级错误） */
export const ImportedState = {
  OK: 'ok',
  NOT_SIGNED_IN: 'not_signed_in',
  TOKEN_MALFORMED: 'token_malformed',
  EXPIRED: 'expired',
  DEVICE_MISSING: 'device_missing',
  FILE_INVALID: 'credential_file_invalid',
  FILE_VERSION_UNSUPPORTED: 'credential_file_version_unsupported',
}

/** 每种状态对应的用户动作 */
export const IMPORT_REMEDIES = {
  [ImportedState.FILE_INVALID]: '重新运行 scripts/export-credentials.mjs 生成凭据文件',
  [ImportedState.FILE_VERSION_UNSUPPORTED]: '凭据文件来自更新的插件：更新本插件，或重新导出',
  [ImportedState.NOT_SIGNED_IN]: '导出机器上没有这个账号：登录后重新导出',
  [ImportedState.TOKEN_MALFORMED]: '凭据文件里的 token 不是合法 JWT：重新导出',
  [ImportedState.EXPIRED]: '登录已过期：在 Windows/macOS 的 TeleAgent 桌面端重新登录，再重新导出',
  [ImportedState.DEVICE_MISSING]: '凭据文件缺少设备指纹：重新运行导出脚本（deviceId/installId 必须成对存在）',
}

// ------------------------------------------------------------------ 路径

function configRoot(home, env) {
  return env?.TELEAGENT_CONFIG || env?.TELEAGENT_CONFIG_DIR || path.join(home, '.config', 'TeleAgent')
}

function dataRoot(home, env) {
  return env?.TELEAGENT_DATA || path.join(home, '.local', 'share', 'TeleAgent')
}

/**
 * 凭据文件的候选路径（按优先级，已去重）。
 *
 * 与 `credential.mjs` 的 `appPaths()` 保持同一套环境变量，但这里不 import 它，
 * 避免两个模块互相依赖。
 */
export function credentialFileCandidates({ env = process.env, home = os.homedir(), pluginRoot } = {}) {
  const out = []
  for (const key of ['TELEAGENT_CREDENTIAL_FILE', 'TELEAGENT_CREDENTIALS']) {
    const value = typeof env?.[key] === 'string' ? env[key].trim() : ''
    if (value) out.push(value)
  }
  out.push(path.join(configRoot(home, env), DEFAULT_FILE_NAME))
  out.push(path.join(dataRoot(home, env), DEFAULT_FILE_NAME))
  if (typeof pluginRoot === 'string' && pluginRoot) out.push(path.join(pluginRoot, 'credentials.json'))
  return [...new Set(out)]
}

/** 找到第一个真实存在的凭据文件；都没有返回 null */
export function findCredentialFile(options = {}) {
  for (const file of credentialFileCandidates(options)) {
    try {
      if (fs.statSync(file).isFile()) return file
    } catch { /* 继续找下一个 */ }
  }
  return null
}

/** 当前是否处于导入模式（有文件即导入，没有则完全走本机链路） */
export function isImportedMode(options = {}) {
  return findCredentialFile(options) !== null
}

// ------------------------------------------------------------------ 解析

function isAccount(value) {
  return value && typeof value === 'object'
    && typeof value.scope === 'string' && value.scope.length > 0
    && typeof value.token === 'string' && value.token.length > 0
}

/** 解析并校验导出文件；永不抛错 */
export function parseCredentialFile(file) {
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (error) {
    return { ok: false, state: ImportedState.FILE_INVALID, error: `无法读取凭据文件：${String(error?.message ?? error)}` }
  }

  let data
  try {
    data = JSON.parse(text)
  } catch {
    return { ok: false, state: ImportedState.FILE_INVALID, error: '凭据文件不是合法 JSON' }
  }

  if (!data || typeof data !== 'object' || data.format !== IMPORT_FORMAT) {
    return { ok: false, state: ImportedState.FILE_INVALID, error: `凭据文件格式不是 ${IMPORT_FORMAT}` }
  }

  const version = Number(data.version)
  if (!Number.isInteger(version) || version < 1 || version > IMPORT_VERSION) {
    return {
      ok: false,
      state: ImportedState.FILE_VERSION_UNSUPPORTED,
      error: `凭据文件版本 ${data?.version ?? '未知'} 不在支持范围内（1..${IMPORT_VERSION}）`,
    }
  }

  const accounts = Array.isArray(data.accounts) ? data.accounts.filter(isAccount) : []
  if (accounts.length === 0) {
    return { ok: false, state: ImportedState.FILE_INVALID, error: '凭据文件里没有可用账号（accounts 为空或缺少 scope/token）' }
  }
  return { ok: true, data, accounts }
}

/**
 * 从 token 里取 JWT 声明（不校验签名，与 `credential.mjs` 的 `parseClaims` 同规则）。
 * @returns {{claims: object|null, error?: string}}
 */
export function decodeClaims(token) {
  const jwt = token.includes(':') ? token.slice(token.indexOf(':') + 1) : token
  const payload = jwt.split('.')[1]
  if (!payload) return { claims: null, error: 'token 不是合法的 JWT（缺少 payload 段）' }
  try {
    return { claims: JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) }
  } catch {
    return { claims: null, error: 'token 的声明不是合法 JSON' }
  }
}

/**
 * 选一个账号：指定的 scope 优先；否则 `current === true`；再否则第一个。
 * @returns {object|null}
 */
export function selectAccount(accounts, scope) {
  if (!Array.isArray(accounts) || accounts.length === 0) return null
  if (typeof scope === 'string' && scope.length > 0) {
    return accounts.find((a) => a.scope === scope) ?? null
  }
  return accounts.find((a) => a?.current === true) ?? accounts[0]
}

// ------------------------------------------------------------------ 诊断

/**
 * 导入模式下的完整诊断，返回形状与 `diagnoseCredential` 一致。
 *
 * `found: false` 表示「没有凭据文件」——调用方应回退到本机链路；
 * `found: true` 时无论 `ok` 是什么，都不应该再碰本机钥匙串。
 *
 * @param {{ home?: string, env?: object, pluginRoot?: string, scope?: string }} [options]
 */
export function diagnoseImported({ home = os.homedir(), env = process.env, pluginRoot, scope } = {}) {
  const file = findCredentialFile({ env, home, pluginRoot })
  if (!file) return { found: false }

  const parsed = parseCredentialFile(file)
  if (!parsed.ok) {
    return {
      found: true,
      ok: false,
      state: parsed.state,
      detail: parsed.error,
      remedy: IMPORT_REMEDIES[parsed.state],
      credentialFile: file,
      source: 'imported',
    }
  }

  const account = selectAccount(parsed.accounts, scope)
  if (!account) {
    return {
      found: true,
      ok: false,
      state: ImportedState.NOT_SIGNED_IN,
      detail: `凭据文件里没有账号 ${scope}`,
      remedy: IMPORT_REMEDIES[ImportedState.NOT_SIGNED_IN],
      credentialFile: file,
      source: 'imported',
    }
  }

  const { claims, error } = decodeClaims(account.token)
  if (!claims) {
    return {
      found: true,
      ok: false,
      state: ImportedState.TOKEN_MALFORMED,
      detail: error,
      remedy: IMPORT_REMEDIES[ImportedState.TOKEN_MALFORMED],
      credentialFile: file,
      scope: account.scope,
      source: 'imported',
    }
  }

  const device = {
    deviceId: typeof account?.device?.deviceId === 'string' ? account.device.deviceId : '',
    installId: typeof account?.device?.installId === 'string' ? account.device.installId : '',
  }
  if (!device.deviceId || !device.installId) {
    return {
      found: true,
      ok: false,
      state: ImportedState.DEVICE_MISSING,
      detail: '凭据文件缺少 deviceId / installId（设备指纹参与签名，缺一上游会拒）',
      remedy: IMPORT_REMEDIES[ImportedState.DEVICE_MISSING],
      credentialFile: file,
      scope: account.scope,
      source: 'imported',
    }
  }

  const appVersion = resolveImportedAppVersion({ account, env })
  const apiKey = typeof account.apiKey === 'string' ? account.apiKey : ''
  const portal = normalizePortal(account.portal)

  const expiresAt = typeof claims.exp === 'number'
    ? claims.exp * 1000
    : (Number(account.expiresAt) > 0 ? Number(account.expiresAt) : undefined)
  const daysLeft = expiresAt === undefined ? undefined : Math.floor((expiresAt - Date.now()) / 86_400_000)

  const base = {
    found: true,
    ok: true,
    token: account.token,
    scope: account.scope,
    claims,
    accountName: account.accountName ?? claims.accountName,
    accountId: account.accountId ?? claims.accountId,
    tenant: account.tenant ?? claims.tenant,
    expiresAt,
    daysLeft,
    device,
    appVersion,
    apiKey,
    portal,
    credentialFile: file,
    exportedAt: parsed.data?.exportedAt,
    source: 'imported',
  }

  if (expiresAt !== undefined && expiresAt < Date.now()) {
    return {
      ...base,
      ok: false,
      state: ImportedState.EXPIRED,
      remedy: IMPORT_REMEDIES[ImportedState.EXPIRED],
      detail: `导入的登录已于 ${new Date(expiresAt).toISOString().slice(0, 10)} 过期`,
    }
  }

  const who = base.accountName ?? base.accountId ?? account.scope
  return {
    ...base,
    state: ImportedState.OK,
    detail: daysLeft === undefined
      ? `已导入：${who}（来源 ${file}）`
      : `已导入：${who}，剩余 ${daysLeft} 天（来源 ${file}）`,
  }
}

// ------------------------------------------------------------------ 取用

/** 导入的版本号：环境变量优先，其次账号/文件里的 appVersion */
export function resolveImportedAppVersion({ account, data, env = process.env } = {}) {
  const fromEnv = typeof env?.TELEAGENT_APP_VERSION === 'string' ? env.TELEAGENT_APP_VERSION.trim() : ''
  if (fromEnv) return fromEnv
  const fromAccount = typeof account?.appVersion === 'string' ? account.appVersion.trim() : ''
  if (fromAccount) return fromAccount
  const fromFile = typeof data?.appVersion === 'string' ? data.appVersion.trim() : ''
  return fromFile || undefined
}

function normalizePortal(value) {
  if (!value || typeof value !== 'object') return null
  const operationToken = typeof value.operationToken === 'string' ? value.operationToken : ''
  if (!operationToken) return null
  const userId = typeof value.userId === 'string' ? value.userId : ''
  const operToken = typeof value.operToken === 'string' ? value.operToken : ''
  return { operationToken, operToken, userId: userId || undefined }
}

/** 设备指纹；没有文件或字段不全时返回 `{}`（与 readDeviceMeta 的失败形状一致） */
export function readImportedDeviceMeta({ home = os.homedir(), env = process.env, pluginRoot, scope } = {}) {
  const imported = diagnoseImported({ home, env, pluginRoot, scope })
  if (!imported.found) return {}
  return imported.device ?? {}
}

/** 导入文件里的网关 apiKey（不含环境变量/显式配置，那条链在 resolveApiKey 里排更前） */
export function importedApiKey({ home = os.homedir(), env = process.env, pluginRoot, scope } = {}) {
  const imported = diagnoseImported({ home, env, pluginRoot, scope })
  if (!imported.found || !imported.apiKey) return null
  return { key: imported.apiKey, source: '导入文件' }
}

/** 导入文件里的版本号；没有则 undefined */
export function importedAppVersion({ home = os.homedir(), env = process.env, pluginRoot, scope } = {}) {
  const file = findCredentialFile({ env, home, pluginRoot })
  if (!file) return undefined
  const parsed = parseCredentialFile(file)
  if (!parsed.ok) return undefined
  const account = selectAccount(parsed.accounts, scope)
  return resolveImportedAppVersion({ account, data: parsed.data, env })
}

/** 导入文件里的账号列表（登录界面的选项来源） */
export function importedScopes({ home = os.homedir(), env = process.env, pluginRoot } = {}) {
  const file = findCredentialFile({ env, home, pluginRoot })
  if (!file) return []
  const parsed = parseCredentialFile(file)
  if (!parsed.ok) return []
  return parsed.accounts.map((account) => {
    const { claims } = decodeClaims(account.token)
    const expiresAt = typeof claims?.exp === 'number' ? claims.exp * 1000 : undefined
    return {
      scope: account.scope,
      accountName: account.accountName ?? claims?.accountName ?? null,
      accountId: account.accountId ?? claims?.accountId ?? null,
      expiresAt,
      daysLeft: expiresAt === undefined ? undefined : Math.floor((expiresAt - Date.now()) / 86_400_000),
      current: account.current === true,
    }
  })
}

/** 门户凭据（积分/签到）；返回形状与 `readPortalAuth` 一致，没有则 null */
export function readImportedPortalAuth({ home = os.homedir(), env = process.env, pluginRoot, scope } = {}) {
  const imported = diagnoseImported({ home, env, pluginRoot, scope })
  if (!imported.found || !imported.portal) return null
  const userId = imported.portal.userId ?? String(imported.accountId ?? '')
  if (!userId) return null
  return {
    userId,
    operationToken: imported.portal.operationToken,
    operToken: imported.portal.operToken ?? '',
    source: `imported:${imported.credentialFile}`,
  }
}

// ------------------------------------------------------------------ 导出（给脚本复用）

/**
 * 把一次「本机读到的账号」组装成导出文件里的 account 对象。
 * 只做形状转换，不做解密；解密仍在调用方（导出脚本）里走原插件链路。
 */
export function buildExportedAccount({
  scope,
  diagnosis,
  device,
  appVersion,
  apiKey,
  portal,
  current = false,
}) {
  return {
    scope,
    current,
    token: diagnosis.token,
    tenant: diagnosis.tenant ?? null,
    accountId: diagnosis.accountId ?? null,
    accountName: diagnosis.accountName ?? null,
    expiresAt: diagnosis.expiresAt ?? null,
    device: {
      deviceId: device?.deviceId ?? '',
      installId: device?.installId ?? '',
    },
    appVersion: appVersion ?? null,
    apiKey: apiKey ?? null,
    portal: portal
      ? {
        userId: portal.userId ?? null,
        operationToken: portal.operationToken,
        operToken: portal.operToken ?? null,
      }
      : null,
  }
}

/** 组装最终导出文件；`accounts[0]` 必须是当前账号 */
export function buildExportDocument({ accounts, sourcePlatform, sourceHome, appVersion }) {
  return {
    format: IMPORT_FORMAT,
    version: IMPORT_VERSION,
    exportedAt: new Date().toISOString(),
    source: {
      platform: sourcePlatform ?? process.platform,
      home: sourceHome ?? os.homedir(),
      appVersion: appVersion ?? null,
    },
    accounts,
  }
}
