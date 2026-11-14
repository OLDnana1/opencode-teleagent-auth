/**
 * 导入模式单测（node:test，不依赖 bun）。
 *
 *   node --test test/imported.test.mjs
 *
 * 全部用临时目录 + 假 JWT，不碰真实钥匙串 / DPAPI / 网络。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import {
  credentialFileCandidates,
  diagnoseImported,
  importedScopes,
  parseCredentialFile,
  readImportedPortalAuth,
  resolveImportedAppVersion,
  selectAccount,
  IMPORT_FORMAT,
  ImportedState,
} from '../lib/imported.mjs'
import { diagnoseCredential, readDeviceMeta } from '../lib/credential.mjs'

// ------------------------------------------------------------------ 工具

function makeHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'teleagent-import-'))
}

function writeDoc(home, document, name = 'magpie-credentials.json') {
  const dir = path.join(home, '.config', 'TeleAgent')
  fs.mkdirSync(dir, { recursive: true })
  const file = path.join(dir, name)
  fs.writeFileSync(file, JSON.stringify(document))
  return file
}

function makeJwt(claims) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  return `eyJhbGciOiJub25lIn0.${encode(claims)}.sig`
}

function makeAccount(overrides = {}) {
  const exp = Math.floor(Date.now() / 1000) + 6 * 86_400
  return {
    scope: 'v1_public_1',
    token: `t1:${makeJwt({ accountId: '1', accountName: 'user_test', tenant: 't1', exp })}`,
    device: { deviceId: 'device-abc', installId: 'install-xyz' },
    appVersion: '3.0.1',
    apiKey: 'sk-test-123',
    portal: null,
    ...overrides,
  }
}

function makeDoc(accounts, extra = {}) {
  return {
    format: IMPORT_FORMAT,
    version: 1,
    exportedAt: '2026-11-14T00:00:00.000Z',
    accounts,
    ...extra,
  }
}

// ------------------------------------------------------------------ 路径

test('候选路径：显式变量排最前，其次 config / data / 插件根', () => {
  const home = makeHome()
  const pluginRoot = path.join(home, 'plugin')
  const files = credentialFileCandidates({
    home,
    env: {
      TELEAGENT_CREDENTIAL_FILE: path.join(home, 'explicit.json'),
      TELEAGENT_CREDENTIALS: path.join(home, 'alias.json'),
    },
    pluginRoot,
  })
  assert.equal(files[0], path.join(home, 'explicit.json'))
  assert.equal(files[1], path.join(home, 'alias.json'))
  assert.ok(files.includes(path.join(home, '.config', 'TeleAgent', 'magpie-credentials.json')))
  assert.ok(files.includes(path.join(home, '.local', 'share', 'TeleAgent', 'magpie-credentials.json')))
  assert.ok(files.includes(path.join(pluginRoot, 'credentials.json')))
})

test('没有文件时 found=false（调用方回退本机链路）', () => {
  const home = makeHome()
  const result = diagnoseImported({ home, env: {}, pluginRoot: path.join(home, 'plugin') })
  assert.equal(result.found, false)
})

// ------------------------------------------------------------------ 解析

test('解析合法文件', () => {
  const home = makeHome()
  const file = writeDoc(home, makeDoc([makeAccount()]))
  const parsed = parseCredentialFile(file)
  assert.equal(parsed.ok, true)
  assert.equal(parsed.accounts.length, 1)
})

test('format 不对 → credential_file_invalid', () => {
  const home = makeHome()
  const file = writeDoc(home, { format: 'nope', version: 1, accounts: [makeAccount()] })
  const parsed = parseCredentialFile(file)
  assert.equal(parsed.ok, false)
  assert.equal(parsed.state, ImportedState.FILE_INVALID)
})

test('版本过高 → credential_file_version_unsupported', () => {
  const home = makeHome()
  const file = writeDoc(home, { ...makeDoc([makeAccount()]), version: 99 })
  const parsed = parseCredentialFile(file)
  assert.equal(parsed.ok, false)
  assert.equal(parsed.state, ImportedState.FILE_VERSION_UNSUPPORTED)
})

test('accounts 为空 / 缺 scope / 缺 token → invalid', () => {
  const home = makeHome()
  const file = writeDoc(home, makeDoc([{ scope: 'x' }, { token: 'y' }, { scope: 'z', token: 'ok' }]))
  const parsed = parseCredentialFile(file)
  assert.equal(parsed.ok, true)
  assert.equal(parsed.accounts.length, 1)
  assert.equal(parsed.accounts[0].scope, 'z')

  const empty = writeDoc(home, makeDoc([]), 'empty.json')
  assert.equal(parseCredentialFile(empty).state, ImportedState.FILE_INVALID)
})

test('JSON 坏掉 → invalid', () => {
  const home = makeHome()
  const dir = path.join(home, '.config', 'TeleAgent')
  fs.mkdirSync(dir, { recursive: true })
  const file = path.join(dir, 'bad.json')
  fs.writeFileSync(file, '{ not json')
  assert.equal(parseCredentialFile(file).state, ImportedState.FILE_INVALID)
})

// ------------------------------------------------------------------ 选择

test('selectAccount：scope 优先，其次 current，最后第一个', () => {
  const a = makeAccount({ scope: 'a' })
  const b = makeAccount({ scope: 'b', current: true })
  const c = makeAccount({ scope: 'c' })
  assert.equal(selectAccount([a, b, c], 'c').scope, 'c')
  assert.equal(selectAccount([a, b, c], undefined).scope, 'b')
  assert.equal(selectAccount([a, c], undefined).scope, 'a')
  assert.equal(selectAccount([a], 'missing'), null)
})

// ------------------------------------------------------------------ 诊断

test('诊断正常：账号 / 剩余天数 / 设备 / apiKey / 来源', () => {
  const home = makeHome()
  const file = writeDoc(home, makeDoc([makeAccount()]))
  const d = diagnoseImported({ home, env: {}, pluginRoot: path.join(home, 'plugin') })
  assert.equal(d.found, true)
  assert.equal(d.ok, true)
  assert.equal(d.state, ImportedState.OK)
  assert.equal(d.scope, 'v1_public_1')
  assert.equal(d.accountName, 'user_test')
  assert.equal(d.device.deviceId, 'device-abc')
  assert.equal(d.device.installId, 'install-xyz')
  assert.equal(d.appVersion, '3.0.1')
  assert.equal(d.apiKey, 'sk-test-123')
  assert.equal(d.credentialFile, file)
  assert.equal(d.source, 'imported')
  assert.ok(d.daysLeft >= 5 && d.daysLeft <= 6)
})

test('过期 → expired（但仍带回 token 与设备，便于上层展示）', () => {
  const home = makeHome()
  const expired = makeAccount({
    token: `t1:${makeJwt({ accountId: '1', exp: Math.floor(Date.now() / 1000) - 60 })}`,
  })
  writeDoc(home, makeDoc([expired]))
  const d = diagnoseImported({ home, env: {}, pluginRoot: path.join(home, 'plugin') })
  assert.equal(d.found, true)
  assert.equal(d.ok, false)
  assert.equal(d.state, ImportedState.EXPIRED)
  assert.ok(d.detail.includes('过期'))
})

test('设备指纹缺失 → device_missing', () => {
  const home = makeHome()
  writeDoc(home, makeDoc([makeAccount({ device: { deviceId: 'only-one' } })]))
  const d = diagnoseImported({ home, env: {}, pluginRoot: path.join(home, 'plugin') })
  assert.equal(d.ok, false)
  assert.equal(d.state, ImportedState.DEVICE_MISSING)
})

test('指定 scope 不存在 → not_signed_in', () => {
  const home = makeHome()
  writeDoc(home, makeDoc([makeAccount()]))
  const d = diagnoseImported({ home, env: {}, scope: 'v1_public_999', pluginRoot: path.join(home, 'plugin') })
  assert.equal(d.ok, false)
  assert.equal(d.state, ImportedState.NOT_SIGNED_IN)
})

test('token 不是 JWT → token_malformed', () => {
  const home = makeHome()
  writeDoc(home, makeDoc([makeAccount({ token: 'not-a-jwt' })]))
  const d = diagnoseImported({ home, env: {}, pluginRoot: path.join(home, 'plugin') })
  assert.equal(d.ok, false)
  assert.equal(d.state, ImportedState.TOKEN_MALFORMED)
})

// ------------------------------------------------------------------ 取用

test('appVersion：环境变量覆盖账号值', () => {
  assert.equal(resolveImportedAppVersion({ account: { appVersion: '3.0.1' }, env: {} }), '3.0.1')
  assert.equal(resolveImportedAppVersion({ account: { appVersion: '3.0.1' }, env: { TELEAGENT_APP_VERSION: '3.2.0' } }), '3.2.0')
  assert.equal(resolveImportedAppVersion({ data: { appVersion: '2.9.0' }, env: {} }), '2.9.0')
  assert.equal(resolveImportedAppVersion({ env: {} }), undefined)
})

test('importedScopes 带账号名与剩余天数', () => {
  const home = makeHome()
  writeDoc(home, makeDoc([makeAccount({ scope: 'a' }), makeAccount({ scope: 'b', current: true })]))
  const scopes = importedScopes({ home, env: {}, pluginRoot: path.join(home, 'plugin') })
  assert.equal(scopes.length, 2)
  assert.equal(scopes[0].scope, 'a')
  assert.equal(scopes[0].accountName, 'user_test')
  assert.equal(scopes[1].current, true)
  assert.ok(scopes[0].daysLeft >= 5)
})

test('portal：有 cookie 才有凭据，来源标记 imported', () => {
  const home = makeHome()
  const withPortal = makeAccount({
    scope: 'with',
    portal: { userId: 'u1', operationToken: 'ot', operToken: 'op' },
  })
  const without = makeAccount({ scope: 'without', current: true })
  writeDoc(home, makeDoc([without, withPortal]))

  const none = readImportedPortalAuth({ home, env: {}, pluginRoot: path.join(home, 'plugin') })
  assert.equal(none, null)

  const hit = readImportedPortalAuth({ home, env: {}, scope: 'with', pluginRoot: path.join(home, 'plugin') })
  assert.equal(hit.userId, 'u1')
  assert.equal(hit.operationToken, 'ot')
  assert.equal(hit.operToken, 'op')
  assert.ok(hit.source.startsWith('imported:'))
})

// ------------------------------------------------------------------ 与插件原链路的关系

test('导入模式优先于平台判断：linux 上也能解出凭据', () => {
  const home = makeHome()
  writeDoc(home, makeDoc([makeAccount()]))
  const d = diagnoseCredential(home, { platform: 'linux' })
  assert.equal(d.ok, true)
  assert.equal(d.source, 'imported')
  assert.equal(d.token, makeAccount().token)
})

test('没有导入文件时 linux 仍回退到 not_macos（原行为不变）', () => {
  const home = makeHome()
  const d = diagnoseCredential(home, { platform: 'linux' })
  assert.equal(d.ok, false)
  assert.equal(d.state, 'not_macos')
})

test('readDeviceMeta 在导入模式下取文件里的指纹', () => {
  const home = makeHome()
  writeDoc(home, makeDoc([makeAccount()]))
  const device = readDeviceMeta(home)
  assert.equal(device.deviceId, 'device-abc')
  assert.equal(device.installId, 'install-xyz')
})
