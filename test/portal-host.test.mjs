/**
 * 门户 cookie 域名匹配的回归测试。
 *
 * 背景：桌面端把 `operationToken` / `operToken` 写在父域 `.teleai.com.cn`，
 * 而旧实现只认 `agent.teleai.com.cn`，导致 Windows/macOS 上也导不出积分 cookie。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isPortalCookieHost, COOKIE_SQL } from '../lib/portal.mjs'

test('接受 teleai.com.cn 及其子域（含父域写法）', () => {
  for (const host of [
    '.teleai.com.cn',
    'teleai.com.cn',
    'agent.teleai.com.cn',
    '.agent.teleai.com.cn',
    'foo.teleai.com.cn',
  ]) {
    assert.equal(isPortalCookieHost(host), true, host)
  }
})

test('拒绝其它站点（不能把同名 cookie 当成凭据）', () => {
  for (const host of [
    '.e.189.cn',
    'umini.shujupie.com',
    'evilteleai.com.cn',
    'teleai.com.cn.evil.test',
    '',
    null,
    undefined,
  ]) {
    assert.equal(isPortalCookieHost(host), false, String(host))
  }
})

test('SQL 用父域匹配，并让更具体的域名后覆盖', () => {
  assert.match(COOKIE_SQL, /LIKE '%\.teleai\.com\.cn'/)
  assert.match(COOKIE_SQL, /ORDER BY CASE host_key/)
  // 具体子域排在父域之后（parseCookieRows 是后写覆盖先写）
  const specific = COOKIE_SQL.indexOf("WHEN 'agent.teleai.com.cn' THEN 3")
  const parent = COOKIE_SQL.indexOf("WHEN 'teleai.com.cn' THEN 1")
  assert.ok(specific > 0 && parent > specific)
})
