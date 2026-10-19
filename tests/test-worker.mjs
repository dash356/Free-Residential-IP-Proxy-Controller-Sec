// Worker 功能回归 + 多机上报冲突测试（mock D1）
// 运行：node tests/test-worker.mjs
import worker from '../src/index.js';

const b64 = (u, p) => 'Basic ' + Buffer.from(u + ':' + p).toString('base64');
const ENV = {
  WEB_USER: 'testadmin', WEB_PASS: 'TestPass123!x', PROXY_USER: 'proxyu', PROXY_PASS: 'ProxyPass123!x',
  DB: null, // 稍后注入
};

// ---------------- Mock D1 ----------------
class MockStmt {
  constructor(db, sql) { this.db = db; this.sql = sql; this.args = []; }
  bind(...a) { this.args = a; return this; }
  run() { return Promise.resolve(this.db.exec(this.sql, this.args, 'run')); }
  first() { return Promise.resolve(this.db.exec(this.sql, this.args, 'first')); }
  all() { return Promise.resolve(this.db.exec(this.sql, this.args, 'all')); }
}
class MockDB {
  constructor() { this.t = { servers: new Map(), server_config: new Map(), global_config: new Map(), auth_attempts: [] }; }
  prepare(sql) { return new MockStmt(this, sql); }
  findSC(nk) { return this.t.server_config.get(nk) || null; }
  exec(sql, args, mode) {
    const s = sql.replace(/\s+/g, ' ').trim();
    const T = this.t;
    if (/^CREATE TABLE IF NOT EXISTS/i.test(s)) return { success: true };
    if (/^CREATE UNIQUE INDEX/i.test(s)) return { success: true };
    if (/^ALTER TABLE/i.test(s)) return { success: true };
    if (/^UPDATE servers SET node_key = ip WHERE node_key IS NULL/i.test(s)) {
      for (const r of T.servers.values()) if (r.node_key == null) r.node_key = r.ip;
      return { success: true };
    }
    if (/^PRAGMA table_info\(server_config\)/i.test(s)) {
      return { results: ['node_key','ip','boot_id','slot_map','mode','manual_node_ip','youtube_check','force_switch','pending_uninstall'].map((n,i)=>({name:n, pk:i===0?1:0})) };
    }
    // --- global_config ---
    if (s.startsWith('SELECT key, value FROM global_config WHERE key IN')) return { results: [] };
    if (s.startsWith("SELECT value FROM global_config WHERE key = 'force_switch'")) {
      const v = T.global_config.get('force_switch'); return v ? { value: v } : null;
    }
    if (s.includes('INSERT INTO global_config')) {
      T.global_config.set(args[0], args[1]); return { success: true };
    }
    // --- servers upsert (by node_key) ---
    if (s.startsWith('INSERT INTO servers (ip, boot_id, node_key,')) {
      T.servers.set(args[2], { ip: args[0], boot_id: args[1], node_key: args[2], details: args[3], log: args[4], candidates: args[5], last_seen: args[6] });
      return { success: true };
    }
    // --- server_config ---
    if (s.startsWith('INSERT OR IGNORE INTO server_config (node_key,')) {
      if (!T.server_config.has(args[0])) T.server_config.set(args[0], {
        node_key: args[0], ip: args[1], boot_id: args[2], slot_map: args[3], mode: args[4],
        manual_node_ip: args[5], youtube_check: args[6], force_switch: args[7], pending_uninstall: 0 });
      return { success: true };
    }
    if (s.startsWith('SELECT * FROM server_config WHERE node_key = ?1')) return this.findSC(args[0]);
    if (s.startsWith('SELECT force_switch FROM server_config WHERE node_key = ?1')) {
      const r = this.findSC(args[0]); return r ? { force_switch: r.force_switch } : null;
    }
    if (s.startsWith('UPDATE server_config SET slot_map = ?2,')) {
      const r = this.findSC(args[0]);
      if (r) Object.assign(r, { slot_map: args[1], mode: args[2], manual_node_ip: args[3], youtube_check: args[4] });
      return { success: true };
    }
    if (s.startsWith('UPDATE server_config SET force_switch = ?2 WHERE node_key = ?1')) {
      const r = this.findSC(args[0]); if (r) r.force_switch = args[1]; return { success: true };
    }
    if (s.startsWith('UPDATE server_config SET pending_uninstall = 1 WHERE node_key = ?1')) {
      const r = this.findSC(args[0]); if (r) r.pending_uninstall = 1; return { success: true };
    }
    // 重装场景：同一 IP 下失联旧节点的残留卸载标记自动清除
    if (s.startsWith('UPDATE server_config SET pending_uninstall = 0')) {
      for (const r of T.server_config.values()) {
        if (r.ip === args[0] && r.node_key !== args[1] && r.pending_uninstall === 1) {
          const srow = T.servers.get(r.node_key);
          if (!srow || srow.last_seen <= args[2]) r.pending_uninstall = 0;
        }
      }
      return { success: true };
    }
    if (s.startsWith('DELETE FROM servers WHERE node_key = ?1')) { T.servers.delete(args[0]); return { success: true }; }
    if (s.startsWith('DELETE FROM server_config WHERE node_key = ?1')) { T.server_config.delete(args[0]); return { success: true }; }
    if (s.startsWith('DELETE FROM servers WHERE last_seen < ?1')) {
      const cutoff = args[0];
      for (const [k, r] of [...T.servers]) {
        if (r.last_seen < cutoff) {
          const sc = T.server_config.get(r.node_key);
          if (!(sc && sc.pending_uninstall === 1)) T.servers.delete(k);
        }
      }
      return { success: true };
    }
    if (s.startsWith('SELECT ip, details FROM servers')) {
      return { results: [...T.servers.values()].map(r => ({ ip: r.ip, details: r.details })) };
    }
    if (s.includes('FROM servers s LEFT JOIN server_config sc ON s.node_key = sc.node_key')) {
      const results = [...T.servers.values()].sort((a,b) => b.last_seen - a.last_seen).map(r => {
        const c = T.server_config.get(r.node_key) || {};
        return { ...r, c_slot_map: c.slot_map, c_mode: c.mode, c_manual_node_ip: c.manual_node_ip,
                 c_youtube_check: c.youtube_check, c_pending_uninstall: c.pending_uninstall };
      });
      return { results };
    }
    // --- auth_attempts / rate limit ---
    if (s.startsWith('INSERT INTO auth_attempts')) { T.auth_attempts.push({ ip: args[0], ts: args[1], ok: args[2] }); return { success: true }; }
    if (s.startsWith('SELECT COUNT(*) AS c FROM auth_attempts')) {
      const n = T.auth_attempts.filter(a => a.ip === args[0] && a.ts > args[1] && a.ok === 0).length;
      return { c: n };
    }
    if (s.startsWith('DELETE FROM auth_attempts')) {
      T.auth_attempts = T.auth_attempts.filter(a => a.ts >= args[0]); return { success: true };
    }
    throw new Error('UNHANDLED SQL: ' + s.slice(0, 120));
  }
}
ENV.DB = new MockDB();

// ---------------- helpers ----------------
const req = (path, opts = {}) => worker.fetch(new Request('https://w' + path, opts), ENV, {});
const authH = { 'Authorization': b64('testadmin', 'TestPass123!x'), 'CF-Connecting-IP': '9.9.9.9' };
let pass = 0, fail = 0;
function ok(name, cond, extra = '') {
  if (cond) { pass++; console.log('  PASS ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra ? ' :: ' + extra : '')); }
}
const jpost = (p, body, h = {}) => req(p, { method: 'POST', headers: { 'Content-Type': 'application/json', ...authH, ...h }, body: JSON.stringify(body) });
const cookieOf = (res) => { const sc = res.headers.get('Set-Cookie') || ''; const m = sc.match(/proxy_session=([^;]*)/); return m ? m[1] : ''; };

console.log('== 登录/会话 ==');
{
  const r = await req('/', { headers: { 'CF-Connecting-IP': '1.1.1.1' } });
  const t = await r.text();
  ok('匿名访问返回登录页', r.status === 200 && t.includes('住宅代理调度中心') && t.includes('/api/login'));
}
let sessCookie = '';
{
  const r = await req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '2.2.2.2' }, body: JSON.stringify({ username: 'testadmin', password: 'TestPass123!x' }) });
  sessCookie = cookieOf(r);
  ok('正确凭证登录成功并种 Cookie', r.status === 200 && !!sessCookie);
  const r2 = await req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '2.2.2.3' }, body: JSON.stringify({ username: 'testadmin', password: 'wrong' }) });
  ok('错误凭证 401', r2.status === 401);
}
{
  const r = await req('/', { headers: { 'Cookie': 'proxy_session=' + sessCookie, 'CF-Connecting-IP': '3.3.3.3' } });
  const t = await r.text();
  ok('会话 Cookie 可进面板', r.status === 200 && t.includes('全局设置'));
  const r2 = await req('/', { headers: { 'Cookie': 'proxy_session=bad', 'CF-Connecting-IP': '3.3.3.4' } });
  ok('伪造 Cookie 被拦回登录页', (await r2.text()).includes('/api/login'));
}
{
  const r = await req('/api/logout', { method: 'POST', headers: { 'Cookie': 'proxy_session=' + sessCookie, 'CF-Connecting-IP': '4.4.4.4' } });
  const sc = r.headers.get('Set-Cookie') || '';
  ok('退出登录清除 Cookie', r.status === 200 && sc.includes('Max-Age=0'));
  const r2 = await req('/', { headers: { 'Cookie': 'proxy_session=', 'CF-Connecting-IP': '4.4.4.5' } });
  ok('退出后访问回到登录页', (await r2.text()).includes('/api/login'));
}

console.log('== 上报/节点（单机） ==');
{
  const r = await jpost('/api/report', { ip: '10.0.0.1', details: [{ port: 3000, country: 'JP' }], log: 'boot ok' });
  ok('老 Agent 上报（无 boot_id）OK', r.status === 200);
  const rBad = await jpost('/api/report', { details: [] });
  ok('上报缺 ip 返回 400（不写脏行）', rBad.status === 400);
  const nodes = await (await req('/api/nodes', { headers: authH })).json();
  ok('单节点出现在列表', nodes.length === 1 && nodes[0].ip === '10.0.0.1');
  ok('老 Agent node_key 即 ip（向后兼容）', nodes[0].node_key === '10.0.0.1');
  const cfg = await (await req('/api/config?ip=10.0.0.1', { headers: authH })).json();
  ok('专属配置默认继承全局', cfg.slot_map['0'] === 'JP' && cfg.uninstall === false);
}

console.log('== 多机同出口 IP：上报不冲突 ==');
const BOOT_A = '111-000001', BOOT_B = '222-000002';
{
  await jpost('/api/report', { ip: '10.9.9.9', boot_id: BOOT_A, details: [{ port: 3000, country: 'JP' }], log: 'A alive' });
  await jpost('/api/report', { ip: '10.9.9.9', boot_id: BOOT_B, details: [{ port: 3001, country: 'US' }], log: 'B alive' });
  const nodes = await (await req('/api/nodes', { headers: authH })).json();
  const twins = nodes.filter(n => n.ip === '10.9.9.9');
  ok('同 IP 双机各自独立成行', twins.length === 2, JSON.stringify(twins.map(t => t.node_key)));
  ok('node_key 互不相同', new Set(twins.map(t => t.node_key)).size === 2);
  ok('各自日志独立不混', twins.some(t => t.log === 'A alive') && twins.some(t => t.log === 'B alive'));
  // 各自独立配置
  const nkA = '10.9.9.9|' + BOOT_A, nkB = '10.9.9.9|' + BOOT_B;
  await jpost('/api/server/config', { node: nkA, country: 'US', mode: 'auto', youtube_check: false });
  const cfgA = await (await req('/api/config?ip=10.9.9.9&boot=' + BOOT_A, { headers: authH })).json();
  const cfgB = await (await req('/api/config?ip=10.9.9.9&boot=' + BOOT_B, { headers: authH })).json();
  ok('A 的配置独立生效', cfgA.slot_map['0'] === 'US');
  ok('B 不受 A 影响（仍为默认 JP）', cfgB.slot_map['0'] === 'JP');
  // 强制换 IP 只影响 A
  await jpost('/api/server/switch', { node: nkA });
  const cfgA2 = await (await req('/api/config?ip=10.9.9.9&boot=' + BOOT_A, { headers: authH })).json();
  const cfgB2 = await (await req('/api/config?ip=10.9.9.9&boot=' + BOOT_B, { headers: authH })).json();
  ok('强制换 IP 只作用于 A', Object.keys(cfgA2.force_switch).length === 1 && Object.keys(cfgB2.force_switch).length === 0);
}

console.log('== 多机：卸载互不干扰 ==');
{
  const nkA = '10.9.9.9|' + BOOT_A, nkB = '10.9.9.9|' + BOOT_B;
  await jpost('/api/server/remove', { node: nkA, mode: 'uninstall' });
  const cfgA = await (await req('/api/config?ip=10.9.9.9&boot=' + BOOT_A, { headers: authH })).json();
  const cfgB = await (await req('/api/config?ip=10.9.9.9&boot=' + BOOT_B, { headers: authH })).json();
  ok('A 收到卸载指令', cfgA.uninstall === true);
  ok('B 未受影响', cfgB.uninstall === false);
  // A 上报心跳（仍在卸载等待期），B 正常心跳
  await jpost('/api/report', { ip: '10.9.9.9', boot_id: BOOT_A, details: [], log: 'A waiting' });
  await jpost('/api/report', { ip: '10.9.9.9', boot_id: BOOT_B, details: [], log: 'B fine' });
  // A 完成卸载并注销
  const un = await jpost('/api/server/uninstalled', { ip: '10.9.9.9', boot_id: BOOT_A });
  ok('A 注销回调成功', un.status === 200);
  const nodes = await (await req('/api/nodes', { headers: authH })).json();
  const twins = nodes.filter(n => n.ip === '10.9.9.9');
  ok('A 已从面板消失，B 仍在', twins.length === 1 && twins[0].node_key === nkB, JSON.stringify(twins.map(t=>t.node_key)));
}

console.log('== 重装场景：旧卸载标记不误伤新系统 ==');
{
  const BOOT_C = '333-000003';
  await jpost('/api/report', { ip: '10.8.8.8', boot_id: BOOT_C, details: [], log: 'C alive' });
  await jpost('/api/server/remove', { node: '10.8.8.8|' + BOOT_C, mode: 'uninstall' });
  // 旧系统失联（把 last_seen 推到 120s+ 前）
  const oldRow = ENV.DB.t.servers.get('10.8.8.8|' + BOOT_C);
  oldRow.last_seen = Date.now() - 300000;
  // 同 IP 全新重装上报（新 boot_id）
  const BOOT_D = '444-000004';
  await jpost('/api/report', { ip: '10.8.8.8', boot_id: BOOT_D, details: [], log: 'D fresh' });
  const cfgD = await (await req('/api/config?ip=10.8.8.8&boot=' + BOOT_D, { headers: authH })).json();
  ok('新系统不受旧卸载标记影响', cfgD.uninstall === false);
  const nodes = await (await req('/api/nodes', { headers: authH })).json();
  const rows = nodes.filter(n => n.ip === '10.8.8.8');
  ok('失联旧节点被清理，只剩新系统', rows.length === 1 && rows[0].node_key === '10.8.8.8|' + BOOT_D, JSON.stringify(rows.map(r=>r.node_key)));
}

console.log('== 限流 ==');
{
  for (let i = 0; i < 10; i++)
    await req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '7.7.7.7' }, body: JSON.stringify({ username: 'x', password: 'y' }) });
  const r = await req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '7.7.7.7' }, body: JSON.stringify({ username: 'testadmin', password: 'TestPass123!x' }) });
  ok('10 次失败后被限流 429', r.status === 429);
  for (let i = 0; i < 12; i++) await req('/', { headers: { 'CF-Connecting-IP': '8.8.8.8' } });
  const r2 = await req('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '8.8.8.8' }, body: JSON.stringify({ username: 'testadmin', password: 'TestPass123!x' }) });
  ok('匿名访问面板不计入失败（未被误封）', r2.status === 200);
}

console.log('== 下发脚本语法 ==');
{
  const fs = await import('fs'), cp = await import('child_process');
  const H = { 'Authorization': b64('testadmin', 'TestPass123!x'), 'CF-Connecting-IP': '9.9.9.9' };
  const agent = await (await req('/agent', { headers: H })).text();
  const lite = await (await req('/scripts/lite_manager.py', { headers: H })).text();
  const proxy = await (await req('/scripts/proxy_server.py', { headers: H })).text();
  fs.writeFileSync('/tmp/_agent.sh', agent); fs.writeFileSync('/tmp/_lite.py', lite); fs.writeFileSync('/tmp/_proxy.py', proxy);
  const sh = (f, c) => { try { cp.execSync(c, { stdio: 'pipe' }); return true; } catch { return false; } };
  ok('agent.sh bash 语法通过', sh(0, 'bash -n /tmp/_agent.sh'));
  ok('lite_manager.py 编译通过', sh(0, 'python3 -m py_compile /tmp/_lite.py'));
  ok('proxy_server.py 编译通过', sh(0, 'python3 -m py_compile /tmp/_proxy.py'));
  ok('心跳上报带 boot_id', lite.includes('"boot_id": BOOT_ID'));
  ok('端口变更持久化到本机文件（防无限重启）', lite.includes('PORT_FILE') && lite.includes('load_base_port'));
  ok('crontab 调用有守卫', agent.includes('command -v crontab'));
}

console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
