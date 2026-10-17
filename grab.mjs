// Botkeep 免费机器抢购脚本 (Node.js 20+)
// 流程：登录 -> 启动TG通知 -> 轮询容量 -> 有容量立即创建 Node.js 满配服务器 -> 成功TG通知
import fs from 'node:fs';
import crypto from 'node:crypto';
const BASE = 'https://api.botkeep.cloud';
const SITE = 'https://botkeep.cloud';
const env = process.env;
const EMAIL = env.BOTKEEP_EMAIL;
const PASSWORD = env.BOTKEEP_PASSWORD;
const TG_TOKEN = env.TG_BOT_TOKEN;
const TG_CHAT = env.TG_CHAT_ID;
const NAME = env.SERVER_NAME || 'my-project';
const RUNTIME = env.RUNTIME || 'nodejs';
const RES = {
  memoryLimitMb: Number(env.RAM_MB || 512),
  cpuLimitPercent: Number(env.CPU_PERCENT || 50),
  storageLimitMb: Number(env.STORAGE_MB || 1024),
};
const list = (v) => (v || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
const INCLUDE = list(env.INCLUDE_NODES); // 白名单：非空时只要这些节点，忽略黑名单
const EXCLUDE = (env.EXCLUDE_NODES ?? 'node2-it').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
const COOLDOWN_MIN = Number(env.COOLDOWN_MINUTES || 30); // 删机器后暂停多少分钟
const SUCCESS_COOLDOWN_MIN = Number(env.SUCCESS_COOLDOWN_MINUTES || 1440); // 抢到后暂停多少分钟（默认 24 小时）
const COOLDOWN_FILE = env.COOLDOWN_FILE || '.cooldown/until';
const RUN_SECONDS = Number(env.RUN_SECONDS || 240); // 单次运行轮询总时长
const INTERVAL_SECONDS = Number(env.INTERVAL_SECONDS || 20); // 轮询间隔，别太小以免触发风控

// 可选代理：LOCAL_PROXY=http://127.0.0.1:端口（由 start_proxy.py 根据 NODE_LINK 生成），只代理 Botkeep 请求
const LOCAL_PROXY = env.LOCAL_PROXY || '';
let bkFetch = fetch;
if (LOCAL_PROXY) {
  const { fetch: ufetch, ProxyAgent } = await import('undici');
  const dispatcher = new ProxyAgent(LOCAL_PROXY);
  bkFetch = (url, opts = {}) => ufetch(url, { ...opts, dispatcher });
}

const jar = new Map();
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));
const log = (...a) => console.log(new Date().toISOString(), ...a);

function saveCookies(res) {
  const list = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const c of list) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    if (i > 0) jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

let csrf = null;
async function api(path, { method = 'GET', body, headers = {}, anonymous = false } = {}) {
  const h = {
    Accept: 'application/json',
    Origin: SITE,
    Referer: `${SITE}/app/create`,
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/129 Safari/537.36',
    ...headers,
  };
  if (jar.size) h.Cookie = cookieHeader();
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (method !== 'GET' && !anonymous) {
    if (!csrf) csrf = (await api('/api/v1/auth/session')).csrf_token;
    h['X-CSRF-Token'] = csrf;
  }
  const res = await bkFetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  saveCookies(res);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const msg = (data && (data.detail || data.message || data.error)) || text || res.statusText;
    const err = new Error(`${method} ${path} -> ${res.status}: ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`);
    err.status = res.status;
    throw err;
  }
  return data && data.data !== undefined && Object.keys(data).length <= 2 ? data.data : data;
}

async function tg(text) {
  if (!TG_TOKEN || !TG_CHAT) return log('TG 未配置，跳过通知:', text);
  try {
    await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TG_CHAT, text, parse_mode: 'HTML', disable_web_page_preview: true }),
    });
  } catch (e) { log('TG 发送失败', e.message); }
}

// 取服务器所在节点/地址，返回小写字符串（等待地址分配，最多 waitSec 秒）
async function botLocation(id, waitSec = 60) {
  const end = Date.now() + waitSec * 1000;
  let info = '';
  while (true) {
    try {
      const bot = await api(`/api/v1/panel/bots/${encodeURIComponent(id)}`);
      const net = await api(`/api/v1/panel/bots/${encodeURIComponent(id)}/network`).catch(() => null);
      const hosts = (net?.allocations || []).map((a) => a.host).filter(Boolean);
      info = (JSON.stringify(bot) + ' ' + hosts.join(' ')).toLowerCase();
      if (hosts.length || /node\d*-[a-z]+/.test(info)) return { info, hosts };
    } catch (e) {
      if (e.status === 404) return { info: '', hosts: [], gone: true }; // 已删除
      log('读取节点失败', e.message);
    }
    if (Date.now() > end) return { info, hosts: [] };
    await sleep(5);
  }
}
const esc = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// 节点显示为可点击的蓝色链接
const nodeLink = (loc) => {
  const h = nodeLabel(loc);
  return /\./.test(h) ? `<a href="https://${esc(h)}">${esc(h)}</a>` : esc(h);
};
// 返回不合格原因（null 表示合格）：白名单非空只看白名单，否则看黑名单
// 节点匹配：node1 能匹配 node1-it、node1-de，但不会匹配 node10-xx
const nodeHit = (info, n) => new RegExp(`(^|[^a-z0-9])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![a-z0-9])`).test(info);
const badNode = (info) => {
  if (!info) return null; // 读不到节点时不判定
  if (INCLUDE.length) return INCLUDE.some((n) => nodeHit(info, n)) ? null : `不在白名单 ${INCLUDE.join(',')}`;
  const hit = EXCLUDE.find((n) => nodeHit(info, n));
  return hit ? `黑名单 ${hit}` : null;
};
const nodeLabel = (loc) => loc.hosts[0] || (loc.info.match(/node\d*-[a-z]+[a-z0-9.-]*/) || ['未知节点'])[0];
// 删除服务器；创建/部署中会返回 409，等它完成再删（最多等 DELETE_WAIT 秒）
async function deleteBot(id) {
  const end = Date.now() + Number(env.DELETE_WAIT || 180) * 1000;
  while (true) {
    try {
      await api(`/api/v1/panel/bots/${encodeURIComponent(id)}/actions`, { method: 'POST', body: { action: 'delete' } });
      log('已提交删除', id);
      return true;
    } catch (e) {
      if (e.status === 404) return true;
      if (e.status !== 409 || Date.now() > end) throw e;
      log('有操作进行中，5 秒后重试删除');
      await sleep(5);
    }
  }
}

// 检查账号已有服务器：不合格节点（白名单/黑名单）的删掉；有合格的返回 true（直接结束）
async function handleExisting(notify = true) {
  const dash = await api('/api/v1/panel/dashboard');
  const bots = Array.isArray(dash?.bots) ? dash.bots : [];
  const kept = [];
  let unknown = false;
  for (const b of bots) {
    if (/delet/i.test(String(b.status || b.state || b.operation?.phase || ''))) { log(`${b.name || b.id} 正在删除，忽略`); continue; }
    const loc = await botLocation(b.id, 5);
    if (loc.gone) { log(`${b.name || b.id} 已删除，忽略`); continue; }
    if (!loc.info) { log(`${b.name || b.id} 读不到节点，本次不处理`); unknown = true; continue; }
    const bad = badNode(loc.info);
    if (bad) {
      log(`已有服务器 ${b.name || b.id} 节点不合格（${bad}），删除`);
      await deleteBot(b.id);
      startCooldown();
      await tg(`🗑 Botkeep：${esc(b.name || b.id)} 在 ${nodeLink(loc)}（${esc(bad)}），已删除，暂停 ${COOLDOWN_MIN} 分钟后继续抢。`);
      throw new Cooldown();
    } else kept.push(`${esc(b.name || b.id)} @ ${nodeLink(loc)}`);
  }
  if (kept.length) {
    log(`账号已有合格服务器，暂停 ${SUCCESS_COOLDOWN_MIN} 分钟`);
    startCooldown(SUCCESS_COOLDOWN_MIN);
    if (notify) await tg(`✅ Botkeep：账号里已有服务器（${kept.join(', ')}），无需再抢。`);
    return true;
  }
  if (unknown) return true; // 读不到节点时保守退出，避免误删/误建
  return false;
}

function cooldownLeft() {
  try { return Math.max(0, Number(fs.readFileSync(COOLDOWN_FILE, 'utf8')) - Date.now()); } catch { return 0; }
}
function startCooldown(min = COOLDOWN_MIN) {
  fs.mkdirSync(COOLDOWN_FILE.split('/').slice(0, -1).join('/') || '.', { recursive: true });
  fs.writeFileSync(COOLDOWN_FILE, String(Date.now() + min * 60000));
}
class Cooldown extends Error {}

// 复用登录 Cookie：存到 .cooldown/session.json（随 actions/cache 保存），失效才重新登录
// 缓存里的 Cookie 用 AES-256-GCM 加密，密钥来自 Secrets（STATE_KEY，未设置则由账号密码派生），
// 即使有人通过 fork PR 读到缓存也解不开
const STATE_KEY = crypto.createHash('sha256').update(env.STATE_KEY || `botkeep-state:${EMAIL}:${PASSWORD}`).digest();
function seal(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', STATE_KEY, iv);
  const data = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]).toString('base64');
}
function unseal(b64) {
  const buf = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', STATE_KEY, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}
const SESSION_FILE = (COOLDOWN_FILE.split('/').slice(0, -1).join('/') || '.') + '/session.json';
function saveSession() {
  fs.mkdirSync(SESSION_FILE.split('/').slice(0, -1).join('/'), { recursive: true });
  fs.writeFileSync(SESSION_FILE, seal(JSON.stringify({ email: EMAIL, cookies: [...jar] })), { mode: 0o600 });
}
async function login() {
  jar.clear(); csrf = null;
  await api('/api/v1/auth/login', { method: 'POST', anonymous: true, body: { email: EMAIL, password: PASSWORD } });
  csrf = (await api('/api/v1/auth/session')).csrf_token;
  saveSession();
}
async function ensureLogin() {
  try {
    const st = JSON.parse(unseal(fs.readFileSync(SESSION_FILE, 'utf8')));
    if (st.email === EMAIL && st.cookies?.length) {
      for (const [k, v] of st.cookies) jar.set(k, v);
      csrf = (await api('/api/v1/auth/session')).csrf_token;
      if (csrf) { saveSession(); return '复用 Cookie 登录成功'; }
    }
  } catch (e) {
    if (e.status && e.status !== 401 && e.status !== 403) throw e; // 非登录失效的错误直接抛出
  }
  await login();
  return '登录成功';
}

// Worker 触发：启动通知每小时最多一次，附带期间运行次数；手动触发：每次都通知
const IS_WORKER = (env.TRIGGER_SOURCE || '') === 'worker';
const NOTIFY_FILE = (COOLDOWN_FILE.split('/').slice(0, -1).join('/') || '.') + '/notify.json';
const NOTIFY_EVERY_MIN = Number(env.NOTIFY_EVERY_MINUTES || 60);
function startNotice() {
  let st = {};
  try { st = JSON.parse(fs.readFileSync(NOTIFY_FILE, 'utf8')); } catch {}
  st.total = (st.total || st.count || 0) + 1; // 累计总运行次数（手动 + Worker），不清零
  // 已重复运行 = 工作流累计运行次数；尝试领取 = 累计查询容量/尝试领取机器的次数（截至本次开始前）
  const line = `已重复运行：${st.total}次\n尝试领取次数：${st.attempts || 0}次`;
  // Worker 每小时最多通知一次（留 3 分钟余量，避免 5 分钟一次的触发抖动错过整点）；手动每次都通知
  const send = !IS_WORKER || Date.now() - (st.last || 0) >= (NOTIFY_EVERY_MIN - 3) * 60000;
  if (send && IS_WORKER) st.last = Date.now();
  delete st.count;
  fs.mkdirSync(NOTIFY_FILE.split('/').slice(0, -1).join('/'), { recursive: true });
  fs.writeFileSync(NOTIFY_FILE, JSON.stringify(st));
  return { send, line };
}

// 每轮询一次就把累计尝试次数 +1 写回（随 actions/cache 保存，任何退出路径都不会丢）
function addAttempt() {
  let st = {};
  try { st = JSON.parse(fs.readFileSync(NOTIFY_FILE, 'utf8')); } catch {}
  st.attempts = (st.attempts || 0) + 1;
  try { fs.writeFileSync(NOTIFY_FILE, JSON.stringify(st)); } catch {}
}

async function main() {
  if (!EMAIL || !PASSWORD) throw new Error('缺少 BOTKEEP_EMAIL / BOTKEEP_PASSWORD');
  const left = cooldownLeft();
  if (left > 0) { log(`冷却中，还剩 ${Math.ceil(left / 60000)} 分钟，本次跳过`); return; }

  const how = await ensureLogin();
  log(`触发：${env.TRIGGER || '未知'}，${how} 出口IP ${LOCAL_PROXY ? (env.PROXY_IP || '代理') : '直连（GitHub）'}`);

  // 已有服务器：黑名单节点删掉，合格的就结束
  if (await handleExisting()) return;

  // 取 Node.js 版本和默认启动命令
  const caps = await api('/api/v1/panel/capabilities');
  const versions = caps?.runtimes?.[RUNTIME] || [];
  const runtimeVersion = env.RUNTIME_VERSION || versions[0] || '';
  const startCommand = caps?.runtimeOptions?.[RUNTIME]?.[runtimeVersion]?.command || 'npm start';
  log('运行时', RUNTIME, runtimeVersion || '(未开放)', '启动命令', startCommand);

  const notice = startNotice();
  const exitIp = LOCAL_PROXY ? `${esc(env.PROXY_IP || '未知')}（代理）` : 'GitHub（直连）';
  if (notice.send) await tg([
    `🚀 Botkeep 抢机器服务${IS_WORKER ? '运行中（每小时通知）' : '已开启'}`,
    ...(notice.line ? [notice.line] : []),
    '',
    `触发：${esc(env.TRIGGER || '未知')}`,
    `出口：${exitIp}`,
    `轮询：${RUN_SECONDS}s，每 ${INTERVAL_SECONDS}s 一次`,
    `配置：${RUNTIME} ${runtimeVersion} / ${RES.memoryLimitMb}MB / ${RES.cpuLimitPercent}% CPU / ${RES.storageLimitMb}MB`,
  ].join('\n'));
  else log(`本小时已通知过，跳过 TG（${notice.line.replace('\n', '，')}）`);

  const qs = new URLSearchParams({
    runtime: RUNTIME,
    runtimeVersion,
    memoryLimitMb: String(RES.memoryLimitMb),
    cpuLimitPercent: String(RES.cpuLimitPercent),
    storageLimitMb: String(RES.storageLimitMb),
  }).toString();
  let idemKey = crypto.randomUUID();
  const deadline = Date.now() + RUN_SECONDS * 1000;
  let n = 0;

  while (Date.now() < deadline) {
    n++;
    addAttempt();
    try {
      const avail = await api('/api/v1/panel/creation-availability?' + qs);
      if (avail?.allowed) {
        log(`第${n}次：有容量，立即创建`);
        const bot = await api('/api/v1/panel/bots', {
          method: 'POST',
          headers: { 'Idempotency-Key': idemKey },
          body: {
            name: NAME,
            platform: 'general',
            runtime: RUNTIME,
            runtimeVersion,
            sourceType: 'blank',
            repository: '',
            archiveName: '',
            branch: 'main',
            startCommand,
            tokenProvided: false,
            resources: RES,
            seedFiles: [],
          },
        });
        const id = bot?.id || bot?.bot?.id || '';
        log('创建成功', JSON.stringify(bot).slice(0, 300));
        const loc = id ? await botLocation(id, 60) : { info: '', hosts: [] };
        const bad = badNode(loc.info);
        if (bad) {
          log(`节点不合格（${bad}）@ ${nodeLabel(loc)}，删除并暂停 ${COOLDOWN_MIN} 分钟`);
          await deleteBot(id);
          startCooldown();
          await tg(`🗑 Botkeep：抢到的机器在 ${nodeLink(loc)}（${esc(bad)}），已删除，暂停 ${COOLDOWN_MIN} 分钟后继续抢。`);
          return;
        }
        startCooldown(SUCCESS_COOLDOWN_MIN);
        await tg(`🎉 Botkeep 抢到了！\n服务器：${esc(NAME)} ${esc(id)}\n节点：${nodeLink(loc)}\n${RUNTIME} ${runtimeVersion} / ${RES.memoryLimitMb}MB / ${RES.cpuLimitPercent}% / ${RES.storageLimitMb}MB\n${SITE}/app\n之后暂停 ${Math.round(SUCCESS_COOLDOWN_MIN / 60)} 小时，到时只检查机器是否还在。`);
        return;
      }
      log(`第${n}次：无容量 - ${avail?.message || ''}`);
      if (/slot/i.test(avail?.message || '')) {
        // 名额被占：可能是上次没删成的黑名单机器
        if (await handleExisting(true)) return;
      }
    } catch (e) {
      if (e instanceof Cooldown) throw e; // 冷却信号交给 main 处理，别在循环里吞掉继续抢
      log(`第${n}次出错：${e.message}`);
      if (e.status === 401 || e.status === 403) {
        try { await login(); log('会话失效，已重新登录'); } catch (e2) { log('重新登录失败', e2.message); }
      }
      if (e.status === 429) await sleep(INTERVAL_SECONDS * 2);
    }
    await sleep(INTERVAL_SECONDS);
  }
  log('本次未抢到，等下次触发');
}

main().catch(async (e) => {
  if (e instanceof Cooldown) { log('进入冷却，本次结束'); return; }
  log('致命错误', e.message);
  await tg(`⚠️ Botkeep 抢机器脚本出错：${esc(e.message)}`);
  process.exit(1);
});
