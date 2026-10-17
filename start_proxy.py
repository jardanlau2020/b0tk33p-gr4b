#!/usr/bin/env python3
# 用 node_proxy.py 把 NODE_LINK 转成本地 http 代理，sing-box 后台常驻到 job 结束，
# 并把 LOCAL_PROXY / PROXY_IP 写进 GITHUB_ENV 供后续步骤使用。
import contextlib, io, json, os, re, socket, subprocess, sys, time
sys.path.insert(0, os.path.dirname(__file__))
import node_proxy as np

link = os.environ.get("NODE_LINK", "").strip()
if not link:
    print("未配置 NODE_LINK，直连")
    sys.exit(0)

workdir = os.environ.get("RUNNER_TEMP", "/tmp")
def fail(msg):
    sys.exit(redact(msg))

SENSITIVE = []
def redact(text):
    """公开仓库日志脱敏：去掉节点地址/SNI/UUID/密码，IP 只留前两段，域名全部打码。"""
    text = str(text or "")
    for v in sorted(SENSITIVE, key=len, reverse=True):
        text = text.replace(v, "***")
    text = re.sub(r"\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b", r"\1.*.*", text)
    text = re.sub(r"\[?[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\]?", "[ipv6]", text)
    text = re.sub(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", "***", text)
    return text

try:
    with contextlib.redirect_stdout(io.StringIO()):  # 公开仓库：不打印节点域名/SNI
        scheme, info = np.normalize_link(link)
except Exception as e:
    fail("节点链接解析失败：%s" % e)
for v in info.values():  # 节点里所有字符串字段都视为敏感（host/sni/uuid/password/path/公钥…）
    if isinstance(v, str) and len(v) >= 4 and v.lower() not in (scheme, "tcp", "tls", "none", "auto"):
        SENSITIVE.append(v)
        print("::add-mask::%s" % v)  # 让 GitHub 在后续所有步骤日志里也自动打码
print("节点协议：%s" % scheme)
try:
    ob = np.build_outbound(scheme, info)
except Exception as e:
    fail("节点配置生成失败：%s" % e)
bindir = os.path.expanduser("~/.cache/sing-box-%s" % np.SING_BOX_VERSION)  # 由 actions/cache 缓存
os.makedirs(bindir, exist_ok=True)
binpath = np.ensure_singbox(bindir)
port = np._free_port()
proxy = "http://127.0.0.1:%d" % port
cfg = {"log": {"level": "warning"},
       "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}],
       "outbounds": [ob], "route": {"final": "proxy"}}
cfgpath = os.path.join(workdir, "sb-config.json")
fd = os.open(cfgpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(cfg, f)
r = subprocess.run([binpath, "check", "-c", cfgpath], capture_output=True, text=True, timeout=30)
if r.returncode != 0:
    fail("sing-box 配置校验失败：%s" % (r.stderr or r.stdout)[:300])
logpath = os.path.join(workdir, "sing-box.log")
proc = subprocess.Popen([binpath, "run", "-c", cfgpath], stdout=open(logpath, "w"),
                        stderr=subprocess.STDOUT, start_new_session=True)
for _ in range(30):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        break
    except OSError:
        if proc.poll() is not None:
            fail("sing-box 启动后异常退出：%s" % np._read_log_tail(logpath))
        time.sleep(1)
else:
    sys.exit("sing-box 30s 内未就绪")
ip = np.probe_exit_ip(proxy)
if not ip:
    fail("代理自检失败：%s" % np._read_log_tail(logpath))
print("代理就绪，出口 IP：%s" % ip)
with open(os.environ["GITHUB_ENV"], "a") as f:
    f.write("LOCAL_PROXY=%s\nPROXY_IP=%s\n" % (proxy, ip))
