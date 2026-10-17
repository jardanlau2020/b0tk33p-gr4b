#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 NODE_LINK（代理节点链接）转成本地代理，供浏览器使用。完全自包含，不拉取外部脚本。

支持：vless / vmess / trojan / ss / socks5(h) / http(s)
所有协议统一经 sing-box 转成本地 http+socks 混合入站（127.0.0.1:随机空闲端口），
浏览器只连这个无认证的本地端口——因此带账号密码的 socks5 也能用，出口 IP 自检也对所有协议有效。

流程：
1. normalize_link()：整理成固定格式 info；遇到不支持的协议/传输/插件直接报错（不再静默降级）
2. build_outbound()：info -> sing-box outbound
3. setup_node_proxy()：下载(可选 sha256 校验) -> check -> 启动 -> 自检出口 IP；
   退出时自动清理 sing-box 进程

setup_node_proxy() 成功返回 (代理URL, 脱敏出口IP, 模式)；失败抛 RuntimeError。
"""
import atexit
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request

SING_BOX_VERSION = "1.14.1"
# 可选：设置环境变量 SING_BOX_SHA256 为 tar.gz 的 sha256，则下载后强校验
SING_BOX_SHA256_ENV = "SING_BOX_SHA256"

SUPPORTED = ("vless", "vmess", "trojan", "ss", "socks5", "socks5h", "http", "https")
SUPPORTED_NET = ("tcp", "ws", "grpc", "httpupgrade")
_TRUTHY = ("1", "true", "yes", "on")


def b64decode(s):
    s = urllib.parse.unquote(s.strip())
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", "replace")


def _q(query):
    return urllib.parse.parse_qs(query, keep_blank_values=True)


def _g(q, k, d=""):
    """取参数；缺失或为空值时都回落到默认值 d。"""
    v = q.get(k, [""])[0]
    return v if v != "" else d


def _truthy(q, *keys):
    return any(_g(q, k).lower() in _TRUTHY for k in keys)


def _warn_unknown(q, known, scheme):
    unknown = [k for k in q.keys() if k not in known]
    if unknown:
        print("NODE_LINK(%s) 忽略未知参数：%s" % (scheme, ",".join(sorted(unknown))))


def _check_net(net, scheme):
    if net not in SUPPORTED_NET:
        raise RuntimeError("%s 传输方式 %s 不受支持（支持 %s）" % (scheme, net, "/".join(SUPPORTED_NET)))


# ---------------------------------------------------------------- 整理成固定格式

def normalize_vless(link):
    u = urllib.parse.urlparse(link)
    q = _q(u.query)
    _warn_unknown(q, {"encryption", "security", "sni", "fp", "alpn", "pbk", "sid", "flow",
                      "type", "path", "host", "serviceName", "allowInsecure", "insecure",
                      "headerType", "spx", "mode"}, "vless")
    uuid = urllib.parse.unquote(u.username or "")
    host = u.hostname or ""
    if not uuid or not host:
        raise RuntimeError("vless 链接缺少 uuid 或 host")
    security = _g(q, "security", "none").lower()
    if security not in ("none", "tls", "reality"):
        raise RuntimeError("vless security=%s 不受支持" % security)
    net = _g(q, "type", "tcp").lower()
    _check_net(net, "vless")
    if _g(q, "headerType", "none").lower() not in ("none", ""):
        raise RuntimeError("vless headerType 不受支持（会连不上）")
    return {
        "scheme": "vless", "uuid": uuid, "host": host, "port": u.port or 443,
        "security": security, "sni": _g(q, "sni", host), "fp": _g(q, "fp"),
        "alpn": _g(q, "alpn"), "pbk": _g(q, "pbk"), "sid": _g(q, "sid"),
        "flow": _g(q, "flow"), "net": net, "path": _g(q, "path", "/"),
        "ws_host": _g(q, "host", host), "serviceName": _g(q, "serviceName"),
        "insecure": _truthy(q, "allowInsecure", "insecure"),
    }


def normalize_vmess(link):
    raw = link.split("://", 1)[1].split("#")[0].split("?")[0]
    data = json.loads(b64decode(raw))
    host = data.get("add", "")
    if not host or not data.get("id"):
        raise RuntimeError("vmess 链接缺少 add 或 id")
    net = (data.get("net") or "tcp").lower()
    _check_net(net, "vmess")
    if (data.get("type") or "none").lower() not in ("none", ""):
        raise RuntimeError("vmess type=%s（伪装头）不受支持" % data.get("type"))
    return {
        "scheme": "vmess", "uuid": data["id"], "host": host,
        "port": int(data.get("port", 443) or 443), "aid": int(data.get("aid", 0) or 0),
        "net": net, "tls": data.get("tls") == "tls", "sni": data.get("sni") or host,
        "fp": data.get("fp") or "", "alpn": data.get("alpn") or "",
        "path": data.get("path") or "/", "ws_host": data.get("host") or host,
        "serviceName": data.get("path") or "",
        "insecure": str(data.get("allowInsecure", "")).lower() in _TRUTHY,
    }


def normalize_trojan(link):
    u = urllib.parse.urlparse(link)
    q = _q(u.query)
    _warn_unknown(q, {"sni", "allowInsecure", "insecure", "type", "path", "host",
                      "serviceName", "security", "alpn", "fp", "peer"}, "trojan")
    host = u.hostname or ""
    password = urllib.parse.unquote(u.username or "")
    if not host or not password:
        raise RuntimeError("trojan 链接缺少 password 或 host")
    net = _g(q, "type", "tcp").lower()
    _check_net(net, "trojan")
    return {
        "scheme": "trojan", "password": password, "host": host, "port": u.port or 443,
        "sni": _g(q, "sni", _g(q, "peer", host)), "net": net, "path": _g(q, "path", "/"),
        "ws_host": _g(q, "host", host), "serviceName": _g(q, "serviceName"),
        "alpn": _g(q, "alpn"), "fp": _g(q, "fp"),
        "insecure": _truthy(q, "allowInsecure", "insecure"),
    }


def normalize_ss(link):
    body = link.split("://", 1)[1].split("#")[0]
    body, _, query = body.partition("?")
    if "plugin" in _q(query):
        raise RuntimeError("ss 链接带 plugin（obfs/v2ray-plugin 等），本脚本不支持")
    body = body.rstrip("/")  # 只去尾部斜杠；base64 本体里可能含 '/'，不能按 '/' 截断
    if "@" in body:  # ss://BASE64(method:password)@host:port 或 ss://method:password@host:port
        userinfo, _, hostport = body.rpartition("@")
        try:
            decoded = b64decode(userinfo)
            if ":" not in decoded:
                raise ValueError
        except Exception:
            decoded = urllib.parse.unquote(userinfo)
        method, _, password = decoded.partition(":")
        host, _, port = hostport.rpartition(":")
        host = host.strip("[]")
    else:  # ss://BASE64(method:password@host:port)
        m = re.match(r"(.+?):(.+)@(.+):(\d+)$", b64decode(body), re.S)
        if not m:
            raise RuntimeError("ss 链接格式无法解析")
        method, password, host, port = m.group(1), m.group(2), m.group(3).strip("[]"), m.group(4)
    if not method or not password or not host or not str(port).isdigit():
        raise RuntimeError("ss 链接缺少 method/password/host/port")
    return {"scheme": "ss", "method": method, "password": password,
            "host": host, "port": int(port)}


def normalize_plain(link):
    """socks5 / socks5h / http / https 代理 URL。"""
    u = urllib.parse.urlparse(link)
    scheme = u.scheme.lower()
    if not u.hostname:
        raise RuntimeError("%s 代理链接缺少 host" % scheme)
    default_port = {"socks5": 1080, "socks5h": 1080, "http": 80, "https": 443}[scheme]
    return {"scheme": scheme, "host": u.hostname, "port": u.port or default_port,
            "user": urllib.parse.unquote(u.username or ""),
            "password": urllib.parse.unquote(u.password or "")}


def normalize_link(raw):
    """第一步：把粘贴的原始链接整理成 (scheme, info)。"""
    raw = (raw or "").strip()
    m = re.search(r"(vless|vmess|trojan|ss|shadowsocks|socks5h?|https?)://[^\s]+",
                  raw, re.IGNORECASE)
    if not m:
        raise RuntimeError("NODE_LINK 里没找到有效的节点链接")
    link = m.group(0).strip()
    scheme = link.split("://", 1)[0].lower()
    if scheme == "shadowsocks":
        scheme = "ss"
    if scheme not in SUPPORTED:
        raise RuntimeError("NODE_LINK 协议不受支持：%s（支持 %s）" % (scheme, "/".join(SUPPORTED)))
    if scheme in ("http", "https", "socks5", "socks5h"):
        info = normalize_plain(link)
    else:
        info = {"vless": normalize_vless, "vmess": normalize_vmess,
                "trojan": normalize_trojan, "ss": normalize_ss}[scheme](link)
    print("节点已整理为固定格式：%s" % canonical_redacted(scheme, info))
    return scheme, info


def canonical_redacted(scheme, info):
    i = info
    if scheme in ("http", "https", "socks5", "socks5h"):
        return "%s://%s%s:%d" % (scheme, "****@" if i["user"] or i["password"] else "",
                                 i["host"], i["port"])
    if scheme == "vless":
        return ("vless://****@%s:%d?security=%s&sni=%s&fp=%s&type=%s&path=%s"
                % (i["host"], i["port"], i["security"], i["sni"], i["fp"] or "-",
                   i["net"], i["path"]))
    if scheme == "vmess":
        return "vmess(id=****,%s:%d,net=%s,tls=%s)" % (i["host"], i["port"], i["net"], i["tls"])
    if scheme == "trojan":
        return "trojan://****@%s:%d?type=%s" % (i["host"], i["port"], i["net"])
    if scheme == "ss":
        return "ss(%s)://****@%s:%d" % (i["method"], i["host"], i["port"])
    return scheme + "://****"


# ---------------------------------------------------------------- 生成 sing-box 配置

def _ws_transport(path_val, host_val):
    """v2ray 系链接常把 early-data 写进 path（如 /p?ed=2560），拆成 sing-box 的 max_early_data。"""
    t = {"type": "ws", "headers": {"Host": host_val}}
    if "?" in (path_val or ""):
        p, _, pq = path_val.partition("?")
        t["path"] = p or "/"
        ed = urllib.parse.parse_qs(pq).get("ed", [None])[0]
        if ed and ed.isdigit():
            t["max_early_data"] = int(ed)
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
    else:
        t["path"] = path_val or "/"
    return t


def _transport(i):
    if i["net"] == "ws":
        return _ws_transport(i["path"], i["ws_host"])
    if i["net"] == "grpc":
        return {"type": "grpc", "service_name": i["serviceName"]}
    if i["net"] == "httpupgrade":
        return {"type": "httpupgrade", "path": i["path"], "host": i["ws_host"]}
    return None


def _tls_block(server_name, fp="", alpn="", reality_pk="", reality_sid="", insecure=False):
    tls = {"enabled": True, "server_name": server_name}
    if insecure:
        tls["insecure"] = True
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if alpn:
        tls["alpn"] = [a for a in alpn.split(",") if a]
    if reality_pk:
        tls["reality"] = {"enabled": True, "public_key": reality_pk, "short_id": reality_sid}
    return tls


def build_outbound(scheme, info):
    """第二步：info -> sing-box outbound。"""
    i = info
    base = {"tag": "proxy", "server": i["host"], "server_port": i["port"]}
    if scheme == "vless":
        ob = dict(base, type="vless", uuid=i["uuid"])
        if i["flow"]:
            ob["flow"] = i["flow"]
        if i["security"] in ("tls", "reality"):
            reality = i["security"] == "reality"
            ob["tls"] = _tls_block(i["sni"], i["fp"], i["alpn"],
                                   i["pbk"] if reality else "", i["sid"] if reality else "",
                                   i["insecure"])
    elif scheme == "vmess":
        ob = dict(base, type="vmess", uuid=i["uuid"], alter_id=i["aid"], security="auto")
        if i["tls"]:
            ob["tls"] = _tls_block(i["sni"], i["fp"], i["alpn"], insecure=i["insecure"])
    elif scheme == "trojan":
        ob = dict(base, type="trojan", password=i["password"],
                  tls=_tls_block(i["sni"], i["fp"], i["alpn"], insecure=i["insecure"]))
    elif scheme == "ss":
        return dict(base, type="shadowsocks", method=i["method"], password=i["password"])
    elif scheme in ("socks5", "socks5h"):
        ob = dict(base, type="socks", version="5")
        if i["user"] or i["password"]:
            ob["username"], ob["password"] = i["user"], i["password"]
        return ob
    elif scheme in ("http", "https"):
        ob = dict(base, type="http")
        if i["user"] or i["password"]:
            ob["username"], ob["password"] = i["user"], i["password"]
        if scheme == "https":
            ob["tls"] = {"enabled": True, "server_name": i["host"]}
        return ob
    else:
        raise RuntimeError("build_outbound 不支持的协议：%s" % scheme)
    tr = _transport(i)
    if tr:
        ob["transport"] = tr
    return ob


# ---------------------------------------------------------------- 启动

def _download(url, dest, tries=3):
    last = None
    for n in range(1, tries + 1):
        try:
            urllib.request.urlretrieve(url, dest)
            return
        except Exception as e:
            last = e
            print("下载失败（第 %d/%d 次）：%s" % (n, tries, e))
            time.sleep(3 * n)
    raise RuntimeError("sing-box 下载失败：%s" % last)


def ensure_singbox(workdir):
    # 优先用 workflow 缓存的二进制（SING_BOX_BIN 环境变量），省去每次下载
    env_bin = os.path.expanduser(os.environ.get("SING_BOX_BIN", "").strip())
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        print("使用缓存的 sing-box：%s" % env_bin)
        return env_bin
    binpath = os.path.join(workdir, "sing-box")
    if os.path.isfile(binpath):
        return binpath
    url = ("https://github.com/SagerNet/sing-box/releases/download/v%s/"
           "sing-box-%s-linux-amd64.tar.gz" % (SING_BOX_VERSION, SING_BOX_VERSION))
    tgz = os.path.join(workdir, "sing-box.tgz")
    print("下载 sing-box v%s ..." % SING_BOX_VERSION)
    _download(url, tgz)
    with open(tgz, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    want = os.environ.get(SING_BOX_SHA256_ENV, "").strip().lower()
    if want and digest != want:
        os.remove(tgz)
        raise RuntimeError("sing-box sha256 校验失败：期望 %s，实际 %s" % (want, digest))
    print("sing-box sha256：%s%s" % (digest, "（已校验）" if want else
                                    "（未设置 %s，可把它填进去做强校验）" % SING_BOX_SHA256_ENV))
    found = False
    with tarfile.open(tgz, "r:gz") as tf:
        for m in tf.getmembers():
            if m.isfile() and os.path.basename(m.name) == "sing-box":
                m.name = "sing-box"  # 固定落地文件名，避免路径穿越
                tf.extract(m, workdir)
                found = True
                break
    os.remove(tgz)
    if not found:
        raise RuntimeError("sing-box 压缩包里没找到可执行文件")
    os.chmod(binpath, 0o755)
    return binpath


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def setup_node_proxy(node_link, workdir="."):
    """返回 (proxy_url, 脱敏出口IP, 模式)。node_link 为空 -> 直连，proxy_url=None。"""
    if not (node_link or "").strip():
        print("未配置 NODE_LINK，直连")
        return None, probe_exit_ip(), "直连"
    scheme, info = normalize_link(node_link)
    print("NODE_LINK 协议：%s，用 sing-box 转本地代理" % scheme)
    ob = build_outbound(scheme, info)
    binpath = ensure_singbox(workdir)
    port = _free_port()
    local_proxy = "http://127.0.0.1:%d" % port
    cfg = {
        "log": {"level": "warning"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in",
                      "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [ob],
        "route": {"final": "proxy"},
    }
    cfgpath = os.path.join(workdir, "sb-config.json")
    fd = os.open(cfgpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # 含凭据，仅本人可读
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    r = subprocess.run([binpath, "check", "-c", cfgpath],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("sing-box 配置校验失败：%s" % ((r.stderr or r.stdout)[:300]))
    logpath = os.path.join(workdir, "sing-box.log")
    logf = open(logpath, "w")
    proc = subprocess.Popen([binpath, "run", "-c", cfgpath],
                            stdout=logf, stderr=subprocess.STDOUT)

    def _cleanup():
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
        except Exception:
            pass
        try:
            logf.close()
        except Exception:
            pass

    atexit.register(_cleanup)
    try:
        for _ in range(30):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=2).close()
                break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError("sing-box 启动后异常退出：%s" % _read_log_tail(logpath))
                time.sleep(1)
        else:
            raise RuntimeError("sing-box 启动 30s 后 127.0.0.1:%d 仍无响应" % port)
        print("本地代理已就绪：%s" % local_proxy)
        ip = probe_exit_ip(local_proxy)
        if not ip:
            raise RuntimeError("代理自检失败：经本地代理访问外网不通，sing-box 日志尾：%s"
                               % _read_log_tail(logpath))
        print("代理自检通过，出口 IP：%s" % ip)
        return local_proxy, ip, "代理"
    except Exception:
        _cleanup()
        raise


def mask_ip(ip):
    """IP 脱敏：1.2.3.4 -> 1.2.*.*（IPv6 只留前 3 段）。"""
    v4 = (ip or "").strip().split(".")
    if len(v4) == 4 and all(p.isdigit() for p in v4):
        return "%s.%s.*.*" % (v4[0], v4[1])
    v6 = (ip or "").strip().split(":")
    if len(v6) >= 3:
        return ":".join(v6[:3]) + ":****"
    return "****"


def probe_exit_ip(proxy_url=None):
    """经指定 http 代理（None=直连）访问外网拿出口 IP，返回脱敏值；失败返回 None。"""
    if proxy_url:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        opener = urllib.request.build_opener()
    try:
        with opener.open("https://www.cloudflare.com/cdn-cgi/trace", timeout=25) as r:
            body = r.read(300).decode("utf-8", "replace")
            m = re.search(r"ip=([^\s]+)", body)
            return mask_ip(m.group(1)) if m else None
    except Exception:
        return None


def _read_log_tail(logpath, n=15, limit=600):
    try:
        with open(logpath) as f:
            return "".join(f.readlines()[-n:])[-limit:]
    except Exception:
        return ""


if __name__ == "__main__":
    print(setup_node_proxy(os.environ.get("NODE_LINK", ""), workdir="/tmp"))
