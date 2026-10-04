// ====== 免费住宅IP智能调度系统 (安全加固版) ======

// 鉴权失败计数（同 isolate 内共享；见 fetch 内 authRateLimited 说明）
const AUTH_FAILS = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- 提取云端变量（不再提供弱口令默认值；未配置强口令则拒绝服务）---
    const WEB_USER = env.WEB_USER || "";
    const WEB_PASS = env.WEB_PASS || "";
    const PROXY_USER = env.PROXY_USER || "";
    const PROXY_PASS = env.PROXY_PASS || "";
    const configuredProxyPort = env.PROXY_PORT ? parseInt(env.PROXY_PORT, 10) : 10001;
    const PROXY_PORT = Number.isInteger(configuredProxyPort) && configuredProxyPort >= 1 && configuredProxyPort <= 65535 ? configuredProxyPort : 10001;

    // ====================================================
    // [安全基线] 弱口令直接拒绝服务（fail closed）
    // 口令必须长度 >= 12 且不在常见弱口令表内，否则所有路由返回 500
    // ====================================================
    const WEAK_SECRETS = new Set(["admin", "admin888", "888888", "password", "123456", "12345678", "qwerty", "proxy", "proxyuser", "changeme", "letmein"]);
    const isWeakSecret = (s) => {
      const v = String(s || "");
      return v.length < 12 || WEAK_SECRETS.has(v.toLowerCase());
    };
    if (isWeakSecret(WEB_PASS) || isWeakSecret(PROXY_PASS)) {
      return new Response(
        "Server misconfigured: set strong WEB_PASS and PROXY_PASS (at least 12 characters, not a common password) in Worker environment variables before use.",
        { status: 500, headers: { "Content-Type": "text/plain;charset=UTF-8" } }
      );
    }

    // ====================================================
    // [安全基线] 简易内存限流（同 isolate 内生效；生产环境请再叠加 Cloudflare 控制台的 Rate Limiting 规则）
    // ====================================================
    const clientIp = (request) => request.headers.get("CF-Connecting-IP") || "unknown";
    const authRateLimited = (request) => {
      const now = Date.now();
      let rec = AUTH_FAILS.get(clientIp(request));
      if (!rec || now > rec.resetAt) {
        rec = { count: 0, resetAt: now + 60000, blockedUntil: 0 };
        AUTH_FAILS.set(clientIp(request), rec);
      }
      return now < rec.blockedUntil;
    };
    const noteAuthFail = (request) => {
      const now = Date.now();
      const ip = clientIp(request);
      let rec = AUTH_FAILS.get(ip);
      if (!rec || now > rec.resetAt) {
        rec = { count: 0, resetAt: now + 60000, blockedUntil: 0 };
        AUTH_FAILS.set(ip, rec);
      }
      rec.count++;
      if (rec.count >= 10) rec.blockedUntil = now + 5 * 60000; // 1 分钟内失败 10 次则封 5 分钟
    };

    // 常量时间字符串比较，防御时序攻击
    const timingSafeEqualStr = (a, b) => {
      const ab = new TextEncoder().encode(String(a));
      const bb = new TextEncoder().encode(String(b));
      if (ab.length !== bb.length) return false;
      let diff = 0;
      for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
      return diff === 0;
    };

    // ====================================================
    // [基础防御] 浏览器与安全节点 Basic Auth 鉴权函数
    // ====================================================
    const authenticate = (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const spaceIdx = authHeader.indexOf(" ");
      if (spaceIdx === -1) return false;
      const scheme = authHeader.slice(0, spaceIdx);
      const encoded = authHeader.slice(spaceIdx + 1);
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const colonIdx = decoded.indexOf(":");
        if (colonIdx === -1) return false;
        const username = decoded.slice(0, colonIdx);
        const password = decoded.slice(colonIdx + 1); // 只按第一个冒号切分，口令可含冒号
        return timingSafeEqualStr(username, WEB_USER) && timingSafeEqualStr(password, WEB_PASS);
      } catch (e) {
        return false;
      }
    };

    const unauthorizedResponse = () => {
      return new Response("Unauthorized.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Residential Proxy Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    // ====================================================
    // [安全基线] 统一鉴权门：所有敏感路由（含 /scripts/* 与 /agent）在业务逻辑之前鉴权
    // ====================================================
    const SENSITIVE_PATHS = new Set([
      "/", "/api/config", "/api/nodes", "/api/proxies", "/api/report", "/api/switch",
      "/agent", "/scripts/proxy_server.py", "/scripts/lite_manager.py"
    ]);
    if (SENSITIVE_PATHS.has(url.pathname)) {
      if (authRateLimited(request)) {
        return new Response("Too many failed attempts. Try again later.", {
          status: 429, headers: { "Content-Type": "text/plain;charset=UTF-8" }
        });
      }
      if (!authenticate(request)) {
        noteAuthFail(request);
        return unauthorizedResponse();
      }
    }

    // ====================================================
    // [1] 数据库建表 (D1)
    // ====================================================
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS servers (
          ip TEXT PRIMARY KEY,
          details TEXT,
          log TEXT DEFAULT '',
          candidates TEXT DEFAULT '[]',
          last_seen INTEGER
        )
      `).run();
      try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN log TEXT DEFAULT ''`).run(); } catch (e) {}
      try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN candidates TEXT DEFAULT '[]'`).run(); } catch (e) {}

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();

    // ====================================================
    // [2] 动态分发：Proxy Server 引擎源码
    // ====================================================
    if (url.pathname === "/scripts/proxy_server.py") {
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64, json, struct, random
from typing import Any

# [安全] 凭证不再由 C2 下发时硬编码，改为读取本机 600 权限的 c2.json（由 /agent 安装脚本写入）
def _load_c2_conf():
    try:
        with open("/opt/proxy_lite/c2.json", "r") as _f:
            return json.load(_f)
    except Exception:
        return {}
_C2CONF = _load_c2_conf()
PROXY_USER = str(_C2CONF.get("proxy_user", "")).encode()
PROXY_PASS = str(_C2CONF.get("proxy_pass", "")).encode()

# [安全] 连接数上限与空闲超时，防线程耗尽 DoS
_MAX_CONN = 200
_conn_sem = threading.BoundedSemaphore(_MAX_CONN)
_IDLE_TIMEOUT = 300

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def _dns_query(host: str, bind_interface: str, dns_server: str = "8.8.8.8", timeout: float = 8) -> str:
    # [安全] 极简 DNS/UDP 客户端：查询走隧道内，防止把代理目标域名暴露给 VPS 服务商
    qid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join([bytes([len(label)]) + label.encode("idna") for label in host.rstrip(".").split(".")]) + b"\\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        if bind_interface:
            s.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode("utf-8"))
        s.sendto(packet, (dns_server, 53))
        data, _ = s.recvfrom(512)
    finally:
        s.close()
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
        raise OSError("bad dns reply")
    ancount = struct.unpack(">H", data[6:8])[0]
    off = 12
    while off < len(data) and data[off] != 0:
        off += data[off] + 1
    off += 5
    for _ in range(ancount):
        if off + 10 > len(data):
            break
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        rtype, rclass, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rclass == 1 and rdlen == 4:
            return socket.inet_ntoa(rdata)
    raise OSError("no A record")

def resolve_host(host: str, bind_interface: str) -> str:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return host
        except OSError:
            pass
    try:
        if bind_interface:
            return _dns_query(host, bind_interface)
    except Exception:
        pass
    return socket.gethostbyname(host)

def create_connection(address: tuple[str, int], bind_interface: str, timeout: float = 20) -> socket.socket:
    host, port = address
    err = None
    try:
        resolved = resolve_host(host, bind_interface)
    except Exception as e:
        raise OSError("dns failed: {}".format(e))
    for res in socket.getaddrinfo(resolved, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    last_active = time.time()
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 60)
        if errored:
            return
        if time.time() - last_active > _IDLE_TIMEOUT:
            return  # [安全] 空闲连接超时断开，防连接堆积
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)
            last_active = time.time()

def socks5_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF") 
            return
        client.sendall(b"\\x05\\x02")
        
        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)
        
        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\\x01\\x01") 
            return
        client.sendall(b"\\x01\\x00") 

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        upstream = create_connection((host, port), bind_interface, timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")
        
        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break
                    
        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), bind_interface, timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), bind_interface, timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int], bind_interface: str) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first, bind_interface)
        else: http_client(client, first, bind_interface)
    except:
        try: client.close()
        except: pass
    finally:
        try: _conn_sem.release()
        except: pass

def start_proxy_server(host: str, port: int, bind_interface: str = "tun0") -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            if not _conn_sem.acquire(blocking=False):
                # [安全] 连接数达上限直接拒绝，防线程耗尽 DoS
                try: client.close()
                except: pass
                continue
            threading.Thread(target=proxy_client, args=(client, address, bind_interface), daemon=True).start()
        except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [3] 动态分发：Lite Manager 调度引擎源码 (防误杀单端口版)
    // ====================================================
    if (url.pathname === "/scripts/lite_manager.py") {
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, json, sys
from pathlib import Path

MAX_CONCURRENT_NODES = 1
BASE_PROXY_PORT = ${PROXY_PORT}
API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = ""  # [安全] 由 load_c2_conf() 从本机 c2.json 填充，不再由 C2 下发时硬编码

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"
LOG_MAX_BYTES = 256 * 1024
REPORT_LOG_BYTES = 12 * 1024
MANAGER_LOG_FILE = WORKSPACE / "manager.log"

GOLDEN_NODES_FILE = WORKSPACE / "golden_nodes.json"
golden_nodes = {}
golden_lock = threading.Lock()

# [安全] 所有凭证从本机 600 权限的 c2.json 读取（由 /agent 安装脚本写入），C2 下发代码中不再包含任何口令
WEB_USER = ""
WEB_PASS = ""

def load_c2_conf():
    global WEB_USER, WEB_PASS, C2_URL
    try:
        with open(str(WORKSPACE / "c2.json"), "r") as f:
            conf = json.load(f)
        WEB_USER = str(conf.get("web_user", ""))
        WEB_PASS = str(conf.get("web_pass", ""))
        C2_URL = str(conf.get("c2_url", ""))
    except Exception as e:
        print("[-] 无法读取 c2.json，请重新运行纳管命令: {}".format(e), flush=True)

dynamic_slot_map = {0: "JP"}
control_mode = "auto"
manual_node_ip = ""
youtube_check_enabled = False
config_fetch_interval = 15
heartbeat_interval = 30
pool = {0: {"process": None, "ip": "", "country": "", "connected_at": 0, "connecting": False}}
pool_lock = threading.Lock()
public_ip = ""

def append_bounded_log(log_file, stream):
    try:
        with open(log_file, "a", buffering=1) as output:
            for line in iter(stream.readline, b""):
                output.write(line.decode("utf-8", errors="replace"))
                output.flush()
                if log_file.stat().st_size > LOG_MAX_BYTES:
                    content = log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                    log_file.write_bytes(b"[log truncated]\\n" + content)
    except: pass

def read_recent_log(log_file):
    try:
        return log_file.read_text(errors="replace")[-REPORT_LOG_BYTES:]
    except: return ""

def read_recent_logs():
    try:
        result = subprocess.run(
            ["journalctl", "-u", "proxy-lite.service", "-n", "120", "--no-pager", "-o", "short-iso"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        journal = result.stdout.decode("utf-8", errors="replace").strip()
        if journal:
            return journal[-REPORT_LOG_BYTES:]
    except: pass
    manager = read_recent_log(MANAGER_LOG_FILE)
    openvpn = read_recent_log(WORKSPACE / "ovpn_err_0.log")
    return (manager + "\\n" + openvpn)[-REPORT_LOG_BYTES:]

class BoundedTee:
    def __init__(self, console, log_file):
        self.console = console
        self.log_file = log_file

    def write(self, value):
        try:
            self.console.write(value)
        except UnicodeEncodeError:
            try:
                if hasattr(self.console, "buffer"):
                    self.console.buffer.write(value.encode("utf-8", errors="replace"))
                else:
                    self.console.write(value.encode("ascii", errors="replace").decode("ascii"))
            except: pass
        try:
            self.console.flush()
        except: pass
        try:
            with open(self.log_file, "a", buffering=1) as output:
                output.write(value)
            if self.log_file.stat().st_size > LOG_MAX_BYTES:
                content = self.log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                self.log_file.write_bytes(b"[log truncated]\\n" + content)
        except: pass

    def flush(self):
        self.console.flush()

dead_ips = {} 

last_switch_timestamps = {0: 0}
global_node_reservoir = {} 
reservoir_lock = threading.Lock()

_cached_snapshot = []
_last_harvest_time = 0

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": f"Basic {auth_ptr}"
    }

def is_ip_blacklisted(ip):
    if ip in dead_ips:
        if time.time() < dead_ips[ip]["expire_at"]:
            return True
        else:
            del dead_ips[ip]
    return False

def add_to_blacklist(ip, country, reason="fault", duration=60):
    dead_ips[ip] = {
        "country": country,
        "expire_at": time.time() + duration,
        "reason": reason
    }

def load_golden_nodes():
    global golden_nodes
    try:
        if GOLDEN_NODES_FILE.exists():
            with open(GOLDEN_NODES_FILE, 'r') as f: golden_nodes = json.load(f)
            print(f"[*] 📥 成功加载【黄金备用池】，当前储备历史高质节点数: {len(golden_nodes)}", flush=True)
    except: pass

def save_golden_nodes():
    try:
        with open(GOLDEN_NODES_FILE, 'w') as f: json.dump(golden_nodes, f)
    except: pass

def add_golden_node(node):
    with golden_lock:
        golden_nodes[node["ip"]] = {
            "ip": node["ip"], "country": node["country"], "config": node["config"],
            "ping": node.get("ping", 9999), "added_at": time.time()
        }
    save_golden_nodes()

def remove_golden_node(ip):
    with golden_lock:
        if ip in golden_nodes: del golden_nodes[ip]
    save_golden_nodes()

def fetch_config():
    req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))

def apply_config(data):
    global dynamic_slot_map, last_switch_timestamps, BASE_PROXY_PORT, control_mode, manual_node_ip, youtube_check_enabled, config_fetch_interval, heartbeat_interval
    if "proxy_port" in data:
        new_port = int(data["proxy_port"])
        if 1 <= new_port <= 65535 and new_port != BASE_PROXY_PORT:
            print(f"[*] 检测到监听端口变更: {BASE_PROXY_PORT} -> {new_port}，准备重启服务...", flush=True)
            BASE_PROXY_PORT = new_port
            os._exit(0)
    new_mode = "manual" if data.get("mode") == "manual" else "auto"
    new_manual_node_ip = str(data.get("manual_node_ip", "")).strip()
    mode_changed = new_mode != control_mode or (new_mode == "manual" and new_manual_node_ip != manual_node_ip)
    control_mode = new_mode
    manual_node_ip = new_manual_node_ip
    youtube_check_enabled = data.get("youtube_check", False) is True
    config_fetch_interval = max(5, min(3600, int(data.get("config_fetch_interval", 15))))
    heartbeat_interval = max(10, min(3600, int(data.get("heartbeat_interval", 30))))
    if "slot_map" in data:
        new_map = {int(k): str(v).upper() for k, v in data.get("slot_map", {}).items()}
        force_switch = {int(k): int(v) for k, v in data.get("force_switch", {}).items()}
    else:
        new_map = {int(k): str(v).upper() for k, v in data.items()}
        force_switch = {}
    with pool_lock:
        for slot, desired_country in new_map.items():
            if slot >= MAX_CONCURRENT_NODES: continue
            dynamic_slot_map[slot] = desired_country
            info = pool[slot]
            cmd_ts = force_switch.get(slot, 0)
            should_switch = False
            if cmd_ts > last_switch_timestamps[slot]:
                last_switch_timestamps[slot] = cmd_ts
                should_switch = True
                print(f"[*] ⚡ 接收到母机手动干预指令: 强制刷新单端口网络层IP！", flush=True)
            if info["process"] and info["process"].poll() is None:
                current_country = info.get("country", "")
                if (current_country and current_country != desired_country) or should_switch or mode_changed:
                    if not should_switch:
                        print(f"[*] 策略变更触发: 需要从 {current_country} 切换到 {desired_country}，正在掐断旧连接...", flush=True)
                    if info["ip"]:
                        add_to_blacklist(info["ip"], info["country"], reason="manual", duration=60)
                    try: info["process"].terminate(); info["process"].wait(timeout=2)
                    except: info["process"].kill()

def update_config_loop():
    while True:
        try:
            apply_config(fetch_config())
        except: pass
        time.sleep(config_fetch_interval)

def c2_heartbeat_loop():
    if not public_ip or public_ip == "Unknown_IP": get_public_ip()
    try:
        payload = json.dumps({"ip": public_ip, "details": [], "log": read_recent_logs()}).encode('utf-8')
        req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
        urllib.request.urlopen(req, timeout=10)
    except: pass
    while True:
        time.sleep(heartbeat_interval)
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None:
                    uptime = time.time() - info["connected_at"]
                    if uptime > 10: 
                        actual_country = info.get("country", dynamic_slot_map.get(slot, "UN"))
                        details.append({"slot": slot, "country": actual_country, "port": BASE_PROXY_PORT, "connected_time": int(uptime), "node_ip": info["ip"]})
        log_file = WORKSPACE / "ovpn_err_0.log"
        with reservoir_lock:
            candidates = [{"ip": n["ip"], "country": n["country"], "ping": n.get("ping", 9999)} for n in global_node_reservoir.values() if n.get("ip") and not is_ip_blacklisted(n["ip"])]
        candidates.sort(key=lambda n: n["ping"])
        payload = json.dumps({"ip": public_ip, "details": details, "log": read_recent_logs(), "candidates": candidates[:500]}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
            print(f"[*] 成功向心跳控制塔汇报。连通率: {len(details)} / 1", flush=True)
        except: pass

def setup_env():
    load_c2_conf()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    sys.stdout = BoundedTee(sys.__stdout__, MANAGER_LOG_FILE)
    sys.stderr = BoundedTee(sys.__stderr__, MANAGER_LOG_FILE)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n")
        AUTH_FILE.chmod(0o600)
    load_golden_nodes()

def harvest_snapshot_nodes() -> list:
    global _cached_snapshot, _last_harvest_time
    if time.time() - _last_harvest_time < 300 and _cached_snapshot:
        return _cached_snapshot
        
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                "country": row.get("CountryShort", "").upper(), 
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        if nodes:
            _cached_snapshot = nodes
            _last_harvest_time = time.time()
        return _cached_snapshot
    except: return _cached_snapshot

def setup_routing(slot: int):
    dev, table = f"tun{slot}", str(100 + slot)
    subprocess.run(["ip", "rule", "del", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", dev, "table", table], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", dev, "table", table], capture_output=True)

# [安全] OpenVPN 配置指令黑名单：第三方志愿者节点下发的 .ovpn 以 root 身份执行，
# 配置文件内手写的 redirect-gateway / route / dhcp-option / up / down 等指令不受
# 命令行 --route-nopull 限制，必须在写入前过滤，含危险指令的节点直接拒收并拉黑。
_OVPN_BLOCKED_DIRECTIVES = (
    "redirect-gateway", "redirect-private",
    "route", "route-ipv6", "route-delay", "route-metric", "route-up", "route-pre-down",
    "dhcp-option", "dhcp-renew", "dhcp-release",
    "up", "down", "ipchange", "tls-verify",
    "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address",
    "plugin", "management", "management-hold", "management-query-passwords",
    "http-proxy", "http-proxy-option", "http-proxy-retry", "http-proxy-timeout", "socks-proxy",
    "setenv", "setenv-safe", "setenv-opt", "script-security", "pull-filter",
    "pkcs12", "askpass", "auth-retry",
)

def sanitize_ovpn_config(text):
    """清洗第三方下发的 OpenVPN 配置。返回 (cleaned_text, ok)，
    ok 为 False 表示配置含有危险指令，调用方应拒收该节点。内联证书块(<ca>/<cert>/...)原样保留。"""
    out_lines = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("<"):
            in_block = not line.startswith("</")
            out_lines.append(raw)
            continue
        if in_block:
            out_lines.append(raw)
            continue
        key = line.split()[0].lower()
        if key in _OVPN_BLOCKED_DIRECTIVES:
            return "", False
        out_lines.append(raw)
    return "\n".join(out_lines) + "\n", True

def connect_slot(slot: int, node: dict):
    try:
        dev, cfg_path, log_file = f"tun{slot}", CONFIG_DIR / f"tun{slot}.ovpn", WORKSPACE / f"ovpn_err_{slot}.log"
        clean_cfg, cfg_ok = sanitize_ovpn_config(node["config"])
        if not cfg_ok:
            print("[-] 单端口 ({}) 节点配置含危险指令，已拒收并拉黑24h: {}".format(node["country"], node["ip"]), flush=True)
            add_to_blacklist(node["ip"], node["country"], reason="evil-config", duration=86400)
            with pool_lock: pool[slot]["connecting"] = False
            return
        cfg_path.write_text(clean_cfg)
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", dev, "--dev-type", "tun", "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", "--route-nopull", "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", "--connect-timeout", "10", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
        log_file.write_text("")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threading.Thread(target=append_bounded_log, args=(log_file, process.stdout), daemon=True).start()
        
        success = False
        for _ in range(25):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass
                
        if success and process.poll() is None:
            is_residential = True
            try:
                print(f"[*] 单端口 ({node['country']}) 隧道初步打通，鉴定是否为纯正住宅IP...", flush=True)
                # [修复] 先经隧道获取真实出口 IP，再查该 IP 的类型；原来误查了 VPN 服务器 IP
                egress_ip = ""
                try:
                    egr = subprocess.run(
                        ["curl", "-s", "-m", "10", "--interface", f"tun{slot}", "https://api.ipify.org"],
                        capture_output=True, text=True, timeout=15)
                    egress_ip = (egr.stdout or "").strip()
                except Exception:
                    egress_ip = ""
                check_ip = egress_ip or node["ip"]
                print(f"[*] 隧道出口 IP 为 {check_ip}，正在鉴定...", flush=True)
                req_url = f"https://ip.net.coffee/ip/{check_ip}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    api_resp = check_res.read().decode("utf-8").lower()
                    if "residential" in api_resp or "isp" in api_resp or "住宅" in api_resp: is_residential = True
                    else:
                        clean_resp = api_resp.replace(" ", "").replace("\\n", "").replace("\\r", "")
                        if "hosting" in api_resp or "datacenter" in api_resp or "机房" in api_resp or "data center" in api_resp:
                            if '"hosting":false' not in clean_resp and '"datacenter":false' not in clean_resp: is_residential = False
            except: pass
            
            if not is_residential:
                is_history_golden = False
                with golden_lock:
                    if node["ip"] in golden_nodes: is_history_golden = True
                
                if is_history_golden:
                    print(f"[*] 单端口 ({node['country']}) 虽为机房IP，但具备【历史黄金池】免死特权，强制放行: {node['ip']}", flush=True)
                else:
                    print(f"[-] 单端口 ({node['country']}) 检测为机房IP，暂时隔离冷却(2小时): {node['ip']}", flush=True)
                    try: process.terminate(); process.wait(timeout=2)
                    except: process.kill()
                    add_to_blacklist(node["ip"], node["country"], reason="datacenter", duration=7200) 
                    with pool_lock: pool[slot]["connecting"] = False
                    return

            setup_routing(slot)
            
            services_passed = True
            if youtube_check_enabled:
                print(f"[*] 单端口 ({node['country']}) 核验通过，执行 YouTube 业务连通性测试...", flush=True)
                test_urls = ["https://www.youtube.com"]
                for test_url in test_urls:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "15", "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "--interface", f"tun{slot}", test_url], capture_output=True)
                    if res.returncode != 0:
                        print(f"[-] 单端口 ({node['country']}) 访问 {test_url} 阻断/超时，临时冷却: {node['ip']}", flush=True)
                        services_passed = False
                        break
            
            if not services_passed:
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()
                add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
                with pool_lock: pool[slot]["connecting"] = False
                return

            add_golden_node(node)
            with pool_lock:
                pool[slot]["process"] = process
                pool[slot]["ip"] = node["ip"]
                pool[slot]["country"] = node["country"]
                pool[slot]["connected_at"] = time.time()
            print(f"[+] 单端口 ({node['country']}) 优质IP完全就绪入池: {node['ip']}", flush=True)
        else:
            try: process.terminate(); process.wait(timeout=2)
            except: process.kill()
            add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
    finally:
        with pool_lock: pool[slot]["connecting"] = False

def health_check_loop():
    test_targets = [
        "http://www.gstatic.com/generate_204",
        "http://captive.apple.com/hotspot-detect.html",
        "https://www.cloudflare.com/cdn-cgi/trace",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]

    while True:
        time.sleep(60) 
        slots_to_check = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None and (time.time() - info["connected_at"] > 60):
                    slots_to_check.append((slot, info["process"], info["ip"], dynamic_slot_map.get(slot, "UN")))
        
        for slot, process, ip, country in slots_to_check:
            failed = True
            
            for attempt in range(2):
                alive = False
                for target in test_targets:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "10", "--interface", f"tun{slot}", target], capture_output=True)
                    if res.returncode == 0:
                        alive = True
                        break 
                
                if alive:
                    failed = False
                    break 
                    
                time.sleep(3)

            if failed:
                print(f"[!] 单端口网络 连续多次【多渠道联合盲探】均失败！判定掉线重拨: {ip}", flush=True)
                add_to_blacklist(ip, country, reason="fault", duration=60)
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()

def maintain_pool():
    global dead_ips, global_node_reservoir, golden_nodes
    while True:
        snapshot = harvest_snapshot_nodes()
        with reservoir_lock:
            for n in snapshot:
                global_node_reservoir[n["ip"]] = n
                
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips: global_node_reservoir.pop(ip, None)
            print(f"[*] ⚡ 蓄水池循环，当前大池常驻: {len(global_node_reservoir)} 个 (极品保留库: {len(golden_nodes)} 个)", flush=True)

        empty_slots = []
        with pool_lock:
            for slot, info in pool.items():
                if not info["connecting"] and (info["process"] is None or info["process"].poll() is not None):
                    empty_slots.append(slot)
                    info["process"] = None; info["ip"] = ""; info["country"] = ""
        
        if empty_slots:
            with reservoir_lock:
                all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x.get("ping", 9999))
            with golden_lock:
                all_golden_nodes = sorted(list(golden_nodes.values()), key=lambda x: x.get("ping", 9999))

            used_ips = [info["ip"] for info in pool.values() if info["ip"]]
            
            for slot in empty_slots:
                if control_mode == "manual":
                    node = next((n for n in all_pool_nodes if n["ip"] == manual_node_ip), None)
                    if not node:
                        node = next((n for n in all_golden_nodes if n["ip"] == manual_node_ip), None)
                    if node and node["ip"] not in used_ips and not is_ip_blacklisted(node["ip"]):
                        used_ips.append(node["ip"])
                        with pool_lock: pool[slot]["connecting"] = True
                        threading.Thread(target=connect_slot, args=(slot, node), daemon=True).start()
                    else:
                        print(f"[-] 手动模式: 等待所选节点 {manual_node_ip or '(未选择)'} 可用...", flush=True)
                    continue

                target_country = dynamic_slot_map.get(slot, "JP")
                
                candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                
                if not candidates:
                    golden_candidates = [n for n in all_golden_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                    if golden_candidates:
                        print(f"[*] 🏆 主池枯竭，触发【黄金备用池】！正在提取历史高质 [{target_country}] 节点...", flush=True)
                        candidates = golden_candidates

                if not candidates:
                    now_ts = time.time()
                    country_blacklisted = [ip for ip, meta in list(dead_ips.items()) if meta["country"] == target_country and now_ts < meta["expire_at"] and meta["reason"] != "datacenter"]
                    
                    if country_blacklisted:
                        for bip in country_blacklisted:
                            dead_ips.pop(bip, None)
                        print(f"[!] ⚡ 区域紧急熔断：[{target_country}] 储备资源彻底归零！已精准释放该区域共 {len(country_blacklisted)} 个冷却中节点提前救场！", flush=True)
                        candidates = [n for n in (all_pool_nodes + all_golden_nodes) if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]

                if candidates:
                    node = candidates.pop(0)
                    used_ips.append(node["ip"])
                    with pool_lock: pool[slot]["connecting"] = True
                    threading.Thread(target=connect_slot, args=(slot, node), daemon=True).start()
                    time.sleep(0.5)
                else:
                    print(f"[-] 单端口: 本地【大池+黄金储备】中该国家可用配额彻底打空，挂起抓取...", flush=True)
        time.sleep(5)

def main():
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", "openvpn.*tun[0-9]"], capture_output=True)
    
    print("========================================", flush=True)
    print("  免费住宅IP智能调度系统 [防误杀极品节点单端口版] 启动！", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=update_config_loop, daemon=True).start()

    try:
        apply_config(fetch_config())
    except: pass

    import proxy_server
    for i in range(MAX_CONCURRENT_NODES):
        threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", BASE_PROXY_PORT, f"tun{i}"), daemon=True).start()
    
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [4] 动态分发：VPS 一键安装脚本
    // ====================================================
    if (url.pathname === "/agent") {
      // [安全] 安装脚本经统一鉴权门校验后下发；凭据以 JSON 形式写入本机 c2.json（600 权限），
      // 下发的 .py 引擎代码中不再包含任何口令。heredoc 使用 quoted 分隔符，JSON 由服务端生成，无注入风险。
      const c2conf = JSON.stringify({ web_user: WEB_USER, web_pass: WEB_PASS, proxy_user: PROXY_USER, proxy_pass: PROXY_PASS, c2_url: domain });
      const agentScript = `#!/usr/bin/env bash
echo "=========================================================="
echo "    免费住宅IP智能调度系统 直连部署 (安全加固版)"
echo "=========================================================="
set -e

crontab -l 2>/dev/null | grep -v "/opt/proxy_lite/heartbeat.sh" | crontab -
rm -f /opt/proxy_lite/heartbeat.sh

apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron

mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

echo "[1/4] 写入 C2 凭证配置 (仅 root 可读)..."
cat > /opt/proxy_lite/c2.json << 'C2JSON_EOF'
${c2conf}
C2JSON_EOF
chmod 600 /opt/proxy_lite/c2.json
C2_URL="${domain}"
C2_AUTH="$(python3 -c "import json;d=json.load(open('/opt/proxy_lite/c2.json'));print(d['web_user']+':'+d['web_pass'])")"

echo "[2/4] 从调度中心拉取智能隔离引擎 (鉴权下载)..."
curl -sfL -u "$C2_AUTH" "$C2_URL/scripts/lite_manager.py" -o lite_manager.py
curl -sfL -u "$C2_AUTH" "$C2_URL/scripts/proxy_server.py" -o proxy_server.py
chmod 600 lite_manager.py proxy_server.py

echo "[3/4] 配置系统群组守护..."
cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Residential Proxy Core Engine
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/proxy-lite.conf << 'EOF'
[Journal]
SystemMaxUse=50M
SystemMaxFileSize=10M
RuntimeMaxUse=20M
MaxRetentionSec=7day
EOF
systemctl restart systemd-journald
journalctl --vacuum-size=50M --vacuum-time=7d >/dev/null 2>&1 || true
systemctl restart proxy-lite.service

echo "[4/4] 校验引擎启动..."
sleep 3
systemctl is-active --quiet proxy-lite.service && echo "[+] 安全加固版部署成功，守护进程运行中。" || echo "[!] 服务未正常启动，请检查 journalctl -u proxy-lite.service"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [5] 开放API接口
    // ====================================================
    if (url.pathname === "/api/countries") {
        try {
            const requestedCountries = [
                "AE","AR","AT","AU","BE","BD","BG","BH","BR","CA","CH","CL","CN","CO",
                "CR","CY","CZ","DE","DK","EE","EG","ES","FI","FR","GB","GR","HK","HR",
                "HU","ID","IE","IL","IN","IQ","IR","IS","IT","JM","JO","JP","KE","KH",
                "KR","KW","KZ","LA","LB","LK","LT","LU","LV","MA","MD","MM","MN","MO",
                "MX","MY","NG","NL","NO","NP","NZ","OM","PA","PE","PH","PK","PL","PT",
                "QA","RO","RS","RU","SA","SE","SG","SI","SK","TH","TR","TW","UA","US",
                "UY","UZ","VE","VN","ZA"
            ];
            const response = await fetch("https://www.vpngate.net/api/iphone/");
            const text = await response.text();
            const lines = text.split('\n');
            const countries = new Set(requestedCountries);
            for (let i = 2; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if (parts.length > 6) {
                    const country = parts[6];
                    if (country && country.length === 2 && country !== "xx" && country !== "--") countries.add(country);
                }
            }
            return new Response(JSON.stringify(Array.from(countries)), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        } catch(err) {
            return new Response(JSON.stringify(["JP", "KR", "US", "GB", "TW"]), { headers: { "Content-Type": "application/json" } }); 
        }
    }

    // [6] API 接口区（鉴权已在顶部统一鉴权门完成，此处不再重复）

    if (url.pathname === "/api/config" && request.method === "GET") {
        const { results } = await env.DB.prepare(`SELECT key, value FROM global_config WHERE key IN ('slot_map', 'force_switch', 'proxy_port', 'mode', 'manual_node_ip', 'youtube_check', 'config_fetch_interval', 'heartbeat_interval', 'frontend_poll_interval')`).all();
        let slot_map = {0: "JP"};
        let force_switch = {};
        let proxy_port = PROXY_PORT;
        let mode = 'auto';
        let manual_node_ip = '';
        let youtube_check = false;
        let config_fetch_interval = 15;
        let heartbeat_interval = 30;
        let frontend_poll_interval = 5;
        if (results) {
            for (let row of results) {
                if (row.key === 'slot_map') slot_map = JSON.parse(row.value);
                if (row.key === 'force_switch') force_switch = JSON.parse(row.value);
                if (row.key === 'proxy_port') proxy_port = parseInt(row.value, 10);
                if (row.key === 'mode') mode = row.value === 'manual' ? 'manual' : 'auto';
                if (row.key === 'manual_node_ip') manual_node_ip = row.value;
                if (row.key === 'youtube_check') youtube_check = row.value === 'true';
                if (row.key === 'config_fetch_interval') config_fetch_interval = Math.max(5, Math.min(3600, parseInt(row.value, 10) || 15));
                if (row.key === 'heartbeat_interval') heartbeat_interval = Math.max(10, Math.min(3600, parseInt(row.value, 10) || 30));
                if (row.key === 'frontend_poll_interval') frontend_poll_interval = Math.max(5, Math.min(300, parseInt(row.value, 10) || 5));
            }
        }
        return new Response(JSON.stringify({slot_map, force_switch, proxy_port, mode, manual_node_ip, youtube_check, config_fetch_interval, heartbeat_interval, frontend_poll_interval}), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        const data = await request.json();
        const proxyPort = Number.parseInt(data.proxy_port, 10);
        if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
          return new Response("Invalid proxy port. Use a number from 1 to 65535.", { status: 400 });
        }
        const slotMap = data.slot_map || data;
        const mode = data.mode === 'manual' ? 'manual' : 'auto';
        const manualNodeIp = typeof data.manual_node_ip === 'string' ? data.manual_node_ip.trim() : '';
        const youtubeCheck = data.youtube_check === true;
        const configFetchInterval = Math.max(5, Math.min(3600, Number.parseInt(data.config_fetch_interval, 10) || 15));
        const heartbeatInterval = Math.max(10, Math.min(3600, Number.parseInt(data.heartbeat_interval, 10) || 30));
        const frontendPollInterval = Math.max(5, Math.min(300, Number.parseInt(data.frontend_poll_interval, 10) || 5));
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('slot_map', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(JSON.stringify(slotMap)).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('proxy_port', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(String(proxyPort)).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('mode', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(mode).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('manual_node_ip', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(manualNodeIp).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('youtube_check', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(String(youtubeCheck)).run();
        for (const [key, value] of [['config_fetch_interval', configFetchInterval], ['heartbeat_interval', heartbeatInterval], ['frontend_poll_interval', frontendPollInterval]]) {
          await env.DB.prepare(`
              INSERT INTO global_config (key, value) VALUES (?1, ?2)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value
          `).bind(key, String(value)).run();
        }
        return new Response("OK");
    }

    if (url.pathname === "/api/switch" && request.method === "POST") {
        const data = await request.json();
        const targetSlot = data.slot;
        let force_switch = {};
        const res = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'force_switch'`).first();
        if (res) force_switch = JSON.parse(res.value);
        force_switch[targetSlot] = Date.now();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('force_switch', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(JSON.stringify(force_switch)).run();
        return new Response("OK");
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        await env.DB.prepare(`
          INSERT INTO servers (ip, details, log, candidates, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)
          ON CONFLICT(ip) DO UPDATE SET details = excluded.details, log = excluded.log, candidates = excluded.candidates, last_seen = excluded.last_seen
        `).bind(data.ip, JSON.stringify(data.details || []), String(data.log || '').slice(-12000), JSON.stringify(data.candidates || []).slice(0, 100000), Date.now()).run();
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error", { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          for (let node of JSON.parse(server.details)) {
            proxyList.push(`socks5://${PROXY_USER}:${PROXY_PASS}@${server.ip}:${node.port}#${node.country}_Port${node.port}_${node.node_ip || 'IP'}`);
          }
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT * FROM servers ORDER BY last_seen DESC`).all();
       return new Response(JSON.stringify((results || []).map(server => {
         let candidates = [];
         try { candidates = JSON.parse(server.candidates || '[]'); } catch (e) {}
         return {...server, candidates};
       })), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      // [安全] 面板响应附加安全头：CSP 防 XSS、DENY 防点击劫持
      return new Response(DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_PORT), {
        headers: {
          "Content-Type": "text/html;charset=UTF-8",
          "Content-Security-Policy": "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'deny'",
          "X-Frame-Options": "DENY",
          "X-Content-Type-Options": "nosniff",
          "Referrer-Policy": "no-referrer"
        }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = (domain, webUser, webPass, proxyPort) => {
  // [安全] 面板不再明文展示任何凭证；纳管命令携带鉴权信息（shell 转义 + HTML 转义），请勿外泄此命令
  const htmlEsc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const shEsc = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
  const bootstrapCmdHtml = htmlEsc("bash <(curl -sL -u " + shEsc(webUser + ":" + webPass) + " " + domain + "/agent)");
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>免费住宅IP智能调度系统 (单端口防误杀版)</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 font-sans p-4 md:p-6 min-h-screen flex flex-col">
    <div class="max-w-[1440px] mx-auto w-full flex-grow relative">
        <div class="absolute -top-24 -left-24 w-72 h-72 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="absolute top-20 right-0 w-80 h-80 bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="relative flex flex-col lg:flex-row lg:justify-between lg:items-end gap-5 mb-7">
            <div>
                <div class="flex items-center gap-3 mb-3">
                    <div class="w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(52,211,153,.8)]"></div>
                    <span class="text-xs tracking-[0.28em] uppercase text-cyan-300/80 font-semibold">Residential Edge Control</span>
                </div>
                <h1 class="text-3xl md:text-4xl font-black tracking-tight bg-gradient-to-r from-cyan-300 via-blue-400 to-violet-400 bg-clip-text text-transparent">住宅代理调度中心</h1>
                <p class="text-slate-400 mt-2 text-sm md:text-base">单端口智能网络编排 · 节点健康监控 · 实时遥测同步</p>
                <a href="/api/proxies" target="_blank" class="inline-flex items-center gap-2 mt-4 text-xs text-cyan-300 hover:text-cyan-200 transition">提取代理列表 <span class="font-mono bg-slate-900/80 border border-cyan-400/20 rounded px-2 py-1">${domain}/api/proxies</span></a>
            </div>
            
            <div class="flex flex-col items-end gap-2">
                <div class="glass-card p-4 rounded-2xl border border-white/10">
                    <p class="text-[11px] tracking-widest uppercase text-slate-500 mb-2">Provision New VPS（命令含鉴权口令，请勿外泄）</p>
                    <code class="text-emerald-300 text-xs md:text-sm select-all break-all">${bootstrapCmdHtml}</code>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-5 mb-5 relative">
            <div class="lg:col-span-1 glass-card p-5 rounded-2xl border border-white/10 flex flex-col min-h-[280px] max-h-[360px]">
                <div class="flex items-start justify-between mb-1">
                    <div><p class="text-[11px] tracking-widest uppercase text-slate-500">Global Pool</p><h2 class="text-xl font-bold text-slate-100 mt-1">可用国家</h2></div>
                    <span class="px-2 py-1 rounded-full text-[10px] bg-cyan-400/10 text-cyan-300 border border-cyan-400/20">LIVE</span>
                </div>
                <p class="text-xs text-slate-500 mb-4">节点池持续刷新，优质线路会优先进入调度队列。</p>
                <div id="countries-list" class="flex flex-wrap gap-2 overflow-y-auto custom-scrollbar flex-grow content-start">
                    <span class="text-slate-500 text-sm">正在拉取节点数据库...</span>
                </div>
            </div>
            <div class="lg:col-span-3 glass-card p-5 rounded-2xl border border-white/10">
                <div class="flex flex-col md:flex-row md:justify-between md:items-center gap-4 mb-5">
                    <div>
                        <p class="text-[11px] tracking-widest uppercase text-slate-500">Policy Console</p>
                        <h2 class="text-xl font-bold text-slate-100 mt-1">连接策略控制</h2>
                        <p class="text-xs text-slate-500 mt-1">端口、模式和节点策略保存后将同步到所有已纳管 VPS。</p>
                    </div>
                    <button onclick="saveConfig()" class="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white px-6 py-3 rounded-xl text-sm font-bold shadow-lg shadow-cyan-900/30 transition transform hover:-translate-y-0.5">保存并全局下发</button>
                </div>
                <div class="flex flex-wrap gap-3" id="config-form">
                    <span class="text-gray-500 text-sm">加载中...</span>
                </div>
            </div>
        </div>
        
        <div class="glass-card rounded-2xl shadow-2xl shadow-black/20 overflow-hidden border border-white/10 mb-5">
            <table class="w-full text-left border-collapse">
                <thead>
                    <tr class="bg-white/[0.04] text-slate-400 border-b border-white/10">
                        <th class="py-3 px-4 font-semibold text-sm w-1/6">VPS 母机 IP</th>
                        <th class="py-3 px-4 font-semibold text-sm">已就绪的特优代理 (国家 | 节点IP:端口)</th>
                        <th class="py-3 px-4 font-semibold text-sm w-1/12">心跳状态</th>
                        <th class="py-3 px-4 font-semibold text-sm text-right w-1/12">在线率</th>
                    </tr>
                </thead>
                <tbody id="nodes-table" class="divide-y divide-gray-700">
                    <tr><td colspan="4" class="py-8 text-center text-gray-500">正在与调度中心数据库通信...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="bg-[#050a12] border border-white/10 rounded-2xl shadow-2xl flex flex-col h-64 relative overflow-hidden">
            <div class="bg-white/[0.04] border-b border-white/10 px-4 py-3 flex items-center justify-between">
                <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full bg-red-500"></div>
                    <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
                    <div class="w-3 h-3 rounded-full bg-green-500"></div>
                    <span class="text-xs text-slate-400 ml-2 font-mono">journalctl -u proxy-lite.service</span>
                </div>
                <div class="text-[10px] text-green-400 font-mono animate-pulse">● 实时直播</div>
            </div>
             <div id="mock-terminal" class="hidden"></div>
             <pre id="remote-log" class="hidden p-4 overflow-y-auto flex-grow bg-black/40 text-xs text-green-300 whitespace-pre-wrap custom-scrollbar"></pre>
        </div>
    </div>

    <style>
        body { background-image: radial-gradient(circle at 20% 0%, rgba(14, 165, 233, .08), transparent 32rem), linear-gradient(135deg, #020617 0%, #0b1120 55%, #111827 100%); }
        .glass-card { background: linear-gradient(145deg, rgba(15, 23, 42, .88), rgba(15, 23, 42, .62)); box-shadow: 0 18px 60px rgba(0, 0, 0, .22), inset 0 1px rgba(255,255,255,.04); backdrop-filter: blur(16px); }
        th { letter-spacing: .08em; text-transform: uppercase; font-size: 10px !important; }
        td { border-color: rgba(255,255,255,.06) !important; }
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(15,23,42,.6); border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #155e75; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #22d3ee; }
        @media (max-width: 640px) { body { padding: 12px; } table { min-width: 680px; } .glass-card { border-radius: 16px; } }
    </style>

    <script>
        // [安全] HTML 转义：所有来自服务端/外部的数据在经 innerHTML 渲染前必须转义，防存储型 XSS
        const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
        // === 伪同步日志系统 ===
        const terminalLogs = [];
        function pushLog(msg, type="INFO") {
            const term = document.getElementById('mock-terminal');
            if (!term) return;
            const now = new Date();
            const timeStr = now.getHours().toString().padStart(2, '0') + ':' + 
                            now.getMinutes().toString().padStart(2, '0') + ':' + 
                            now.getSeconds().toString().padStart(2, '0');
            
            let color = 'text-gray-300';
            if(type === 'WARN') color = 'text-yellow-400';
            if(type === 'ERR') color = 'text-red-400';
            if(type === 'SUCCESS') color = 'text-green-400';
            if(type === 'SYS') color = 'text-blue-300';

            terminalLogs.push(\`<span class="text-gray-500">[\${timeStr}]</span> <span class="\${color}">[\${type}] \${esc(msg)}</span>\`);
            if(terminalLogs.length > 50) terminalLogs.shift();
            
            term.innerHTML = terminalLogs.join('<br>');
            term.scrollTop = term.scrollHeight;
        }

        function renderRemoteLogs(servers) {
            const log = servers.map(server => {
                const text = String(server.log || '').trim();
                return text ? \`===== \${server.ip} =====\\n\${text}\` : '';
            }).filter(Boolean).join('\\n');
            const remoteLog = document.getElementById('remote-log');
            if (log) {
                remoteLog.textContent = log.slice(-24000);
                remoteLog.classList.remove('hidden');
            } else {
                remoteLog.classList.add('hidden');
            }
        }

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                list.sort();
                container.innerHTML = list.map(c => \`<span class="bg-gray-700 px-2 py-1 rounded text-xs font-bold text-gray-300 border border-gray-600 cursor-pointer hover:bg-gray-600 transition" onclick="document.getElementById('slot-cfg-0').value='\${esc(c)}'">\${esc(c)}</span>\`).join('');
            } catch(e) {}
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/config');
                const map_data = await res.json();
                const map = map_data.slot_map || map_data; 
                const container = document.getElementById('config-form');
                
                const port = Number(map_data.proxy_port) || ${proxyPort};
                const val = map[0] || 'JP';
                let html = \`
                    <div class="flex flex-wrap items-end gap-4 bg-gray-900 border border-gray-700 rounded p-4 relative group">
                        <div class="flex flex-col gap-2 w-48">
                            <label for="control-mode" class="text-[12px] text-gray-400 text-left">连接模式</label>
                            <select id="control-mode" onchange="toggleManualMode()" class="bg-gray-800 border border-gray-600 rounded p-2 text-white font-bold focus:outline-none focus:border-blue-400 transition w-full">
                                <option value="auto" \${map_data.mode === 'manual' ? '' : 'selected'}>自动连接</option>
                                <option value="manual" \${map_data.mode === 'manual' ? 'selected' : ''}>手动选择</option>
                            </select>
                        </div>
                        <div class="flex flex-col gap-2 min-w-56 flex-1">
                            <label for="manual-node" class="text-[12px] text-gray-400 text-left">手动节点</label>
                            <select id="manual-node" class="bg-gray-800 border border-gray-600 rounded p-2 text-white font-mono focus:outline-none focus:border-blue-400 transition w-full">
                                <option value="\${esc(map_data.manual_node_ip || '')}">等待节点列表...</option>
                            </select>
                        </div>
                        <div class="flex flex-col gap-2 w-48">
                            <label for="proxy-port" class="text-[12px] text-gray-400 text-left">代理监听端口</label>
                            <input type="number" id="proxy-port" value="\${port}" min="1" max="65535" step="1" required class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold text-xl focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <label class="flex items-center gap-3 px-3 py-2 rounded-xl bg-slate-800/70 border border-white/10 cursor-pointer select-none">
                            <input type="checkbox" id="youtube-check" \${map_data.youtube_check ? 'checked' : ''} class="w-4 h-4 accent-cyan-400" />
                            <span><strong class="block text-sm text-slate-200">YouTube 可用检测</strong><small class="text-[11px] text-slate-500">默认关闭，减少连接耗时</small></span>
                        </label>
                        <div class="flex flex-col gap-2 w-40">
                            <label for="config-fetch-interval" class="text-[12px] text-gray-400 text-left">Agent 拉配置间隔（秒）</label>
                            <input type="number" id="config-fetch-interval" value="\${map_data.config_fetch_interval || 15}" min="5" max="3600" step="1" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <div class="flex flex-col gap-2 w-40">
                            <label for="heartbeat-interval" class="text-[12px] text-gray-400 text-left">Agent 心跳间隔（秒）</label>
                            <input type="number" id="heartbeat-interval" value="\${map_data.heartbeat_interval || 30}" min="10" max="3600" step="1" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <div class="flex flex-col gap-2 w-40">
                            <label for="frontend-poll-interval" class="text-[12px] text-gray-400 text-left">面板轮询间隔（秒）</label>
                            <input type="number" id="frontend-poll-interval" value="\${map_data.frontend_poll_interval || 5}" min="5" max="300" step="1" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <div class="flex flex-col bg-gray-900 border-l border-gray-700 pl-4 text-center relative group w-48">
                            <div class="flex justify-between items-center px-1 mb-2">
                                <label class="text-[12px] text-gray-400">当前区域策略</label>
                            <button onclick="forceSwitchIP(0, \${port})" title="嫌弃该IP？一键强制拉黑换新" class="text-gray-500 hover:text-red-400 transition">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.214-.722 5.002 5.002 0 009.777 1.665H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.277z" clip-rule="evenodd"></path>
                                </svg>
                            </button>
                            </div>
                            <input type="text" id="slot-cfg-0" value="\${esc(val)}" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold text-xl uppercase focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                    </div>
                \`;
                
                container.innerHTML = html;
                toggleManualMode();
            } catch(e) {}
        }

        function toggleManualMode() {
            const mode = document.getElementById('control-mode');
            const node = document.getElementById('manual-node');
            if (!mode || !node) return;
            node.disabled = mode.value !== 'manual';
            node.classList.toggle('opacity-50', node.disabled);
        }

        function updateManualNodeOptions(servers) {
            const select = document.getElementById('manual-node');
            if (!select) return;
            const selected = select.value;
            const candidates = [];
            (servers || []).forEach(server => {
                (server.candidates || []).forEach(node => {
                    if (!candidates.some(item => item.ip === node.ip)) candidates.push(node);
                });
            });
            candidates.sort((a, b) => (a.ping || 9999) - (b.ping || 9999) || String(a.country || '').localeCompare(String(b.country || '')) || String(a.ip).localeCompare(String(b.ip)));
            select.innerHTML = '<option value="">请选择可用节点</option>' + candidates.map(node =>
                \`<option value="\${esc(node.ip)}">\${esc(node.country || '--')} | \${esc(node.ip)} | \${esc(node.ping || '?')} ms</option>\`
            ).join('');
            if (candidates.some(node => node.ip === selected)) select.value = selected;
            toggleManualMode();
        }

        async function forceSwitchIP(slot, port) {
            if(!confirm(\`确认要强行断开并刷新【端口 \${port}】当前的节点 IP 吗？\\n(该IP仅会进入 1 分钟临时冷却，不会被从池中删除。)\`)) return;
            try {
                const res = await fetch('/api/switch', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({slot: slot})
                });
                if(res.ok) {
                    pushLog(\`[指令下达] 已向代理层发送端口 \${port} 的手动熔断强杀指令\`, 'WARN');
                    alert(\`⚡ 指令下达成功！\\nVPS 监控引擎已收到杀机指令。\`);
                } else {
                    alert('网络指令下发失败，请重试');
                }
            } catch(e) {
                alert('网络指令下发异常');
            }
        }

        async function saveConfig() {
            const port = Number.parseInt(document.getElementById('proxy-port').value, 10);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                alert('代理端口必须是 1 到 65535 之间的整数');
                return;
            }
            const map = {
                0: document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP'
            };
            const mode = document.getElementById('control-mode').value;
            const manualNodeIp = document.getElementById('manual-node').value;
            const youtubeCheck = document.getElementById('youtube-check').checked;
            const configFetchInterval = Number.parseInt(document.getElementById('config-fetch-interval').value, 10);
            const heartbeatInterval = Number.parseInt(document.getElementById('heartbeat-interval').value, 10);
            const frontendPollInterval = Number.parseInt(document.getElementById('frontend-poll-interval').value, 10);
            if (!Number.isInteger(configFetchInterval) || configFetchInterval < 5 || configFetchInterval > 3600 || !Number.isInteger(heartbeatInterval) || heartbeatInterval < 10 || heartbeatInterval > 3600 || !Number.isInteger(frontendPollInterval) || frontendPollInterval < 5 || frontendPollInterval > 300) {
                alert('间隔设置不合法：配置拉取 5-3600 秒，心跳 10-3600 秒，面板轮询 5-300 秒');
                return;
            }
            if (mode === 'manual' && !manualNodeIp) {
                alert('手动模式必须先选择一个可用节点');
                return;
            }
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({slot_map: map, proxy_port: port, mode, manual_node_ip: manualNodeIp, youtube_check: youtubeCheck, config_fetch_interval: configFetchInterval, heartbeat_interval: heartbeatInterval, frontend_poll_interval: frontendPollInterval})
            });
            if (!res.ok) {
                alert('配置保存失败，请检查端口范围后重试');
                return;
            }
            pushLog('[控制中心广播] 国家路由策略已更新至节点。', 'SYS');
            alert(\`配置已下发，代理端口将切换为 \${port}。\`);
            loadConfig();
            restartNodePolling(frontendPollInterval);
        }

        let nodePollingTimer;
        function restartNodePolling(seconds) {
            if (nodePollingTimer) clearInterval(nodePollingTimer);
            nodePollingTimer = setInterval(fetchNodes, seconds * 1000);
        }

        async function fetchNodes() {
            try {
                const res = await fetch('/api/nodes');
                const servers = await res.json();
                const tbody = document.getElementById('nodes-table');
                renderRemoteLogs(servers || []);
                updateManualNodeOptions(servers || []);
                
                if (!servers || servers.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-gray-500">当前没有被纳管的机器，请在 VPS 运行右上角命令接入</td></tr>';
                    return;
                }

                servers.forEach(s => {
                    if (Math.random() > 0.6) {
                        const dList = JSON.parse(s.details || '[]');
                        const evtRand = Math.random();
                        if (evtRand > 0.8) {
                            pushLog(\`节点 [\${esc(s.ip)}] 心跳数据已同步，当前健康存活链路: \${dList.length}/1\`, 'SUCCESS');
                        } else if (evtRand > 0.5 && dList.length < 1) {
                            pushLog(\`节点 [\${esc(s.ip)}] 正在从黄金储备池中提取“免死金牌”极品节点...\`, 'INFO');
                        } else if (evtRand > 0.3) {
                            pushLog(\`节点 [\${esc(s.ip)}] 路由表重组完成，黄金历史节点已豁免下发。\`, 'SYS');
                        }
                    }
                });

                tbody.innerHTML = servers.map(server => {
                    const details = JSON.parse(server.details || '[]');
                    const timeAgo = Math.floor((Date.now() - server.last_seen) / 1000);
                    
                    details.sort((a,b) => a.port - b.port);

                    let proxyBadges = details.map(d => 
                        \`<div class="inline-flex items-center bg-gray-700 border border-gray-600 rounded px-2 py-1 mr-2 mb-2 text-xs">
                            <span class="text-blue-400 font-bold mr-2">\${esc(d.country)}</span>
                            <span class="font-mono text-blue-200 mr-2" title="节点物理IP">\${esc(d.node_ip || '分配中...')}:\${esc(d.port)}</span>
                        </div>\`
                    ).join('');

                    if (details.length === 0) proxyBadges = '<span class="text-yellow-500 text-xs">高容错极速调度中... 正在建立单端口稳定网络...</span>';

                    return \`
                        <tr class="hover:bg-gray-750 transition-colors">
                            <td class="py-4 px-4 font-mono text-lg text-blue-300 align-top">\${esc(server.ip)}</td>
                            <td class="py-4 px-4 align-top">\${proxyBadges}</td>
                            <td class="py-4 px-4 text-gray-400 align-top">\${timeAgo}s 前</td>
                            <td class="py-4 px-4 align-top text-right">
                                <span class="\${details.length === 1 ? 'bg-green-900 text-green-300' : 'bg-yellow-900 text-yellow-300'} py-1 px-3 rounded-full text-xs font-bold">\${details.length} / 1</span>
                            </td>
                        </tr>
                    \`;
                }).join('');
            } catch (err) {}
        }
        
        fetchCountries();
        loadConfig();
        fetchNodes();
        fetch('/api/config').then(res => res.json()).then(config => restartNodePolling(config.frontend_poll_interval || 5)).catch(() => restartNodePolling(5));
    </script>
</body>
</html>
`;
};
