# -*- coding: utf-8 -*-
"""
Tesla 订单 / 交付追踪器(本地版)
================================
在你自己的电脑上运行,数据只在本机和特斯拉服务器之间传输,不经过任何第三方。

用法:
    pip install flask curl_cffi
    python tesla_tracker.py
    然后浏览器打开 http://localhost:8756

登录流程(和开源社区的做法一致):
1. 点击"登录特斯拉账号",在弹出的特斯拉官方页面登录
2. 登录成功后页面会跳到一个打不开的 tesla://auth/callback?... 地址(显示错误页是正常的)
3. 从浏览器地址栏 / 开发者工具复制那个完整地址,粘贴回本页面

为什么用 curl_cffi:特斯拉的登录接口会校验 TLS 指纹,
普通 requests 拿到的 token 会被 owner-api 拒绝(403),
curl_cffi 可以模拟真实 Chrome 的握手。

--------------------------------------------------------------------
Tesla Order / Delivery Tracker (local version)
================================
Runs entirely on your own computer; data only travels between this machine
and Tesla's servers, never through any third party.

Usage:
    pip install flask curl_cffi
    python tesla_tracker.py
    then open http://localhost:8756 in your browser

Login flow (matches what the open-source community does):
1. Click "Log in to Tesla account" and sign in on the official Tesla page
   that pops up
2. After a successful login, the page redirects to an unreachable
   tesla://auth/callback?... URL (seeing an error page here is expected)
3. Copy that full URL from the browser address bar / devtools and paste it
   back into this page

Why curl_cffi: Tesla's login endpoint checks the TLS fingerprint of the
client. A token obtained via plain `requests` gets rejected by owner-api
(403). curl_cffi can mimic a real Chrome TLS handshake.
"""

import base64
import hashlib
import json
import os
import re
import time
import urllib.parse
from datetime import datetime

from flask import Flask, request, redirect, render_template_string

try:
    from curl_cffi import requests as http  # 模拟浏览器 TLS 指纹 / mimics a browser's TLS fingerprint
    IMPERSONATE = {"impersonate": "chrome"}
except ImportError:  # 退而求其次,可能会被特斯拉拒绝 / fallback, Tesla may reject the login
    import requests as http
    IMPERSONATE = {}
    print("警告: 未安装 curl_cffi,登录可能被特斯拉拒绝。请运行: pip install curl_cffi")
    # Warning: curl_cffi is not installed, login may be rejected by Tesla. Run: pip install curl_cffi

# ---------------- 常量(来自社区逆向的 Tesla Owner API) ----------------
# ---------------- Constants (from community reverse-engineering of the Tesla Owner API) ----------------
CLIENT_ID = "ownerapi"
REDIRECT_URI = "tesla://auth/callback"
AUTH_URL = "https://auth.tesla.com/oauth2/v3/authorize"
TOKEN_URL = "https://auth.tesla.com/oauth2/v3/token"
SCOPE = "openid email offline_access"
ORDERS_URL = "https://owner-api.teslamotors.com/api/1/users/orders"
TASKS_URL = "https://akamai-apigateway-vfx.tesla.com/tasks"
APP_VERSION = "9.99.9-9999"  # API 不严格校验版本号 / the API doesn't strictly validate the version string
DEVICE_COUNTRY = "CA"        # 按需改成你的地区,如 CN / US / DE / change to your own region as needed, e.g. CN / US / DE
DEVICE_LANGUAGE = "zh"

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TOKEN_FILE = os.path.join(DATA_DIR, "tesla_tokens.json")
STATE_FILE = os.path.join(DATA_DIR, "auth_state.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")

# 在订单 JSON 里递归搜索这些关键字,寻找船名 / 承运信息
# Recursively search the order JSON for these keywords to find vessel name / carrier info
VESSEL_KEY_RE = re.compile(r"vessel|ship|carrier|transport|voyage|freight", re.I)

app = Flask(__name__)


# ---------------- 工具函数 ----------------
# ---------------- Utility functions ----------------
def _load(path, default=None):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def _save(path, obj):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def token_valid(access_token):
    try:
        payload = access_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))["exp"] > time.time() + 60
    except Exception:
        return False


def get_access_token():
    """返回可用的 access_token,过期则自动刷新;没有则返回 None
    Return a usable access_token, refreshing it automatically if expired;
    return None if there is none."""
    tokens = _load(TOKEN_FILE)
    if not tokens:
        return None
    if token_valid(tokens.get("access_token", "")):
        return tokens["access_token"]
    # 刷新 / refresh
    try:
        r = http.post(TOKEN_URL, data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": tokens["refresh_token"],
        }, **IMPERSONATE)
        r.raise_for_status()
        new = r.json()
        tokens["access_token"] = new["access_token"]
        if "refresh_token" in new:
            tokens["refresh_token"] = new["refresh_token"]
        _save(TOKEN_FILE, tokens)
        return tokens["access_token"]
    except Exception as e:
        print("刷新 token 失败:", e)
        return None


def fetch_all(access_token):
    """拉取订单列表 + 每个订单的详细任务数据
    Fetch the order list plus the detailed task data for each order."""
    headers = {"Authorization": f"Bearer {access_token}"}
    r = http.get(ORDERS_URL, headers=headers, **IMPERSONATE)
    r.raise_for_status()
    orders = r.json()["response"]
    result = []
    for order in orders:
        ref = order["referenceNumber"]
        params = urllib.parse.urlencode({
            "deviceLanguage": DEVICE_LANGUAGE,
            "deviceCountry": DEVICE_COUNTRY,
            "referenceNumber": ref,
            "appVersion": APP_VERSION,
        })
        d = http.get(f"{TASKS_URL}?{params}", headers=headers, **IMPERSONATE)
        d.raise_for_status()
        result.append({"order": order, "details": d.json()})
    return result


def flatten(obj, path=""):
    """把嵌套 JSON 拍平成 {路径: 值},方便做变更对比和关键字搜索
    Flatten nested JSON into {path: value}, to make diffing and keyword
    search easier."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{path}[{i}]"))
    else:
        out[path] = obj
    return out


def diff_snapshots(old, new):
    """对比两次抓取,返回 [(路径, 旧值, 新值)]
    Compare two fetched snapshots, returning [(path, old_value, new_value)]."""
    fo, fn = flatten(old), flatten(new)
    changes = []
    for k in sorted(set(fo) | set(fn)):
        if fo.get(k) != fn.get(k):
            changes.append((k, fo.get(k, "—"), fn.get(k, "—")))
    return changes


def find_vessel_hints(snapshot):
    """在订单数据里找疑似船运 / 物流字段
    Look for fields in the order data that look like shipping / logistics info."""
    hints = []
    for k, v in flatten(snapshot).items():
        if VESSEL_KEY_RE.search(k) and v not in (None, "", "N/A"):
            hints.append((k, v))
    return hints


def append_history(snapshot):
    history = _load(HISTORY_FILE, [])
    entry = {"ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "data": snapshot}
    changes = []
    if history:
        changes = diff_snapshots(history[-1]["data"], snapshot)
        if not changes:
            history[-1]["ts_checked"] = entry["ts"]  # 无变化只更新检查时间 / no changes, only update the checked timestamp
            _save(HISTORY_FILE, history)
            return history, []
    entry["changes"] = [list(c) for c in changes]
    history.append(entry)
    _save(HISTORY_FILE, history[-50:])  # 最多留 50 个快照 / keep at most 50 snapshots
    return history, changes


def extract_summary(item):
    """从一个订单条目里提取仪表盘要展示的字段
    Extract the fields the dashboard displays from a single order entry."""
    order = item["order"]
    tasks = item["details"].get("tasks", {})
    reg = tasks.get("registration", {}).get("orderDetails", {})
    sched = tasks.get("scheduling", {})
    pay = tasks.get("finalPayment", {}).get("data", {})
    return {
        "ref": order.get("referenceNumber", "—"),
        "status": order.get("orderStatus", "—"),
        "model": order.get("modelCode", "—").upper(),
        "vin": order.get("vin") or "尚未分配",
        "reserved": reg.get("reservationDate", "—"),
        "booked": reg.get("orderBookedDate", "—"),
        "odometer": f'{reg.get("vehicleOdometer", "—")} {reg.get("vehicleOdometerType", "")}'.strip(),
        "routing": reg.get("vehicleRoutingLocation", "—"),
        "window": sched.get("deliveryWindowDisplay", "—"),
        "eta": pay.get("etaToDeliveryCenter", "—"),
        "appt": sched.get("apptDateTimeAddressStr", "—"),
    }


def voyage_stage(summary):
    """粗略推断车辆处于哪个阶段: 0 已下单 1 生产 2 运输中 3 可预约 4 已排交付
    Roughly infer which stage the vehicle is at:
    0 ordered, 1 in production, 2 in transit, 3 ready to schedule, 4 delivery scheduled."""
    if summary["appt"] not in ("—", None, ""):
        return 4
    if summary["window"] not in ("—", None, ""):
        return 3
    if summary["vin"] != "尚未分配":
        try:
            if float(str(summary["odometer"]).split()[0]) > 0:
                return 2
        except (ValueError, IndexError):
            pass
        return 1
    return 0


# ---------------- 页面模板 ----------------
# ---------------- Page template ----------------
PAGE = """
<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tesla 交付追踪</title>
<style>
:root{
  --ink:#0c1622; --panel:#12202f; --line:#1f3347;
  --fg:#e8f0f6; --dim:#8aa3b8; --cyan:#57cfe0; --amber:#f0b43c; --red:#e2442e;
  --mono:ui-monospace,'Cascadia Code',Consolas,monospace;
}
*{box-sizing:border-box} body{margin:0;background:var(--ink);color:var(--fg);
  font:15px/1.6 -apple-system,'Segoe UI','Microsoft YaHei',sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:28px 18px 60px}
h1{font-size:20px;letter-spacing:.08em;margin:0}
h1 span{color:var(--cyan)}
.sub{color:var(--dim);font-size:13px;margin:2px 0 24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:18px 20px;margin-bottom:16px}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
.pill{font:600 12px var(--mono);padding:3px 10px;border-radius:99px;
  border:1px solid var(--cyan);color:var(--cyan)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px;margin-top:14px}
.k{color:var(--dim);font-size:12px;letter-spacing:.05em}
.v{font-family:var(--mono);font-size:14px;word-break:break-all}
/* 航线进度 —— signature / voyage progress — signature */
.voyage{display:flex;align-items:center;margin:22px 4px 6px}
.stop{flex:0 0 auto;text-align:center;width:74px}
.dot{width:12px;height:12px;border-radius:50%;border:2px solid var(--dim);margin:0 auto 6px;background:var(--ink)}
.stop.done .dot{background:var(--cyan);border-color:var(--cyan)}
.stop.now .dot{background:var(--red);border-color:var(--red);box-shadow:0 0 0 5px rgba(226,68,46,.18)}
.leg{flex:1;border-top:2px dashed var(--line);margin-bottom:22px}
.leg.done{border-top:2px solid var(--cyan)}
.stop small{color:var(--dim);font-size:11px}
.stop.now small{color:var(--fg)}
button,.btn{background:var(--cyan);color:#04222a;border:0;border-radius:8px;
  padding:9px 18px;font:600 14px inherit;cursor:pointer;text-decoration:none;display:inline-block}
button.ghost,.btn.ghost{background:transparent;color:var(--cyan);border:1px solid var(--cyan)}
input[type=text]{width:100%;background:var(--ink);border:1px solid var(--line);border-radius:8px;
  color:var(--fg);padding:9px 12px;font:13px var(--mono);margin:8px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
td{padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}
td.path{font-family:var(--mono);color:var(--dim);font-size:12px}
.old{color:var(--red);text-decoration:line-through}
.new{color:var(--cyan)}
details summary{cursor:pointer;color:var(--dim);font-size:13px}
pre{background:var(--ink);border:1px solid var(--line);border-radius:8px;
  padding:12px;overflow:auto;max-height:420px;font:12px var(--mono)}
.warn{color:var(--amber);font-size:13px}
a{color:var(--cyan)}
.err{border-color:var(--red)} .err .k{color:var(--red)}
@media(max-width:560px){.stop{width:56px}.stop small{font-size:10px}}
</style></head><body><div class="wrap">
<h1>TESLA <span>交付追踪</span></h1>
<p class="sub">本地运行 · 数据仅保存在你自己的电脑 · {{ now }}</p>

{% if error %}<div class="card err"><span class="k">出错了</span>
<div class="v" style="margin-top:6px">{{ error }}</div></div>{% endif %}

{% if not logged_in %}
  <div class="card">
    <b>第一步</b> — 点击下面按钮,在特斯拉官方页面登录你的账号:<br><br>
    <a class="btn" href="{{ auth_url }}" target="_blank">登录特斯拉账号 ↗</a>
    <p class="warn">重要:点登录之前,先在新打开的特斯拉页面按 <b>F12</b> 打开开发者工具并切到
    <b>Console(控制台)</b> 标签。登录成功后浏览器会尝试跳转
    <code>tesla://auth/callback?code=...</code>(打不开是正常的),
    控制台里会出现一条 <code>Failed to launch 'tesla://auth/callback?code=...'</code>
    的报错——把里面这个 tesla:// 开头的完整地址复制出来。
    (Network/网络 标签里最后一个请求的 location 响应头里也能找到)</p>
    <b>第二步</b> — 把复制的完整地址粘贴到这里:
    <form method="post" action="/callback">
      <input type="text" name="redirect_url" placeholder="tesla://auth/callback?code=..." required>
      <button type="submit">完成登录</button>
    </form>
  </div>
{% else %}
  <form method="post" action="/fetch" style="margin-bottom:16px">
    <button type="submit">↻ 拉取最新数据</button>
    <a class="btn ghost" href="/logout" onclick="return confirm('确定退出登录并删除本地 token?')">退出登录</a>
  </form>

  {% for s in summaries %}
  <div class="card">
    <div class="row">
      <div><b style="font-size:17px">{{ s.model }}</b>
        <span class="v" style="color:var(--dim)"> {{ s.ref }}</span></div>
      <span class="pill">{{ s.status }}</span>
    </div>
    <div class="voyage">
      {% set names = ['已下单','工厂生产','运输途中','可约交付','交付预约'] %}
      {% for i in range(5) %}
        <div class="stop {{ 'done' if i < s.stage else ('now' if i == s.stage else '') }}">
          <div class="dot"></div><small>{{ names[i] }}</small>
        </div>
        {% if i < 4 %}<div class="leg {{ 'done' if i < s.stage }}"></div>{% endif %}
      {% endfor %}
    </div>
    <div class="grid">
      <div><div class="k">VIN</div><div class="v">{{ s.vin }}</div></div>
      <div><div class="k">交付窗口</div><div class="v">{{ s.window }}</div></div>
      <div><div class="k">到达交付中心 ETA</div><div class="v">{{ s.eta }}</div></div>
      <div><div class="k">交付预约</div><div class="v">{{ s.appt }}</div></div>
      <div><div class="k">里程表</div><div class="v">{{ s.odometer }}</div></div>
      <div><div class="k">路由地点代码</div><div class="v">{{ s.routing }}</div></div>
      <div><div class="k">下订日期</div><div class="v">{{ s.booked }}</div></div>
      <div><div class="k">预订日期</div><div class="v">{{ s.reserved }}</div></div>
    </div>
  </div>
  {% endfor %}

  <div class="card">
    <b>🚢 船运线索</b>
    {% if vessels %}
      <table>{% for k, v in vessels %}
        <tr><td class="path">{{ k }}</td>
        <td class="v">{{ v }} — <a target="_blank"
          href="https://www.vesselfinder.com/vessels?name={{ v|urlencode }}">在 VesselFinder 查船位 ↗</a></td></tr>
      {% endfor %}</table>
    {% else %}
      <p class="warn">当前订单数据里没找到船名 / 承运商字段。北美本地生产的车通常走卡车或火车,
      不会有海运信息;海运订单(如上海/柏林发货)的字段一般在临近发船时才出现。</p>
    {% endif %}
    <div class="k" style="margin-top:10px">手动查船(输入船名):</div>
    <form onsubmit="window.open('https://www.vesselfinder.com/vessels?name='+encodeURIComponent(this.q.value));return false"
      style="display:flex;gap:8px">
      <input type="text" name="q" placeholder="例如 Glovis Splendor">
      <button type="submit">查询</button>
    </form>
  </div>

  <div class="card">
    <b>📋 变更记录</b>
    {% if history %}
      {% for h in history|reverse %}
        {% if h.get('changes') %}
        <p class="k" style="margin:12px 0 4px">{{ h.ts }}</p>
        <table>{% for c in h.changes %}
          <tr><td class="path">{{ c[0] }}</td>
          <td><span class="old">{{ c[1] }}</span> → <span class="new">{{ c[2] }}</span></td></tr>
        {% endfor %}</table>
        {% endif %}
      {% endfor %}
      {% if not has_changes %}<p class="warn">暂无变更(首个快照已保存,之后每次"拉取最新数据"都会自动对比)。</p>{% endif %}
    {% else %}<p class="warn">还没有数据,点上面"拉取最新数据"。</p>{% endif %}
  </div>

  {% if raw %}
  <div class="card"><details><summary>查看完整原始 JSON(高级)</summary>
    <pre>{{ raw }}</pre></details></div>
  {% endif %}
{% endif %}
</div></body></html>
"""


# ---------------- 路由 ----------------
# ---------------- Routes ----------------
@app.route("/")
def index():
    logged_in = get_access_token() is not None
    auth_url = None
    if not logged_in:
        verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        _save(STATE_FILE, {"verifier": verifier})
        auth_url = AUTH_URL + "?" + urllib.parse.urlencode({
            "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI,
            "response_type": "code", "scope": SCOPE,
            "state": os.urandom(8).hex(),
            "code_challenge": challenge, "code_challenge_method": "S256",
        })

    history = _load(HISTORY_FILE, [])
    latest = history[-1]["data"] if history else []
    summaries = []
    for item in latest:
        s = extract_summary(item)
        s["stage"] = voyage_stage(s)
        summaries.append(s)

    return render_template_string(
        PAGE, logged_in=logged_in, auth_url=auth_url,
        summaries=summaries,
        vessels=find_vessel_hints(latest),
        history=history,
        has_changes=any(h.get("changes") for h in history),
        raw=json.dumps(latest, ensure_ascii=False, indent=2) if latest else None,
        error=request.args.get("error"),
        now=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


@app.route("/callback", methods=["POST"])
def callback():
    try:
        url = request.form["redirect_url"].strip()
        code = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["code"][0]
        verifier = _load(STATE_FILE, {}).get("verifier")
        r = http.post(TOKEN_URL, data={
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }, **IMPERSONATE)
        r.raise_for_status()
        _save(TOKEN_FILE, r.json())
        return redirect("/")
    except Exception as e:
        return redirect("/?error=" + urllib.parse.quote(f"登录失败: {e}"))


@app.route("/fetch", methods=["POST"])
def fetch():
    token = get_access_token()
    if not token:
        return redirect("/?error=" + urllib.parse.quote("登录已过期,请重新登录"))
    try:
        snapshot = fetch_all(token)
        append_history(snapshot)
        return redirect("/")
    except Exception as e:
        return redirect("/?error=" + urllib.parse.quote(f"拉取数据失败: {e}"))


@app.route("/logout")
def logout():
    for f in (TOKEN_FILE, STATE_FILE):
        if os.path.exists(f):
            os.remove(f)
    return redirect("/")


if __name__ == "__main__":
    print("\n  Tesla 交付追踪器已启动 → 浏览器打开  http://localhost:8756\n")
    app.run(host="127.0.0.1", port=8756, debug=False)
