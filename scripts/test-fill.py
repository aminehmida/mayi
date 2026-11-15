#!/usr/bin/env python3
"""End-to-end test of `mayi fill` with no human and no real account.

Starts a local test site with several kinds of sign-in form, a headless
Chrome with a debugging port (through `mayi browser`), and the development
vault daemon. Then signs in to each form with `mayi fill` and checks, on the
site's side, that the right username, password and two-factor code arrived,
and that nothing secret was printed.

The site checks two-factor codes with its own implementation, separate from
the Rust one.

Usage: scripts/test-fill.py   (after `cargo build`)

To also check what an agent's browser tool would see, point
MAYI_PLAYWRIGHT_DIR at a node_modules folder holding playwright-core.
"""

import base64
import hashlib
import hmac
import http.server
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "debug")
USERNAME = "amine@example.com"
PASSWORD = "hunter2-correct-horse"
TOTP_KEY = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
APPROVE_PASSWORD = "approve-only-pw"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def totp(key, at):
    raw = base64.b32decode(key + "=" * (-len(key) % 8))
    mac = hmac.new(raw, struct.pack(">Q", int(at // 30)), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 1_000_000).zfill(6)


def code_ok(code):
    now = time.time()
    return code in (totp(TOTP_KEY, now), totp(TOTP_KEY, now - 30))


# --- The test site ------------------------------------------------------------

PAGE = """<!doctype html><meta charset=utf-8><title>{title}</title>
<style>body{{font:16px system-ui;margin:40px}} input{{display:block;margin:8px 0;padding:6px}}
.boxes input{{display:inline-block;width:2em;text-align:center}}</style>
<h1>{title}</h1>{body}"""

FORMS = {
    "/simple": ("Sign in", """<form method=post action=/simple>
<label>Email <input name=email type=email autocomplete=username></label>
<label>Password <input name=password type=password autocomplete=current-password></label>
<button>Sign in</button></form>"""),
    "/steps": ("Sign in, step 1", """<form method=post action=/steps>
<label>Email address <input name=email type=email></label><button>Next</button></form>"""),
    "/steps/password": ("Sign in, step 2", """<form method=post action=/steps/password>
<p>Signing in as the address you gave.</p>
<label>Password <input name=password type=password></label><button>Next</button></form>"""),
    "/steps/code": ("Two-factor", """<form method=post action=/steps/code>
<label>Code from your app <input name=code autocomplete=one-time-code inputmode=numeric></label>
<button>Verify</button></form>"""),
    "/boxes": ("Enter your code", """<form method=post action=/boxes id=f>
<div class=boxes>""" + "".join(f"<input maxlength=1 inputmode=numeric aria-label='Digit {i + 1}'>" for i in range(6)) + """</div>
<input type=hidden name=code></form>
<script>
const boxes=[...document.querySelectorAll('.boxes input')];
boxes.forEach((b,i)=>b.addEventListener('input',()=>{
  if(b.value&&i<boxes.length-1)boxes[i+1].focus();
  if(boxes.every(x=>x.value.length===1)){f.code.value=boxes.map(x=>x.value).join('');f.submit();}
}));
</script>"""),
    "/scripted": ("Sign in (scripted)", """<div id=app></div>
<script>
// Like a controlled form in a framework: values live in script state,
// updated only by input events, and Enter posts them.
const state={user:'',pass:''};
app.innerHTML='<label>Username <input id=u autocomplete=username></label>'+
  '<label>Password <input id=p type=password></label>';
u.addEventListener('input',e=>state.user=e.target.value);
p.addEventListener('input',e=>state.pass=e.target.value);
document.addEventListener('keydown',async e=>{
  if(e.key!=='Enter')return;
  const r=await fetch('/scripted',{method:'POST',body:JSON.stringify(state)});
  location=r.ok?'/done':'/failed';
});
</script>"""),
    "/shadow": ("Sign in (shadow DOM)", """<login-box></login-box>
<script>
customElements.define('login-box',class extends HTMLElement{connectedCallback(){
  const root=this.attachShadow({mode:'open'});
  root.innerHTML='<form method=post action=/shadow><label>User <input name=user autocomplete=username></label>'+
    '<label>Password <input name=password type=password></label><button>Go</button></form>';
}});
</script>"""),
    "/decoy": ("Sign in (with a decoy)", """<form method=post action=/decoy>
<label>Email <input name=email type=email></label>
<input name=trap type=password style="position:absolute;left:-9999px" tabindex=-1>
<label>Password <input name=password type=password></label><button>Sign in</button></form>"""),
    "/change": ("Change password", """<form method=post action=/change>
<label>Current password <input name=current type=password></label>
<label>New password <input name=new type=password autocomplete=new-password></label>
<label>Confirm <input name=confirm type=password autocomplete=new-password></label>
<button>Change</button></form>"""),
    "/stuck": ("Sign in (Enter does nothing)", """<form id=f>
<label>Email <input name=email type=email></label>
<label>Password <input name=password type=password></label></form>
<p id=error></p>
<script>f.addEventListener('submit',e=>{e.preventDefault();error.textContent='Something went wrong.';});</script>"""),
    "/button": ("Sign in (button only)", """<label>Email <input id=e type=email></label>
<label>Password <input id=p type=password></label>
<div role=button id=go tabindex=0 style="display:inline-block;padding:6px 12px;border:1px solid">Continue</div>
<script>
go.addEventListener('click',async()=>{
  const r=await fetch('/button',{method:'POST',body:JSON.stringify({user:e.value,pass:p.value})});
  location=r.ok?'/done':'/failed';
});
</script>"""),
    "/done": ("Welcome", "<p>Signed in.</p>"),
    "/failed": ("Failed", "<p>Wrong credentials.</p>"),
}

results = {}
steps = {}


class Site(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_page(self, path):
        title, body = FORMS[path]
        data = PAGE.format(title=title, body=body).encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, to):
        self.send_response(303)
        self.send_header("location", to)
        self.send_header("content-length", "0")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/status":
            data = json.dumps(results).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path in FORMS:
            self.send_page(path)
        else:
            self.send_error(404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length).decode()
        if path in ("/scripted", "/button"):
            data = json.loads(raw or "{}")
            ok = data.get("user") == USERNAME and data.get("pass") == PASSWORD
            results[path[1:]] = ok
            self.send_response(200 if ok else 403)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
        if path == "/steps":
            steps["email"] = form.get("email") == USERNAME
            return self.redirect("/steps/password")
        if path == "/steps/password":
            steps["password"] = form.get("password") == PASSWORD
            return self.redirect("/steps/code")
        if path == "/steps/code":
            results["steps"] = steps.get("email") and steps.get("password") and code_ok(form.get("code", ""))
        elif path == "/simple":
            password = form.get("password")
            results["simple"] = form.get("email") == USERNAME and password == PASSWORD
            results["approved"] = form.get("email") == USERNAME and password == APPROVE_PASSWORD
        elif path == "/boxes":
            results["boxes"] = code_ok(form.get("code", ""))
        elif path == "/shadow":
            results["shadow"] = form.get("user") == USERNAME and form.get("password") == PASSWORD
        elif path == "/decoy":
            results["decoy"] = form.get("email") == USERNAME and form.get("password") == PASSWORD and not form.get("trap")
        elif path == "/change":
            results["change"] = "submitted"
        self.redirect("/done")


# --- Helpers -------------------------------------------------------------------


class Harness:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="mayi-fill-")
        self.site_port = free_port()
        self.cdp_port = free_port()
        self.site = f"http://127.0.0.1:{self.site_port}"
        self.browser = f"http://127.0.0.1:{self.cdp_port}"
        self.env = dict(os.environ, MAYI_HOME=os.path.join(self.tmp, "home"), MAYI_SOCKET="s.sock",
                        XDG_DATA_HOME=os.path.join(self.tmp, "data"), MAYI_BROWSER=self.browser,
                        MAYI_SESSION="fill-test", MAYI_AGENT="test-fill")
        os.makedirs(self.env["MAYI_HOME"])
        self.failures = []
        self.outputs = []
        self.views = []

    def run(self, *args, stdin=None):
        result = subprocess.run([os.path.join(BIN, args[0]), *args[1:]], cwd=self.tmp, env=self.env,
                                input=stdin, capture_output=True, text=True, timeout=90)
        self.outputs.append(result.stdout + result.stderr)
        return result

    def check(self, name, ok, detail=""):
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail and not ok else ''}")
        if not ok:
            self.failures.append(name)

    def cdp(self, path, method="GET"):
        request = urllib.request.Request(self.browser + path, method=method)
        with urllib.request.urlopen(request, timeout=5) as r:
            body = r.read()
        try:
            return json.loads(body)
        except ValueError:
            return body.decode()

    def close_tabs(self):
        for tab in self.cdp("/json/list"):
            if tab["type"] == "page" and tab["url"].startswith("http"):
                self.cdp(f"/json/close/{tab['id']}")

    def open(self, url):
        self.close_tabs()
        tab = self.cdp("/json/new?" + urllib.parse.quote(url, safe=":/?=&"), method="PUT")
        self.wait_for(lambda: self.tab_url(tab["id"]) == url, f"{url} to load")
        time.sleep(0.4)
        return tab["id"]

    def tab_url(self, tab_id):
        for tab in self.cdp("/json/list"):
            if tab["id"] == tab_id:
                return tab["url"]
        return None

    def wait_for(self, condition, what, seconds=10):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if condition():
                return True
            time.sleep(0.1)
        raise RuntimeError(f"timed out waiting for {what}")

    def field_empty(self, path):
        """Whether the page's password field is empty, judged by the agent's own tool when available."""
        playwright = os.environ.get("MAYI_PLAYWRIGHT_DIR")
        if not playwright:
            return None
        shot = os.path.join(os.environ.get("MAYI_SCREENSHOT_DIR", self.tmp), f"agent-view{path.replace('/', '-')}.png")
        view = subprocess.run(["node", os.path.join(ROOT, "scripts", "agent-view.mjs"), self.browser, self.site + path, shot],
                              env=dict(os.environ, NODE_PATH=playwright), capture_output=True, text=True, timeout=60)
        if view.returncode != 0:
            print(view.stderr[-500:])
            return False
        seen = json.loads(view.stdout)
        self.views.append(seen)
        return PASSWORD not in seen["snapshot"] and PASSWORD not in seen["html"] and PASSWORD not in seen["values"]

    def status(self):
        with urllib.request.urlopen(self.site + "/status", timeout=5) as r:
            return json.loads(r.read())


def main():
    if not os.path.exists(os.path.join(BIN, "mayi")):
        sys.exit("build first: cargo build")
    h = Harness()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", h.site_port), Site)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    daemon = None
    try:
        site = f"127.0.0.1:{h.site_port}"
        print("setup")
        h.check("vault created", h.run("mayi-devd", "init").returncode == 0)
        added = h.run("mayi-devd", "add", "test-login", "--login", "--site", site, "--level", "1",
                      stdin=f"{USERNAME}\n{PASSWORD}\n{TOTP_KEY}\n")
        h.check("login added", added.returncode == 0, added.stderr)
        added = h.run("mayi-devd", "add", "approve-login", "--login", "--site", site, "--level", "3",
                      stdin=f"{USERNAME}\n{APPROVE_PASSWORD}\n\n")
        h.check("level 3 login added", added.returncode == 0, added.stderr)
        h.run("mayi-devd", "add", "PLAIN", "--level", "1", stdin="plain-value\n")

        daemon = subprocess.Popen([os.path.join(BIN, "mayi-devd"), "serve"], cwd=h.tmp, env=h.env,
                                  stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        h.wait_for(lambda: os.path.exists(os.path.join(h.tmp, "s.sock")), "the vault daemon")
        prompts = []
        threading.Thread(target=lambda: [prompts.append(line) for line in daemon.stderr], daemon=True).start()

        started = h.run("mayi", "browser", "--headless", "--port", str(h.cdp_port))
        h.check("mayi browser starts a browser", started.returncode == 0, started.stderr)
        listed = h.run("mayi", "list")
        h.check("mayi list shows the login's site", f"test-login\tlevel 1\tpassword,totp,username\tlogin for {site}" in listed.stdout, listed.stdout)

        print("sign-in forms")
        h.open(h.site + "/simple")
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in to the test site")
        h.check("one-page form", r.returncode == 0 and h.status().get("simple") is True, r.stdout + r.stderr)
        h.check("says what it typed", "Typed the username and password of test-login" in r.stdout, r.stdout)

        h.open(h.site + "/steps")
        for page, field in [("/steps/password", "username"), ("/steps/code", "password"), ("/done", "two-factor code")]:
            r = h.run("mayi", "fill", "test-login", "-r", "Sign in over three pages")
            h.check(f"three pages: the {field}", r.returncode == 0 and f"Typed the {field} of" in r.stdout, r.stdout + r.stderr)
            h.wait_for(lambda: any(t["url"].endswith(page) for t in h.cdp("/json/list")), page)
            time.sleep(0.3)
        h.check("three pages: the site accepted all three", h.status().get("steps") is True, str(h.status()))

        h.open(h.site + "/boxes")
        r = h.run("mayi", "fill", "test-login", "-r", "Enter the two-factor code")
        h.wait_for(lambda: "boxes" in h.status(), "the code to arrive", 5)
        h.check("code split into six boxes", r.returncode == 0 and h.status().get("boxes") is True, r.stdout + r.stderr)

        h.open(h.site + "/scripted")
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in to the scripted form")
        h.wait_for(lambda: "scripted" in h.status(), "the scripted form to post", 5)
        h.check("form driven by input events", r.returncode == 0 and h.status().get("scripted") is True, r.stdout + r.stderr)

        h.open(h.site + "/shadow")
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in inside a web component")
        h.check("form inside shadow DOM", r.returncode == 0 and h.status().get("shadow") is True, r.stdout + r.stderr)

        h.open(h.site + "/decoy")
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in past a decoy field")
        h.check("off-screen decoy left empty", r.returncode == 0 and h.status().get("decoy") is True, r.stdout + r.stderr)

        h.open(h.site + "/button")
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in with a button", "--submit-selector", "#go")
        h.wait_for(lambda: "button" in h.status(), "the button form to post", 5)
        h.check("form submitted by clicking a named button", r.returncode == 0 and h.status().get("button") is True and "clicked #go" in r.stdout, r.stdout + r.stderr)
        results.pop("button")
        h.open(h.site + "/button")
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in with a button")
        h.wait_for(lambda: "button" in h.status(), "the button form to post", 5)
        h.check("form without Enter: its Continue button is found and clicked", r.returncode == 0 and h.status().get("button") is True and 'clicked "Continue"' in r.stdout, r.stdout + r.stderr)

        print("the password never stays in the page")
        for path in ["/stuck"]:
            h.open(h.site + path)
            r = h.run("mayi", "fill", "test-login", "-r", "Sign in where Enter does nothing")
            h.check(f"{path}: reported, after waiting", r.returncode == 65 and "cleared it from the field" in r.stderr, r.stdout + r.stderr)
            empty = h.field_empty(path)
            if empty is None:
                print(f"  skip {path}: the password field is empty again (set MAYI_PLAYWRIGHT_DIR to check)")
            else:
                h.check(f"{path}: the password field is empty again", empty, "the password is still there")

        print("refusals")
        h.open(h.site + "/change")
        r = h.run("mayi", "fill", "test-login", "-r", "Change the password")
        h.check("password change form refused", r.returncode == 65 and "change form" in r.stderr and "change" not in h.status(), r.stderr)

        h.open(f"http://localhost:{h.site_port}/simple")
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in elsewhere")
        h.check("no tab on the login's site", r.returncode == 65 and "no open tab is on a website" in r.stderr, r.stderr)
        r = h.run("mayi", "fill", "test-login", "-r", "Sign in elsewhere", "--tab", "localhost")
        h.check("another host refused", r.returncode == 65 and f"is for {site}" in r.stderr, r.stderr)

        r = h.run("mayi", "run", "-s", "P=test-login/password", "-r", "read it", "--", "env")
        h.check("a login cannot go to a command", r.returncode == 77 and "is a login" in r.stderr, r.stderr)
        r = h.run("mayi", "fill", "PLAIN", "-r", "fill a plain secret")
        h.check("a plain secret cannot be typed into a page", r.returncode == 64 and "is not a login" in r.stderr, r.stderr)

        print("approval")
        h.open(h.site + "/simple")
        prompts.clear()

        def approve():
            h.wait_for(lambda: any("approval needed" in line for line in prompts), "the approval prompt", 20)
            daemon.stdin.write("o\n")
            daemon.stdin.flush()

        threading.Thread(target=approve, daemon=True).start()
        r = h.run("mayi", "fill", "approve-login", "-r", "Sign in after approval")
        shown = "".join(prompts)
        h.check("level 3 waits for approval, then fills", r.returncode == 0 and h.status().get("approved") is True, r.stdout + r.stderr)
        h.check("the prompt shows the site", f"sign in: http://{site}" in shown and "types username, password" in shown, shown)

        h.open(h.site + "/simple")
        prompts.clear()
        threading.Thread(target=lambda: (h.wait_for(lambda: any("approval needed" in l for l in prompts), "prompt", 20),
                                         daemon.stdin.write("d\n"), daemon.stdin.flush()), daemon=True).start()
        r = h.run("mayi", "fill", "approve-login", "-r", "Sign in, to be denied", "--tab", "simple", "--session", "other")
        h.check("a denial types nothing", r.returncode == 77, r.stdout + r.stderr)

        if h.views:
            print("what the agent's browser tool sees")
            h.check("the username is visible to the agent", any(USERNAME in v["snapshot"] for v in h.views))
            h.check("no password in any snapshot, HTML or accessibility tree",
                    all(PASSWORD not in json.dumps(v) for v in h.views))

        print("nothing secret printed")
        code_now = totp(TOTP_KEY, time.time())
        everything = "".join(h.outputs)
        for name, value in [("password", PASSWORD), ("level 3 password", APPROVE_PASSWORD), ("two-factor key", TOTP_KEY)]:
            h.check(f"no {name} in any output", value not in everything)
        h.check("no current code in any output", code_now not in everything)
        log = h.run("mayi-devd", "log", "-n", "40").stdout
        h.check("the audit log records sign-ins by site", f"sign in to: http://{site}" in log, log[-500:])
        h.check("the audit log holds no value", PASSWORD not in log and TOTP_KEY not in log)
    finally:
        if daemon:
            daemon.terminate()
        subprocess.run(["pkill", "-f", h.env["XDG_DATA_HOME"]], capture_output=True)
        server.shutdown()
        time.sleep(0.5)
        shutil.rmtree(h.tmp, ignore_errors=True)

    print()
    if h.failures:
        print(f"{len(h.failures)} failed: {', '.join(h.failures)}")
        sys.exit(1)
    print("all passed")


if __name__ == "__main__":
    main()
