# reconx.py
# ReconX: Cyber-style WHOIS & DNS Recon Suite (single file)
# Run: streamlit run reconx.py

import sys, os, io, json, csv, socket, ssl, subprocess, platform, datetime, concurrent.futures
import requests
import whois
import dns.resolver
import streamlit as st

# ---------- Page setup & cyber styling ----------
st.set_page_config(page_title="ReconX — Cyber Recon Suite", layout="wide")

CYBER_CSS = """
<style>
/* Background gradient + subtle grid */
html, body, [data-testid="stAppViewContainer"] {
  background: radial-gradient(1200px 600px at 20% 10%, rgba(0,255,204,0.12), transparent 40%),
              radial-gradient(1000px 800px at 80% 20%, rgba(0,136,255,0.10), transparent 45%),
              linear-gradient(135deg, #0b1220 0%, #0f1b2e 50%, #0b1220 100%);
}
* { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
h1,h2,h3 { letter-spacing: .5px; }
.cyber-title {
  font-size: 3.2rem; text-align:center; margin: 0.6rem 0 1.2rem 0;
  color: #00ffcc; text-shadow: 0 0 12px #00ffcc88, 0 0 28px #00ffff44;
}
.cyber-sub { text-align:center; color:#9feaf9; margin-top: -0.5rem; }
.cyber-card {
  border-radius: 18px; padding: 16px 18px; background: rgba(17,28,47,0.65);
  border: 1px solid rgba(0,255,204,0.18); box-shadow: 0 10px 30px rgba(0,0,0,0.35);
}
.cyber-badge {
  display:inline-block; padding:4px 10px; border-radius:12px; margin-right:8px;
  background: linear-gradient(90deg, #00ffcc44, #0088ff44);
  border:1px solid rgba(0,255,204,0.35); color:#aef2ff; font-size:.8rem;
}
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, rgba(0,255,204,0.08), rgba(0,136,255,0.06));
  border-right: 1px solid rgba(0,255,204,0.15);
}
button[kind="primary"] {
  border-radius: 12px !important; box-shadow: 0 0 18px rgba(0,255,204,0.4) !important;
}
input, textarea {
  border-radius: 10px !important; border: 1px solid rgba(0,255,204,0.35) !important;
  background: rgba(8,14,26,0.7) !important; color: #c7f9ff !important;
}
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)
st.markdown('<div class="cyber-title">🔍 ReconX</div>', unsafe_allow_html=True)
st.markdown('<div class="cyber-sub">Advanced WHOIS & DNS Reconnaissance — stylish · smooth · cyber</div>', unsafe_allow_html=True)
st.divider()

# ---------- Helpers ----------
COMMON_PORTS = [
    21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,993,995,1025,1433,1521,2049,2375,
    3000,3128,3306,3389,3541,4444,5060,5432,5601,5900,5985,6379,7001,8080,8081,8443,9000,9200,10000
]

DEFAULT_SUBS = [
    "www","mail","ftp","dev","api","test","staging","admin","portal","cpanel","webmail",
    "blog","m","cdn","shop","assets","beta","app","img","static","docs","support","intranet"
]

def safe_text(x):
    try:
        return json.dumps(x, ensure_ascii=False, default=str)
    except Exception:
        return str(x)

def to_downloads(data_dict):
    # JSON
    json_bytes = json.dumps(data_dict, indent=2, ensure_ascii=False, default=str).encode("utf-8")
    # CSV (flatten naive)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Section","Key","Value"])
    for section, payload in data_dict.items():
        if isinstance(payload, dict):
            for k, v in payload.items():
                writer.writerow([section, k, safe_text(v)])
        elif isinstance(payload, list):
            for i, v in enumerate(payload):
                writer.writerow([section, f"item_{i}", safe_text(v)])
        else:
            writer.writerow([section, "", safe_text(payload)])
    csv_bytes = output.getvalue().encode("utf-8")
    return json_bytes, csv_bytes

# ---------- Recon functions (cached where helpful) ----------
@st.cache_data(ttl=600, show_spinner=False)
def do_whois(domain: str):
    return whois.whois(domain)

@st.cache_data(ttl=600, show_spinner=False)
def dns_records(domain: str, rtypes=None):
    if rtypes is None:
        rtypes = ["A","AAAA","MX","NS","TXT","CAA","CNAME","SOA"]
    out = {}
    for rt in rtypes:
        try:
            ans = dns.resolver.resolve(domain, rt)
            out[rt] = [r.to_text() for r in ans]
        except Exception as e:
            out[rt] = f"Error: {e}"
    return out

@st.cache_data(ttl=600, show_spinner=False)
def resolve_ip(domain: str):
    return socket.gethostbyname(domain)

@st.cache_data(ttl=600, show_spinner=False)
def reverse_ip(ip: str):
    # Free service (rate limited) — may fail if abused.
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
        if r.status_code == 200 and r.text.strip():
            if "error" in r.text.lower():
                return {"error": r.text.strip()}
            return {"domains": [x.strip() for x in r.text.splitlines() if x.strip()]}
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def scan_port(ip: str, port: int, timeout=0.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex((ip, port))
        s.close()
        return port if res == 0 else None
    except Exception:
        return None

def port_scan(ip: str, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        futures = [ex.submit(scan_port, ip, p) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)

@st.cache_data(ttl=600, show_spinner=False)
def ip_geo(ip: str):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query,lat,lon,timezone,reverse,hosting", timeout=15)
        return r.json()
    except Exception as e:
        return {"status":"fail","message": str(e)}

@st.cache_data(ttl=600, show_spinner=False)
def ssl_certificate(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        # Normalize key info
        def dn_to_str(seq):
            return ", ".join("=".join(x) for i in seq for x in i)
        subject = dn_to_str(cert.get("subject", []))
        issuer = dn_to_str(cert.get("issuer", []))
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "san": [x[1] for x in cert.get("subjectAltName", []) if x[0]=="DNS"]
        }
    except Exception as e:
        return {"error": str(e)}

def ping_host(host: str):
    count_flag = "-n" if platform.system().lower().startswith("win") else "-c"
    try:
        res = subprocess.run(["ping", count_flag, "1", host],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
        return {"status": "Alive" if res.returncode == 0 else "Unreachable"}
    except Exception as e:
        return {"status": f"Error: {e}"}

def subdomain_bruteforce(domain: str, wordlist: list, max_workers=200, timeout=0.6):
    found = []
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout

    def try_resolve(sub):
        name = f"{sub}.{domain}".strip()
        try:
            answers = resolver.resolve(name, "A")
            return name, [r.to_text() for r in answers]
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(try_resolve, w.strip()) for w in wordlist if w.strip()]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                found.append({"host": res[0], "A": res[1]})
    return sorted(found, key=lambda x: x["host"])

# ---------- Sidebar controls ----------
with st.sidebar:
    st.markdown("### ⚙️ Recon Controls")
    domain = st.text_input("Target domain", placeholder="example.com")
    run_btn = st.button("Run Recon", use_container_width=True)
    st.markdown("---")

    st.markdown("#### Select modules")
    do_mod_whois = st.checkbox("WHOIS", True)
    do_mod_dns = st.checkbox("DNS Records", True)
    do_mod_subs = st.checkbox("Subdomain Enum", True)
    do_mod_rev = st.checkbox("Reverse IP (hosted domains)", True)
    do_mod_ports = st.checkbox("Port Scan (common)", True)
    do_mod_geo = st.checkbox("IP Geolocation", True)
    do_mod_ssl = st.checkbox("SSL Certificate", True)
    do_mod_ping = st.checkbox("Ping / Alive", True)

    st.markdown("---")
    st.markdown("#### Subdomain options")
    sub_src = st.radio("Wordlist", ["Built-in (quick)", "Upload .txt"])
    uploaded = None
    if sub_src == "Upload .txt":
        uploaded = st.file_uploader("Upload subdomains wordlist (.txt)", type=["txt"])
    max_subs = st.slider("Max words to try", 10, 5000, 500)
    st.caption("Tip: keep it reasonable to avoid rate-limits.")

    st.markdown("---")
    st.markdown("#### Port scan options")
    use_common_ports = st.radio("Ports", ["Common list", "Custom"])
    custom_ports = st.text_input("Custom ports (e.g. 1-1024, 3306, 8080)", value="")

# ---------- Main action ----------
results = {}
if run_btn:
    if not domain.strip():
        st.error("Please enter a domain.")
        st.stop()

    with st.container():
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.markdown(f'<span class="cyber-badge">Target</span> `{domain}`  '
                    f'<span class="cyber-badge">Timestamp</span> `{datetime.datetime.utcnow().isoformat()}Z`',
                    unsafe_allow_html=True)

        # Resolve IP early (many modules need it)
        ip_addr = None
        try:
            ip_addr = resolve_ip(domain)
            st.markdown(f'<span class="cyber-badge">Resolved IP</span> `{ip_addr}`', unsafe_allow_html=True)
            results["resolved_ip"] = ip_addr
        except Exception as e:
            st.warning(f"Could not resolve IP for {domain}: {e}")

        st.markdown("</div>", unsafe_allow_html=True)

    # WHOIS
    if do_mod_whois:
        with st.expander(" WHOIS"):
            try:
                data = do_whois(domain)
                results["whois"] = dict(data)
                st.json(results["whois"])
            except Exception as e:
                results["whois"] = {"error": str(e)}
                st.error(f"WHOIS failed: {e}")

    # DNS Records
    if do_mod_dns:
        with st.expander(" DNS Records"):
            data = dns_records(domain)
            results["dns"] = data
            st.json(data)

    # Subdomain enumeration
    if do_mod_subs:
        with st.expander(" Subdomain Enumeration"):
            # Determine wordlist
            wordlist = []
            if sub_src == "Built-in (quick)":
                wordlist = DEFAULT_SUBS[:max_subs]
            else:
                if uploaded is None:
                    st.info("Upload a .txt wordlist to run subdomain enumeration.")
                else:
                    text = uploaded.read().decode("utf-8", errors="ignore").splitlines()
                    wordlist = text[:max_subs]

            if wordlist:
                with st.spinner(f"Bruteforcing up to {len(wordlist)} subdomains..."):
                    found = subdomain_bruteforce(domain, wordlist)
                results["subdomains"] = found
                if found:
                    st.success(f"Found {len(found)} subdomains")
                    st.table(found)
                else:
                    st.warning("No subdomains found (with the provided wordlist).")

    # Reverse IP
    if do_mod_rev and ip_addr:
        with st.expander(" Reverse IP (hosted domains)"):
            data = reverse_ip(ip_addr)
            results["reverse_ip"] = data
            st.json(data)

    # Port Scan
    if do_mod_ports and ip_addr:
        with st.expander(" Port Scan"):
            if use_common_ports == "Common list":
                ports = COMMON_PORTS
            else:
                # Parse "1-1024, 80,443"
                def parse_ports(s):
                    out = set()
                    for part in s.split(","):
                        part = part.strip()
                        if not part:
                            continue
                        if "-" in part:
                            a,b = part.split("-",1)
                            a,b = int(a), int(b)
                            for p in range(min(a,b), max(a,b)+1):
                                out.add(p)
                        else:
                            out.add(int(part))
                    return sorted(out)
                try:
                    ports = parse_ports(custom_ports)
                except Exception as e:
                    st.error(f"Invalid port list: {e}")
                    ports = []

            if ports:
                with st.spinner(f"Scanning {len(ports)} ports on {ip_addr} ..."):
                    open_ports = port_scan(ip_addr, ports)
                results["open_ports"] = open_ports
                if open_ports:
                    st.success(f"Open ports: {open_ports}")
                else:
                    st.warning("No open ports detected in the selected set.")

    # IP Geo
    if do_mod_geo and ip_addr:
        with st.expander("🗺️ IP Geolocation"):
            geo = ip_geo(ip_addr)
            results["ip_geo"] = geo
            st.json(geo)

    # SSL Certificate
    if do_mod_ssl:
        with st.expander("🔐 SSL Certificate"):
            cert = ssl_certificate(domain)
            results["ssl"] = cert
            st.json(cert)

    # Ping
    if do_mod_ping:
        with st.expander("Ping / Host Alive"):
            p = ping_host(domain if ip_addr is None else ip_addr)
            results["ping"] = p
            st.json(p)

    # Downloads
    st.markdown("### ⬇️ Export Results")
    results["target"] = {"domain": domain, "ip": ip_addr, "time_utc": datetime.datetime.utcnow().isoformat()+"Z"}
    jbytes, cbytes = to_downloads(results)
    st.download_button("Download JSON", jbytes, file_name=f"reconx_{domain}.json", mime="application/json")
    st.download_button("Download CSV", cbytes, file_name=f"reconx_{domain}.csv", mime="text/csv")

# Nice footer
st.markdown("---")
st.caption("ReconX — For authorized security testing only. Built with using Python & Streamlit.")

