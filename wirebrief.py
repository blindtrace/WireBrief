#!/usr/bin/env python3
"""
WireBrief - runs tshark and builds a forensic report (HTML + Markdown) from a PCAP.

Usage:
    python3 wirebrief.py capture.pcapng -o report_out
    python3 wirebrief.py capture.pcapng -o report_out --allowlist allowlist.txt
Requirements: Python 3.8+ and tshark in PATH. No external libraries.
"""
import argparse, hashlib, html, ipaddress, math, re, statistics, subprocess, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ALLOW_DOMAINS = """ocsp.pki.goog
ocsp.digicert.com
ocsp.sectigo.com
ocsp.godaddy.com
ocsp.globalsign.com
ocsp.amazontrust.com
lencr.org
phicdn.net
googlesyndication.com
doubleclick.net
google-analytics.com
googletagmanager.com
googletagservices.com
googleadservices.com
gstatic.com
googleapis.com
googlevideo.com
ytimg.com
ggpht.com
criteo.com
criteo.net
creativecdn.com
rubiconproject.com
pubmatic.com
adnxs.com
casalemedia.com
smartadserver.com
3lift.com
openx.net
openxcdn.net
lijit.com
id5-sync.com
crwdcntrl.net
rlcdn.com
adsrvr.org
bidswitch.net
smilewanted.com
vlitag.com
vliplatform.com
a-mo.net
amazon-adsystem.com
mozilla.com
mozilla.net
mozgcp.net
akamaiedge.net
akamai.net
cloudflareinsights.com
"""

STD_PORTS = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139, 143, 389, 443,
             445, 465, 514, 587, 993, 995, 1433, 3306, 3389, 5353, 5432, 8080, 8443}
WATCH = ["pastebin.com", "paste.ee", "hastebin.com", "ghostbin", "transfer.sh", "anonfiles",
         "ngrok", "duckdns.org", "no-ip", "ddns.net", "trycloudflare.com", "githubusercontent.com",
         "telegram.org", "discord", "bit.ly", ".onion", "mega.nz", "temp.sh"]
EXEC_EXT = r"\.(exe|dll|ps1|bat|vbs|hta|scr|msi|jar|sh|elf|bin)(\?|$)"
WEB_EXT = r"\.(php|asp|aspx|jsp|cgi)(\?|$)"
SCRIPT_UA = re.compile(r"(python|curl|wget|powershell|go-http|java/|libwww|MSIE [4-6]\.)", re.I)
esc = html.escape


# ───────────────────────── helpers ─────────────────────────
def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "tshark failed")
    return p.stdout


def fields(pcap, flt, flds):
    cmd = ["tshark", "-r", pcap, "-n", "-Y", flt, "-T", "fields", "-E", "separator=/t",
           "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in flds:
        cmd += ["-e", f]
    out = []
    for line in run(cmd).splitlines():
        r = line.split("\t")
        out.append(r + [""] * (len(flds) - len(r)))
    return out


def first(s):
    return s.split(",")[0] if s else ""


def internal(ip):
    try:
        p = ipaddress.ip_address(ip)
        return p.is_private and not (p.is_multicast or p.is_unspecified or p.is_loopback
                                     or ip == "255.255.255.255")
    except ValueError:
        return False


def hb(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def ts(t):
    return datetime.fromtimestamp(float(t), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def entropy(s):
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) if s else 0


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""):
            h.update(ch)
    return h.hexdigest()


# ───────────────────────── data collection ─────────────────────────
def collect_flows(pcap):
    cols = ["frame.time_epoch", "ip.src", "ip.dst", "ip.proto", "tcp.stream", "tcp.srcport",
            "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.flags", "frame.len", "_ws.col.Protocol"]
    rows = fields(pcap, "ip", cols)
    protos, pbytes, sent, recv = Counter(), Counter(), Counter(), Counter()
    flows, t0, t1, nbytes = {}, None, None, 0
    for t, src, dst, pr, sid, tsp, tdp, usp, udp, fl, ln, col in rows:
        try:
            t, ln = float(t), int(first(ln))
        except ValueError:
            continue
        src, dst = first(src), first(dst)
        t0 = t if t0 is None else min(t0, t)
        t1 = t if t1 is None else max(t1, t)
        nbytes += ln
        protos[col] += 1
        pbytes[col] += ln
        sent[src] += ln
        recv[dst] += ln
        sp, dp = first(tsp) or first(usp), first(tdp) or first(udp)
        if not sp or not dp:
            continue
        sp, dp = int(sp), int(dp)
        kind = "TCP" if first(tsp) else "UDP"
        key = ("t", first(sid)) if kind == "TCP" else ("u",) + tuple(sorted([(src, sp), (dst, dp)]))
        f = flows.setdefault(key, {"proto": kind, "first": (src, sp, dst, dp), "syn": None,
                                   "b": defaultdict(int), "n": 0, "t0": t, "t1": t})
        f["b"][(src, sp)] += ln
        f["n"] += 1
        f["t1"] = max(f["t1"], t)
        try:
            if int(first(fl), 16) & 0x12 == 0x02 and not f["syn"]:
                f["syn"] = (src, sp, dst, dp)
        except ValueError:
            pass
    out = []
    for f in flows.values():
        c = f["syn"] or f["first"]
        out.append({"proto": f["proto"], "cip": c[0], "cport": c[1], "sip": c[2], "sport": c[3],
                    "c2s": f["b"][(c[0], c[1])], "s2c": f["b"][(c[2], c[3])], "n": f["n"],
                    "t0": f["t0"], "dur": f["t1"] - f["t0"]})
    return out, protos, pbytes, sent, recv, {"frames": len(rows), "bytes": nbytes, "t0": t0, "t1": t1}


def collect_dns(pcap):
    cols = ["frame.time_epoch", "ip.src", "ip.dst", "dns.flags.response", "dns.qry.name",
            "dns.a", "dns.flags.rcode"]
    q, nx, ipmap = Counter(), Counter(), defaultdict(set)
    for t, s, d, resp, name, a, rc in fields(pcap, "dns", cols):
        name = name.split(",")[0].lower()
        if not name:
            continue
        if resp in ("1", "True", "true"):
            for ip in filter(None, a.split(",")):
                ipmap[ip].add(name)
            if rc == "3":
                nx[name] += 1
        else:
            q[name] += 1
    return q, nx, ipmap


def collect_http(pcap):
    cols = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "http.host",
            "http.request.method", "http.request.uri", "http.user_agent"]
    return [[first(x) for x in r] for r in fields(pcap, "http.request", cols)]


def collect_tls(pcap):
    base = ["ip.src", "ip.dst", "tls.handshake.extensions_server_name"]
    try:
        rows = fields(pcap, "tls.handshake.type == 1", base + ["tls.handshake.ja3"])
    except RuntimeError:
        rows = [r + [""] for r in fields(pcap, "tls.handshake.type == 1", base)]
    return [[first(x) for x in r] for r in rows]


def extract_files(pcap, outdir):
    d = outdir / "raw" / "extracted"
    d.mkdir(parents=True, exist_ok=True)
    try:
        run(["tshark", "-r", pcap, "-n", "-q", "--export-objects", f"http,{d}"])
    except RuntimeError:
        return []
    seen = {}
    for p in sorted(d.iterdir()):
        if not p.is_file():
            continue
        h = sha256(p)
        stem = re.sub(r"\(\d+\)(?=(\.\w+)?$)", "", p.name)
        e = seen.setdefault(h, {"hash": h, "name": stem, "size": p.stat().st_size, "count": 0, "path": p})
        e["count"] += 1
    return list(seen.values())


def magic(path):
    with open(path, "rb") as f:
        b = f.read(8)
    if b[:2] == b"MZ": return "Windows PE (EXE/DLL)"
    if b[:4] == b"\x7fELF": return "Linux ELF"
    if b[:2] == b"PK": return "ZIP/Office/JAR"
    if b[:4] == b"%PDF": return "PDF"
    if b[:5].lower() in (b"<?php", b"<html") or b[:2] == b"#!": return "Text/script"
    if b[:2] == b"\x30\x82": return "DER (likely OCSP/cert)"
    return "Unknown"


# ───────────────────────── analysis ─────────────────────────
class Report:
    def __init__(self):
        self.sections, self.findings, self.iocs = [], [], {}

    def sec(self, title):
        self.sections.append((title, []))
        return self.sections[-1][1]

    def find(self, sev, title, detail, evidence="", mitre=""):
        self.findings.append((sev, title, detail, evidence, mitre))

    def ioc(self, typ, val, ctx):
        self.iocs.setdefault((typ, val), ctx)


def main():
    ap = argparse.ArgumentParser(prog="wirebrief", description="WireBrief: from raw PCAP to analyst-ready report, powered by tshark.")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--allowlist", default="allowlist.txt")
    a = ap.parse_args()
    pcap = a.pcap
    out = Path(a.out or f"report_{datetime.now():%Y-%m-%d}")
    (out / "raw").mkdir(parents=True, exist_ok=True)

    al = Path(a.allowlist)
    if not al.exists():
        al.write_text("# Allowlist: any domain ending with one of these is treated as noise. One suffix per line.\n"
                      + ALLOW_DOMAINS, encoding="utf-8")
    allow = [x.strip().lower() for x in al.read_text(encoding="utf-8").splitlines()
             if x.strip() and not x.startswith("#")]

    def noisy(d):
        d = (d or "").lower()
        return bool(d) and any(d == s or d.endswith("." + s) for s in allow)

    print("[1/6] tshark: packets and flows ..."); sys.stdout.flush()
    flows, protos, pbytes, sent, recv, meta = collect_flows(pcap)
    print("[2/6] DNS ..."); q, nx, dnsmap = collect_dns(pcap)
    print("[3/6] HTTP ..."); http = collect_http(pcap)
    print("[4/6] TLS ..."); tls = collect_tls(pcap)
    print("[5/6] extracting files ..."); files = extract_files(pcap, out)
    for name, args in [("io_stat", ["-z", "io,stat,0"]), ("protocol_hierarchy", ["-z", "io,phs"]),
                       ("endpoints_ip", ["-z", "endpoints,ip"]), ("conversations_tcp", ["-z", "conv,tcp"])]:
        try:
            (out / "raw" / f"{name}.txt").write_text(run(["tshark", "-r", pcap, "-n", "-q"] + args))
        except RuntimeError:
            pass

    sni_map = {d: n.lower() for s, d, n, j in tls if n}

    def dom(ip):
        return sni_map.get(ip) or (sorted(dnsmap[ip])[0] if dnsmap.get(ip) else "")

    R = Report()
    print("[6/6] analysis and report ...")
    YES = "yes"

    # ---- 1
    s = R.sec("1. Case Information & Evidence Integrity")
    s.append(("t", ["Field", "Value"], [
        ["File name", Path(pcap).name], ["SHA256", sha256(pcap)],
        ["Analysis date (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")],
        ["Tool", run(["tshark", "--version"]).splitlines()[0]]]))
    s.append(("p", "Analysis was performed read-only on the original file. Raw tshark outputs are saved in the raw folder."))
    sum_idx = len(R.sections)
    R.sec("")  # filled at the end

    # ---- 3
    s = R.sec("3. Capture Overview")
    dur = (meta["t1"] or 0) - (meta["t0"] or 0)
    s.append(("t", ["Item", "Value"], [
        ["First packet (UTC)", ts(meta["t0"])],
        ["Last packet (UTC)", ts(meta["t1"])],
        ["Duration", f"{dur:.1f} seconds"],
        ["Packets (IPv4)", f"{meta['frames']:,}"],
        ["Size", hb(meta["bytes"])],
        ["Flows", f"{len(flows):,}"]]))
    s.append(("p", "Protocol distribution (top-most protocol per packet):"))
    s.append(("t", ["Protocol", "Packets", "Bytes", "%"],
              [[p, (f"{c:,}", c), (hb(pbytes[p]), pbytes[p]), f"{c / max(meta['frames'], 1) * 100:.1f}"]
               for p, c in protos.most_common(12)]))

    # ---- 4
    s = R.sec("4. Internal Hosts & Conversations")
    ips = {ip for ip in list(sent) + list(recv) if internal(ip)}
    peers = defaultdict(set)
    for f in flows:
        peers[f["cip"]].add(f["sip"]); peers[f["sip"]].add(f["cip"])
    s.append(("p", "Private hosts seen in the capture:"))
    s.append(("t", ["Host", "Sent", "Received",
                    "Distinct peers"],
              [[ip, (hb(sent[ip]), sent[ip]), (hb(recv[ip]), recv[ip]), (str(len(peers[ip])), len(peers[ip]))]
               for ip in sorted(ips, key=lambda x: -(sent[x] + recv[x]))]))
    grp = defaultdict(lambda: [0, 0, 0, 1e18])
    for f in flows:
        if internal(f["cip"]) and internal(f["sip"]):
            g = grp[(f["cip"], f["sip"], f["sport"], f["proto"])]
            g[0] += 1; g[1] += f["c2s"]; g[2] += f["s2c"]; g[3] = min(g[3], f["t0"])
    s.append(("p", "Internal conversations (host to host). Each row is grouped by client, server and port. "
                     "Client = the side that opened the connection (first SYN); server = the side listening on the port."))
    rows = []
    for (c, sv, sp, pr), (n, c2s, s2c, t0) in sorted(grp.items(), key=lambda x: x[1][3]):
        odd = sp not in STD_PORTS
        rows.append([c, sv, (str(sp), sp, "hi" if odd else ""), pr, (str(n), n),
                     (hb(c2s), c2s), (hb(s2c), s2c), ts(t0)])
        if odd:
            R.find("high", "Internal connection on a non-standard port",
                   f"{c} connected to {sv} on {pr}/{sp} ({n} connections, sent {hb(c2s)}, received {hb(s2c)}).",
                   f"flow {c} -> {sv}:{sp}", "T1021 / T1571 (Non-Standard Port)")
            R.ioc("IP (internal)", sv, f"server on non-standard port {sp}")
    s.append(("t", ["Client", "Server", "Server port",
                    "Proto", "Connections",
                    "Client → Server", "Server → Client",
                    "First seen (UTC)"], rows))

    # ---- 5
    s = R.sec("5. Top External Destinations (grouped by IP and domain)")
    ext = defaultdict(lambda: [0, 0, 0])
    for f in flows:
        if not internal(f["sip"]):
            g = ext[(f["sip"], f["proto"])]
            g[0] += 1; g[1] += f["c2s"]; g[2] += f["s2c"]
    s.append(("p", "An IP repeats because each conversation row is one connection and browsers open many parallel "
                     "connections to the same server. Here they are grouped, with the connection count per IP."))
    main_rows, noise_rows = [], []
    for (ip, pr), (n, c2s, s2c) in sorted(ext.items(), key=lambda x: -(x[1][1] + x[1][2])):
        d = dom(ip)
        row = [ip, d or "-", pr, (str(n), n), (hb(c2s), c2s), (hb(s2c), s2c)]
        (noise_rows if noisy(d) else main_rows).append(row)
        if not noisy(d) and c2s >= 1_000_000 and c2s > 3 * s2c:
            R.find("high", "Large upload to an external host",
                   f"{ip} ({d or 'no domain'}): sent {hb(c2s)} vs received {hb(s2c)}.",
                   ip, "T1041 (Exfiltration Over C2)")
            R.ioc("IP", ip, "large upload")
    hd = ["Server IP", "Domain", "Proto",
          "Connections", "Sent", "Received"]
    s.append(("t", hd, main_rows[:60]))
    s.append(("d", f"Known noise (ads/CDN/OCSP) - {len(noise_rows)} rows", hd, noise_rows))

    # ---- 6
    s = R.sec("6. DNS Analysis")
    s.append(("p", f"Total queries: {sum(q.values()):,} across {len(q):,} distinct domains."))
    s.append(("t", ["Domain", "Queries", "Noise?"],
              [[d, (str(c), c), YES if noisy(d) else ""] for d, c in q.most_common(25)]))
    if nx:
        s.append(("p", "Failed lookups (NXDOMAIN):"))
        s.append(("t", ["Domain", "Count"], [[d, (str(c), c)] for d, c in nx.most_common(20)]))
        if sum(nx.values()) >= 10:
            R.find("medium", "High number of NXDOMAIN responses",
                   f"{sum(nx.values())} failed lookups.",
                   ", ".join(list(nx)[:5]), "T1568.002 (DGA)")
    odd = []
    for d, c in q.items():
        lab_ = d.split(".")[0]
        if not noisy(d) and (len(d) > 50 or (len(lab_) >= 12 and entropy(lab_) > 3.6)):
            odd.append([d, f"{entropy(lab_):.2f}", (str(len(d)), len(d))])
            R.find("medium", "Random-looking or long domain name",
                   f"{d} (entropy {entropy(lab_):.2f}).", d, "T1568 / T1071.004")
            R.ioc("Domain", d, "random-looking name")
    s.append(("p", "Long or random-looking domains (after allowlist filtering):"))
    s.append(("t", ["Domain", "Entropy", "Length"], odd))
    for d in set(q) | set(sni_map.values()):
        if any(w in d for w in WATCH):
            R.find("medium", "Domain on the watchlist",
                   f"{d} (paste/file-sharing/tunnel service).", d, "T1102 / T1567")
            R.ioc("Domain", d, "watchlist")

    # ---- 7
    s = R.sec("7. HTTP Analysis (cleartext)")
    is_ocsp = lambda h, u: "ocsp" in h or h.startswith(("status.", "r3.o.lencr")) or re.match(r"^/(s/)?gts", u)
    keep, ocsp_n, ocsp_names = [], Counter(), set()
    for no, t, src, dst, host, m, uri, ua in http:
        if is_ocsp(host, uri) or noisy(host):
            ocsp_n[host] += 1; ocsp_names.add(uri.rstrip("/").split("/")[-1] or "%2f")
            continue
        keep.append([no, ts(t), src, dst, host, m, uri[:80], ua[:50]])
        path = uri.split("?")[0]
        if re.search(EXEC_EXT, uri, re.I):
            R.find("high", "Executable/script download over HTTP",
                   f"{src} requested {host}{path}.", f"frame {no}",
                   "T1105 (Ingress Tool Transfer)")
            R.ioc("URL", f"hxxp://{host}{path}", "executable")
        elif re.search(WEB_EXT, uri, re.I):
            where = "internal" if internal(dst) else "external"
            R.find("medium", f"Web script requested over HTTP ({where})",
                   f"{src} -> {host}{path} ({m}). Response content needs manual review.", f"frame {no}", "T1071.001")
            R.ioc("URL", f"hxxp://{host}{path}", "web script")
        if re.fullmatch(r"[\d.]+(:\d+)?", host) and not internal(dst):
            R.find("medium", "HTTP to a direct IP address",
                   f"{src} -> {host}{path}", f"frame {no}", "T1071.001")
        if m == "POST" and not internal(dst):
            R.find("medium", "Cleartext POST to an external host",
                   f"{src} -> {host}{path}", f"frame {no}", "T1048")
        if SCRIPT_UA.search(ua):
            R.find("medium", "Unusual User-Agent", f"{src}: {ua}", f"frame {no}", "T1071.001")
    s.append(("p", f"HTTP requests (excluding OCSP and noise): {len(keep)}. Hidden: {sum(ocsp_n.values())} OCSP/noise requests."))
    s.append(("t", ["Frame", "Time", "Client", "Server", "Host",
                    "Method", "URI", "User-Agent"], keep[:200]))
    s.append(("d", "OCSP/noise requests by host",
              ["Host", "Count"], [[h, (str(c), c)] for h, c in ocsp_n.most_common()]))

    # ---- 8
    s = R.sec("8. TLS Analysis (SNI server names)")
    sn = Counter(n.lower() for _, _, n, _ in tls if n)
    s.append(("t", ["SNI", "Count", "Noise?"],
              [[n, (str(c), c), YES if noisy(n) else ""] for n, c in
               sorted(sn.items(), key=lambda x: (noisy(x[0]), -x[1]))[:80]]))
    ja = Counter(j for *_, j in tls if j)
    if ja:
        s.append(("d", "Client JA3 fingerprints", ["JA3", "Count"],
                  [[j, (str(c), c)] for j, c in ja.most_common(15)]))

    # ---- 9
    s = R.sec("9. Unusual Internal Connections")
    s.append(("p", "This means connections between internal hosts on non-standard ports, or HTTP to an internal server. "
                     "See section 4 (odd ports are highlighted in red) and the findings in section 12."))

    # ---- 10
    s = R.sec("10. Beaconing Detection")
    gb = defaultdict(list)
    for f in flows:
        if not noisy(dom(f["sip"])):
            gb[(f["cip"], f["sip"], f["sport"], f["proto"])].append(f["t0"])
    brow = []
    for (c, sv, sp, pr), tl in gb.items():
        if len(tl) < 6:
            continue
        tl.sort()
        iv = [b - a for a, b in zip(tl, tl[1:])]
        m = statistics.mean(iv)
        cv = statistics.pstdev(iv) / m if m else 9
        if m >= 3 and cv < 0.25:
            brow.append([c, sv, str(sp), pr, (str(len(tl)), len(tl)), f"{m:.1f}", f"{cv:.2f}"])
            R.find("high", "Beaconing pattern",
                   f"{c} -> {sv}:{sp} every ~{m:.1f}s ({len(tl)} connections, CV={cv:.2f}).",
                   f"{c}->{sv}", "T1071 / T1029")
            R.ioc("IP", sv, "beaconing")
    s.append(("p", "Criteria: 6 or more connections to the same destination, mean interval of 3 seconds or more, "
                     "and coefficient of variation (CV) below 0.25."))
    s.append(("t", ["Client", "Server", "Port", "Proto",
                    "Connections", "Mean interval (s)", "CV"], brow))

    # ---- 11
    s = R.sec("11. Extracted Files (deduplicated)")
    frows, nrows = [], []
    for f in sorted(files, key=lambda x: x["name"]):
        mg = magic(f["path"])
        row = [f["name"], mg, (hb(f["size"]), f["size"]), (str(f["count"]), f["count"]), f["hash"]]
        if f["name"] in ocsp_names:
            nrows.append(row); continue
        frows.append(row)
        if mg.startswith(("Windows", "Linux")):
            R.find("high", "Executable extracted from traffic",
                   f"{f['name']} ({mg}).", f["hash"], "T1105")
            R.ioc("SHA256", f["hash"], f["name"])
        elif re.search(WEB_EXT, f["name"], re.I):
            R.ioc("SHA256", f["hash"], f["name"])
    hd = ["Name", "Type (magic)", "Size",
          "Copies", "SHA256"]
    s.append(("p", f"{len(files)} unique files after hash deduplication."))
    s.append(("t", hd, frows))
    s.append(("d", f"OCSP responses (hidden) - {len(nrows)} files", hd, nrows))

    # ---- 12
    s = R.sec("12. Suspicious Findings by Severity")
    order = {"high": 0, "medium": 1, "info": 2}
    lab = {"high": ("High", "hi"), "medium": ("Medium", "md"), "info": ("Info", "lo")}
    seen, uniq = set(), []
    for fd in sorted(R.findings, key=lambda x: order[x[0]]):
        if (fd[1], fd[2]) not in seen:
            seen.add((fd[1], fd[2])); uniq.append(fd)
    s.append(("t", ["Severity", "Title", "Details",
                    "Evidence", "MITRE ATT&CK"],
              [[(lab[a][0], order[a], lab[a][1]), b, c, d, e] for a, b, c, d, e in uniq]))
    if not uniq:
        s.append(("p", "Nothing was flagged by the current rules. That does not mean the capture is clean: review the sections manually."))

    # ---- 13
    s = R.sec("13. Indicators of Compromise (IOCs)")
    s.append(("t", ["Type", "Value", "Context"],
              [[t, v, c] for (t, v), c in sorted(R.iocs.items())]))

    # ---- 14
    s = R.sec("14. Limitations & Recommendations")
    s.append(("p", "Limitations: encrypted content (TLS/QUIC) was not decrypted. Detection relies on simple rules and "
                     "thresholds, so results are indicators that need manual confirmation. IP-to-domain mapping comes only "
                     "from DNS and SNI inside this capture."))
    s.append(("t", ["Priority", "Recommendation"], [
        ["Immediate", "Isolate the hosts named in high-severity findings and inspect them at endpoint level."],
        ["Immediate", "Manually inspect extracted files (e.g. panel.php) in an isolated environment."],
        ["Short term", "Block confirmed-malicious IPs and domains at the firewall and DNS."],
        ["Short term", "Review non-standard ports between internal hosts and identify the service behind them."],
        ["Long term", "Add detection rules for the observed patterns and block cleartext HTTP for scripts."]]))

    # ---- 2 (executive summary)
    cnt = Counter(f[0] for f in uniq)
    top = [f"[{lab[a][0]}] {b}: {c}" for a, b, c, *_ in uniq[:6]]
    R.sections[sum_idx] = ("2. Executive Summary", [
        ("p", f"Analyzed {meta['frames']:,} packets over {dur:.0f} seconds across {len(ips)} internal hosts and many "
                f"external destinations. Automated findings: {cnt['high']} high, {cnt['medium']} medium."),
        ("t", ["Top findings"], [[x] for x in top] or [["None"]]),
        ("p", "Note: this summary is generated automatically from rules and must be reviewed by an analyst.")])

    title = f"PCAP Analysis Report: {Path(pcap).name}"
    (out / "report.html").write_text(render_html(R, title), encoding="utf-8")
    (out / "report.md").write_text(render_md(R, title), encoding="utf-8")
    print(f"Done: {out / 'report.html'}")


# ───────────────────────── export ─────────────────────────
def cell(c):
    return (c, c, "") if isinstance(c, str) else (c[0], c[1], c[2] if len(c) > 2 else "")


def html_table(hd, rows):
    h = "<table class='s'><thead><tr>" + "".join(f"<th>{esc(x)}</th>" for x in hd) + "</tr></thead><tbody>"
    for r in rows:
        h += "<tr>"
        for c in r:
            d, v, cls = cell(c)
            h += f"<td dir='ltr' class='{cls}' data-v='{esc(str(v))}'>{esc(str(d))}</td>"
        h += "</tr>"
    return h + "</tbody></table>"


def render_html(R, title):
    side = "left"
    css = ("body{font-family:Segoe UI,Tahoma,sans-serif;max-width:1250px;margin:20px auto;padding:0 16px;"
           "background:#fafafa;color:#222}h1{border-bottom:3px solid #345}h2{margin-top:36px;color:#234;"
           f"border-{side}:5px solid #468;padding-{side}:10px}}.w{{overflow-x:auto}}table{{border-collapse:collapse;"
           "width:100%;font-size:13px;background:#fff}th,td{border:1px solid #ccc;padding:5px 8px;text-align:left;"
           "word-break:break-all}th{background:#e8eef5;cursor:pointer;position:sticky;top:0}td.hi{background:#fcc;"
           "font-weight:bold}td.md{background:#fe9}td.lo{background:#cfc}details{margin:10px 0}summary{cursor:pointer;"
           "font-weight:bold;color:#456}#q{width:100%;padding:8px;margin:10px 0;font-size:14px}")
    js = ("document.querySelectorAll('table.s th').forEach((th,i)=>th.onclick=()=>{const tb=th.closest('table')."
          "tBodies[0],rs=[...tb.rows],asc=th.dataset.a!=='1';th.dataset.a=asc?'1':'0';rs.sort((a,b)=>{const x=a."
          "cells[i].dataset.v,y=b.cells[i].dataset.v,nx=parseFloat(x),ny=parseFloat(y);const r=(!isNaN(nx)&&!isNaN"
          "(ny)&&/^[\\d.]+$/.test(x)&&/^[\\d.]+$/.test(y))?nx-ny:x.localeCompare(y);return asc?r:-r});rs.forEach("
          "r=>tb.appendChild(r))});q.oninput=()=>document.querySelectorAll('tbody tr').forEach(r=>r.style.display="
          "r.innerText.toLowerCase().includes(q.value.toLowerCase())?'':'none');")
    ph = "Search all tables (IP / domain / ...)"
    body = f"<h1>{esc(title)}</h1><input id='q' placeholder='{esc(ph)}'>"
    foot = "<p style='color:#888;font-size:12px'>Generated by WireBrief</p>"
    for t, blocks in R.sections:
        body += f"<h2>{esc(t)}</h2>"
        for b in blocks:
            if b[0] == "p":
                body += f"<p>{esc(b[1])}</p>"
            elif b[0] == "t":
                body += f"<div class='w'>{html_table(b[1], b[2])}</div>"
            elif b[0] == "d":
                body += f"<details><summary>{esc(b[1])}</summary><div class='w'>{html_table(b[2], b[3])}</div></details>"
    body += foot
    return (f"<!doctype html><html lang='en' dir='ltr'><head><meta charset='utf-8'><title>PCAP Report</title>"
            f"<style>{css}</style></head><body>{body}<script>{js}</script></body></html>")


def md_table(hd, rows):
    t = "| " + " | ".join(hd) + " |\n|" + "---|" * len(hd) + "\n"
    for r in rows:
        t += "| " + " | ".join(str(cell(c)[0]).replace("|", "\\|") for c in r) + " |\n"
    return t


def render_md(R, title):
    m = f"# {title}\n\n"
    for t, blocks in R.sections:
        m += f"## {t}\n\n"
        for b in blocks:
            if b[0] == "p":
                m += b[1] + "\n\n"
            elif b[0] == "t":
                m += md_table(b[1], b[2]) + "\n"
            elif b[0] == "d":
                m += f"<details><summary>{b[1]}</summary>\n\n{md_table(b[2], b[3])}\n</details>\n\n"
    m += "---\n*Generated by WireBrief*\n"
    return m


if __name__ == "__main__":
    main()
