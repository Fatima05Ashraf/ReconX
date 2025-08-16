#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WHOIS & DNS Recon Tool
- Takes a domain
- Shows WHOIS summary and DNS records (A, AAAA, MX, TXT, NS, CNAME)
- Pretty terminal output + optional JSON/CSV export
"""

import argparse
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# libs
import whois
import dns.resolver
import dns.exception

console = Console()

def safe_list(x):
    if x is None:
        return []
    if isinstance(x, (list, tuple, set)):
        return list(x)
    return [x]

def whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"error": f"WHOIS failed: {e}"}

    # Normalize dates
    def fmt_date(d):
        if not d:
            return None
        # whois lib sometimes returns list of dates
        if isinstance(d, (list, tuple)):
            d = d[0]
        try:
            return d.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(d)

    data = {
        "domain": domain,
        "registrar": getattr(w, "registrar", None),
        "creation_date": fmt_date(getattr(w, "creation_date", None)),
        "expiration_date": fmt_date(getattr(w, "expiration_date", None)),
        "updated_date": fmt_date(getattr(w, "updated_date", None)),
        "name_servers": sorted({ns.strip(".") for ns in safe_list(getattr(w, "name_servers", [])) if ns}),
        "status": safe_list(getattr(w, "status", [])),
        "raw": str(getattr(w, "text", ""))[:2000],  # cap raw text
    }
    return data

def dns_query(domain: str, rtype: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, rtype)
        return [a.to_text() for a in answers]
    except dns.resolver.NXDOMAIN:
        return ["NXDOMAIN"]
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.DNSException as e:
        return [f"DNS error: {e}"]

def gather_dns(domain: str) -> dict:
    records = {}
    for rt in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
        records[rt] = dns_query(domain, rt)
    # simple SPF/DMARC hints from TXT
    spf = [t for t in records["TXT"] if t.lower().startswith("v=spf1")]
    dmarc = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    records["SPF"] = spf
    records["DMARC"] = dmarc
    return records

def print_whois(w: dict):
    if "error" in w:
        console.print(Panel(f"[red]{w['error']}[/red]", title="WHOIS", border_style="red"))
        return
    table = Table(title=f"WHOIS: {w['domain']}", box=box.SIMPLE_HEAVY)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    rows = [
        ("Registrar", w.get("registrar") or "-"),
        ("Created", w.get("creation_date") or "-"),
        ("Updated", w.get("updated_date") or "-"),
        ("Expires", w.get("expiration_date") or "-"),
        ("Name Servers", ", ".join(w.get("name_servers") or []) or "-"),
        ("Status", ", ".join(w.get("status") or []) or "-"),
    ]
    for k, v in rows:
        table.add_row(k, v)
    console.print(table)

def print_dns(d: dict, domain: str):
    table = Table(title=f"DNS Records: {domain}", box=box.SIMPLE_HEAVY)
    table.add_column("Type", style="magenta", no_wrap=True)
    table.add_column("Values", style="white")
    for rt, vals in d.items():
        if rt in ("SPF", "DMARC"):
            # show below as separate panels
            continue
        display = ", ".join(vals) if vals else "-"
        table.add_row(rt, display)
    console.print(table)

    if d.get("SPF"):
        console.print(Panel("\n".join(d["SPF"]), title="SPF (TXT)", border_style="green"))
    else:
        console.print(Panel("No SPF record found", title="SPF (TXT)", border_style="yellow"))

    if d.get("DMARC"):
        console.print(Panel("\n".join(d["DMARC"]), title="DMARC (TXT)", border_style="green"))
    else:
        console.print(Panel("No DMARC record found at _dmarc."+domain, title="DMARC (TXT)", border_style="yellow"))

def to_json(data: dict, out_path: str):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def to_csv(data: dict, out_path: str):
    """
    Writes a flat CSV. WHOIS summary in first rows, then DNS records.
    """
    rows = []
    w = data["whois"]
    rows.append(["Section", "Key", "Value"])
    if "error" in w:
        rows.append(["WHOIS", "error", w["error"]])
    else:
        rows.extend([
            ["WHOIS", "domain", w.get("domain")],
            ["WHOIS", "registrar", w.get("registrar")],
            ["WHOIS", "creation_date", w.get("creation_date")],
            ["WHOIS", "updated_date", w.get("updated_date")],
            ["WHOIS", "expiration_date", w.get("expiration_date")],
            ["WHOIS", "name_servers", ";".join(w.get("name_servers") or [])],
            ["WHOIS", "status", ";".join(w.get("status") or [])],
        ])
    for rt, vals in data["dns"].items():
        if not vals:
            rows.append(["DNS", rt, "-"])
        else:
            for v in vals:
                rows.append(["DNS", rt, v])

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

def run(domain: str, out: str = None, fmt: str = "json"):
    console.print(Panel(f"[bold]WHOIS & DNS Recon[/bold]\nTarget: [cyan]{domain}[/cyan]\nTime: {datetime.utcnow()} UTC",
                        border_style="blue", title="Recon"))

    w = whois_lookup(domain)
    d = gather_dns(domain)

    print_whois(w)
    print_dns(d, domain)

    out_data = {"domain": domain, "whois": w, "dns": d, "timestamp_utc": datetime.utcnow().isoformat()}

    if out:
        if fmt.lower() == "json":
            to_json(out_data, out)
            console.print(f"[green]Saved JSON ->[/green] {out}")
        elif fmt.lower() == "csv":
            to_csv(out_data, out)
            console.print(f"[green]Saved CSV  ->[/green] {out}")
        else:
            console.print("[red]Unknown format; use json or csv[/red]")

def main():
    parser = argparse.ArgumentParser(description="WHOIS & DNS Recon Tool")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--out", help="Path to save results (e.g., out.json or out.csv)")
    parser.add_argument("--format", default="json", choices=["json", "csv"], help="Export format")
    args = parser.parse_args()
    run(args.domain, args.out, args.format)

if __name__ == "__main__":
    main()
