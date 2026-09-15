#!/usr/bin/env python3
import argparse, hashlib, json, statistics, struct, subprocess, sys, time
from pathlib import Path
from typing import Any, BinaryIO
MAX_RESPONSE = 8 * 1024 * 1024

def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")

def decode_stream(text: str) -> list[dict[str, Any]]:
    dec = json.JSONDecoder(); pos = 0; out = []
    while pos < len(text):
        while pos < len(text) and text[pos].isspace(): pos += 1
        if pos >= len(text): break
        value, pos = dec.raw_decode(text, pos)
        if not isinstance(value, dict): raise ValueError("expected JSON object stream")
        out.append(value)
    return out

def module_graph(args):
    raw = subprocess.check_output(["go","list","-m","-json","all"], cwd=args.module_root, text=True, encoding="utf-8")
    rows = []
    for r in decode_stream(raw):
        item = {"path": r.get("Path",""), "version": r.get("Version",""), "sum": r.get("Sum",""),
                "go_version": r.get("GoVersion",""), "main": bool(r.get("Main",False)),
                "indirect": bool(r.get("Indirect",False))}
        rep = r.get("Replace")
        if isinstance(rep, dict):
            item["replace"] = {"path": rep.get("Path",""), "version": rep.get("Version",""), "sum": rep.get("Sum","")}
        rows.append(item)
    rows.sort(key=lambda x:(x["path"],x["version"]))
    write_json(Path(args.output), {"modules": rows})

def read_exact(stream: BinaryIO, n: int) -> bytes:
    chunks=[]; rem=n
    while rem:
        b=stream.read(rem)
        if not b: raise EOFError(f"unexpected EOF reading {n} bytes")
        chunks.append(b); rem -= len(b)
    return b"".join(chunks)

def request(proc, payload):
    raw=json.dumps(payload,separators=(",",":"),ensure_ascii=False).encode()
    proc.stdin.write(struct.pack(">I",len(raw))+raw); proc.stdin.flush()
    n=struct.unpack(">I",read_exact(proc.stdout,4))[0]
    if n <= 0 or n > MAX_RESPONSE: raise RuntimeError(f"invalid response size {n}")
    obj=json.loads(read_exact(proc.stdout,n).decode())
    if not isinstance(obj,dict): raise RuntimeError("response must be object")
    return obj

def percentile(values, p):
    vals=sorted(values); idx=max(0,min(len(vals)-1,round((len(vals)-1)*p)))
    return vals[idx]

def stats(vals):
    return {"min_ms":round(min(vals),3),"median_ms":round(statistics.median(vals),3),
            "p95_ms":round(percentile(vals,0.95),3),"max_ms":round(max(vals),3)}

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()

def measure(args):
    binary=Path(args.binary).resolve()
    starts=[]; statuses=[]
    for i in range(args.iterations):
        t0=time.perf_counter_ns()
        p=subprocess.Popen([str(binary),"--serve-stdio"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            hr=request(p,{"id":f"h{i}","method":"core.handshake","params":{"protocol":"atlas-core","version":"1.0.0","client_name":"phase554d-evidence","client_version":"1","session_nonce":f"phase554d-{i}"}})
            t1=time.perf_counter_ns()
            if hr.get("ok") is not True: raise RuntimeError(f"handshake failed: {hr}")
            s0=time.perf_counter_ns()
            sr=request(p,{"id":f"s{i}","method":"core.status","params":{}})
            s1=time.perf_counter_ns()
            if sr.get("ok") is not True: raise RuntimeError(f"status failed: {sr}")
            starts.append((t1-t0)/1e6); statuses.append((s1-s0)/1e6)
        finally:
            if p.stdin:
                try: p.stdin.close()
                except OSError: pass
            try: p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                p.terminate()
                try: p.wait(timeout=2)
                except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=2)
    build=subprocess.check_output(["go","version","-m",str(binary)],text=True,encoding="utf-8").splitlines()
    write_json(Path(args.output),{"runner_os":args.runner_os,"iterations":args.iterations,
        "binary":{"name":binary.name,"size_bytes":binary.stat().st_size,"sha256":sha256(binary),"go_version_m":build},
        "toolchain":subprocess.check_output(["go","version"],text=True,encoding="utf-8").strip(),
        "startup_to_handshake":stats(starts),"status_roundtrip":stats(statuses)})

def flatten(items):
    out=[]
    def visit(xs):
        if not isinstance(xs,list): return
        for x in xs:
            if isinstance(x,dict):
                out.append(x); visit(x.get("components"))
    visit(items); return out

def review_sbom(args):
    src=Path(args.sbom); bom=json.loads(src.read_text(encoding="utf-8"))
    if bom.get("bomFormat")!="CycloneDX": raise ValueError("not CycloneDX")
    if str(bom.get("specVersion"))!="1.6": raise ValueError(f"unexpected specVersion {bom.get('specVersion')}")
    comps=flatten(bom.get("components"))
    if not comps: raise ValueError("no SBOM components")
    observed={str(c.get("name","")):str(c.get("version","")) for c in comps}
    expected={"github.com/theupdateframework/go-tuf/v2":"v2.4.2","golang.org/x/text":"v0.36.0","modernc.org/sqlite":"v1.58.0"}
    for m,v in expected.items():
        if observed.get(m)!=v: raise ValueError(f"SBOM dependency mismatch {m}: {observed.get(m)!r} != {v!r}")
    inv=[]
    for c in comps:
        ev=c.get("evidence")
        inv.append({"name":c.get("name",""),"version":c.get("version",""),"purl":c.get("purl",""),
                    "licenses":c.get("licenses",[]),
                    "license_evidence":ev.get("licenses",[]) if isinstance(ev,dict) else []})
    inv.sort(key=lambda x:(str(x["name"]),str(x["version"])))
    write_json(Path(args.output),{"sbom":src.name,"component_count":len(inv),"components":inv})

def main():
    p=argparse.ArgumentParser(); sp=p.add_subparsers(dest="cmd",required=True)
    a=sp.add_parser("module-graph"); a.add_argument("--module-root",required=True); a.add_argument("--output",required=True); a.set_defaults(func=module_graph)
    a=sp.add_parser("measure"); a.add_argument("--binary",required=True); a.add_argument("--runner-os",required=True); a.add_argument("--iterations",type=int,default=20); a.add_argument("--output",required=True); a.set_defaults(func=measure)
    a=sp.add_parser("review-sbom"); a.add_argument("--sbom",required=True); a.add_argument("--output",required=True); a.set_defaults(func=review_sbom)
    args=p.parse_args(); args.func(args); return 0
if __name__=="__main__": sys.exit(main())
