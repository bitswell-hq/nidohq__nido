#!/usr/bin/env python3
"""Measures the email-recovery circuit and its components and writes the
tables of MEASUREMENTS.md between its generated-block markers.

For the recovery circuit and every bench package: ACIR opcodes and UltraHonk
gates (`bb gates`). For the proved packages: native witness generation
(`nargo execute`) and zero-knowledge proving (`bb prove --scheme ultra_honk
--oracle_hash keccak --zk`, the flavor Perch's verifier accepts), median
wall time over RUNS runs and the largest peak resident set size, and
`bb verify` of every proof. For the recovery circuit (and its 1024-byte
comparison build) also bb.js, the prover a browser runs, with one worker
thread and with one per core (packages/email-recovery/scripts/measure-bbjs.mjs
on the committed Gmail fixture, one process per run).

Run through scripts/measure.sh, which installs and checks the pinned
toolchain, builds the TypeScript packages, and sets NARGO and BB. RUNS
(default 3) sets the repetitions.
"""

import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
NARGO = os.environ["NARGO"]
BB = os.environ["BB"]
RUNS = int(os.environ.get("RUNS", "3"))
SCHEME = ["--scheme", "ultra_honk", "--oracle_hash", "keccak"]

REPO = HERE.parent.parent
GMAIL_FIXTURE = REPO / "crates/integration-tests/fixtures/email/provider-gmail-com"

# (directory, package, what it measures, proved, header bound)
RECOVERY = [
    ("recovery", "recovery", "The recovery circuit: spec obligations C1 to C6 at 1536-byte headers", True, 1536),
    ("bench/recovery_1024", "bench_recovery_1024", "The same relation at 1024-byte headers, for comparison", True, 1024),
]

# (package, what it measures, proved), each in bench/<package> as bench_<package>
BENCHES = [
    ("rsa_2048", "RSA-2048 PKCS#1 v1.5 / SHA-256 of a given digest", True),
    ("header_sha_1024", "SHA-256 of a 1024-byte header block, zero past its length", True),
    ("header_scan_1024", "Header structure scan (1024 bytes)", False),
    ("header_from_1024", "Scan + From address (124 bytes)", False),
    ("header_tags_1024", "Scan + From + DKIM-Signature tags (512-byte field, 16 tags)", False),
    ("header_parse_1024", "Scan + From + tags + Subject: all header parsing", True),
    ("body_hash_1024", "bh= against a body of at most 1024 bytes", True),
    ("body_hash_4096", "bh= against a body of at most 4096 bytes", True),
    ("spec_hashes", "Commitment C, key hash, registry leaf, depth-16 Merkle root, Subject opening", True),
    ("dkim_header_1024", "Header-only DKIM composition at 1024-byte headers", True),
]


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def timed(cmd, cwd):
    """Wall seconds and peak RSS in bytes of one process."""
    with tempfile.TemporaryFile() as err:
        start = time.perf_counter()
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=err)
        _, status, usage = os.wait4(proc.pid, 0)
        elapsed = time.perf_counter() - start
        if status != 0:
            err.seek(0)
            sys.exit(f"{' '.join(cmd)} failed:\n{err.read().decode()}")
    rss = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    return elapsed, rss


def gates(package):
    out = run([BB, "gates", "-s", "ultra_honk", "-b", str(HERE / f"target/{package}.json")])
    f = json.loads(out.stdout)["functions"][0]
    return f["acir_opcodes"], f["circuit_size"]


def prove(package, work):
    artifact = HERE / f"target/{package}.json"
    run([BB, "write_vk", *SCHEME, "-b", str(artifact), "-o", str(work)])
    witness_times, prove_times, peak = [], [], 0
    for i in range(RUNS):
        name = f"{package}_{i}"
        t, _ = timed([NARGO, "execute", "--package", package, name], HERE)
        witness_times.append(t)
        out = work / f"proof_{i}"
        out.mkdir()
        t, rss = timed(
            [BB, "prove", *SCHEME, "--zk", "-b", str(artifact),
             "-w", str(HERE / f"target/{name}.gz"), "-o", str(out)],
            HERE,
        )
        prove_times.append(t)
        peak = max(peak, rss)
        run([BB, "verify", *SCHEME, "--zk", "-k", str(work / "vk"),
             "-p", str(out / "proof"), "-i", str(out / "public_inputs")])
        (HERE / f"target/{name}.gz").unlink()
    proof_bytes = (work / "proof_0" / "proof").stat().st_size
    return statistics.median(witness_times), statistics.median(prove_times), peak, proof_bytes


def bbjs(package, header_max, threads):
    """Median prove and witness times and the largest peak RSS of bb.js."""
    rows = []
    for _ in range(RUNS):
        out = run(["node", str(REPO / "packages/email-recovery/scripts/measure-bbjs.mjs"),
                   str(GMAIL_FIXTURE), str(threads),
                   "--circuit", str(HERE / f"target/{package}.json"), "--header-max", str(header_max)],
                  cwd=REPO)
        rows.append(json.loads(out.stdout.strip().splitlines()[-1]))
    return (statistics.median(r["execute_ms"] for r in rows),
            statistics.median(r["prove_ms"] for r in rows),
            max(r["peak_rss_mib"] for r in rows),
            rows[0]["proof_bytes"])


def machine():
    if sys.platform == "darwin":
        cpu = run(["sysctl", "-n", "machdep.cpu.brand_string"]).stdout.strip()
        cores = run(["sysctl", "-n", "hw.ncpu"]).stdout.strip()
        mem = int(run(["sysctl", "-n", "hw.memsize"]).stdout) // 2**30
        os_name = f"macOS {platform.mac_ver()[0]}"
    else:
        cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "unknown")
        cores = str(os.cpu_count())
        mem = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // 2**30
        os_name = f"Linux {platform.release()}"
    return f"{cpu}, {cores} cores, {mem} GB, {os_name}"


def main():
    load = os.getloadavg()[0]
    rows_gates, rows_prove = [], []
    packages = [r[:4] for r in RECOVERY] + [(f"bench/{p}", f"bench_{p}", what, proved) for p, what, proved in BENCHES]
    with tempfile.TemporaryDirectory() as tmp:
        for path, package, what, proved in packages:
            opcodes, size = gates(package)
            log2 = (size - 1).bit_length()
            rows_gates.append(f"| `{path}` | {what} | {opcodes:,} | {size:,} | 2^{log2} |")
            if proved:
                work = Path(tmp) / package
                work.mkdir()
                w, p, rss, proof_bytes = prove(package, work)
                rows_prove.append(
                    f"| `{path}` | 2^{log2} | {w * 1000:,.0f} ms | {p * 1000:,.0f} ms | "
                    f"{rss / 2**20:,.0f} MiB | {proof_bytes:,} |"
                )
            print(f"measured {package}", file=sys.stderr)
        rows_bbjs = []
        cores = os.cpu_count()
        for path, package, _, _, header_max in RECOVERY:
            for threads in (1, cores):
                w, p, rss, proof_bytes = bbjs(package, header_max, threads)
                rows_bbjs.append(
                    f"| `{path}` | {header_max:,} | {threads} | {w:,.0f} ms | {p:,.0f} ms | {rss:,} MiB | {proof_bytes:,} |"
                )
                print(f"measured bb.js, {package}, {threads} threads", file=sys.stderr)
    load_after = os.getloadavg()[0]

    nargo_v = run([NARGO, "--version"]).stdout.splitlines()[0]
    bb_v = run([BB, "--version"]).stdout.strip()
    block = "\n".join([
        f"Generated by `scripts/measure.sh` on {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC.",
        f"Machine: {machine()}; load average {load:.1f} at the start and {load_after:.1f} at the end.",
        f"Toolchain: {nargo_v}, bb {bb_v}. Proving: median of {RUNS} runs.",
        "",
        "| Package | Measures | ACIR opcodes | UltraHonk gates | Padded size |",
        "| --- | --- | --- | --- | --- |",
        *rows_gates,
        "",
        "| Package | Padded size | `nargo execute` (witness) | `bb prove --zk` | `bb prove` peak RSS | Proof bytes |",
        "| --- | --- | --- | --- | --- | --- |",
        *rows_prove,
        "",
        "bb.js 0.87.0 on the recovery circuit (Node, the Gmail fixture; `keccakZK`):",
        "",
        "| Package | Header bound | Threads | noir_js witness | bb.js prove | Peak RSS (process) | Proof bytes |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        *rows_bbjs,
    ])

    doc = HERE / "MEASUREMENTS.md"
    text = doc.read_text()
    begin = "<!-- BEGIN GENERATED by scripts/measure.sh; do not edit -->"
    end = "<!-- END GENERATED -->"
    pattern = re.compile(re.escape(begin) + ".*?" + re.escape(end), re.S)
    if not pattern.search(text):
        sys.exit(f"{doc} has no generated-block markers")
    doc.write_text(pattern.sub(lambda _: f"{begin}\n{block}\n{end}", text))
    print(block)


if __name__ == "__main__":
    main()
