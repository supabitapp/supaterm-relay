import glob, json, os, sys

results = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def rows(name):
    return [json.loads(line) for line in open(os.path.join(results, name))]


idle = [
    ("baseline relay", "baseline-pairs.jsonl"),
    ("256 B read buffer", "lean-rb256.jsonl"),
    ("handler handoff", "lean-handoff.jsonl"),
    ("handoff + 256 B buffer", "lean-handoff-rb256.jsonl"),
    ("lean: all three", "lean-all.jsonl"),
    ("lean: all, 1 KiB buffer", "lean-all-rb1024.jsonl"),
    ("standalone goroutine", "standalone-goroutine.jsonl"),
    ("standalone epoll", "standalone-epoll.jsonl"),
    ("baseline, hosts only", "baseline-hosts.jsonl"),
    ("lean, hosts only", "lean-all-hosts.jsonl"),
]
print(f"{'idle':26} {'sockets':>8} {'RSS MiB':>8} {'RSS/sock':>9} {'heap/sock':>10} {'stack/sock':>11} {'gor/sock':>9} {'50k MiB':>8}")
for label, name in idle:
    r = rows(name)
    z, t = r[0], r[-1]
    n = t["sockets"]
    per = lambda k: (t[k] - z[k]) / n
    rss = per("rssKiB") * 1024
    print(f"{label:26} {n:8} {t['rssKiB'] / 1024:8.0f} {rss / 1024:8.1f}K {per('heapAllocBytes') / 1024:9.1f}K "
          f"{per('stackInuseBytes') / 1024:10.1f}K {per('goroutines'):9.2f} {(z['rssKiB'] * 1024 + rss * 50000) / 2**20:8.0f}")

bench = {}
for path in sorted(glob.glob(os.path.join(results, "bench-*.jsonl"))):
    variant = os.path.basename(path)[len("bench-"):].rsplit("-", 1)[0]
    for line in open(path):
        r = json.loads(line)
        bench.setdefault(variant, {}).setdefault((r["payloadBytes"], r["clients"]), []).append(r)
order = sys.argv[1:] or ["baseline", "lean_rb4096", "lean_rb1024", "lean_rb256", "standalone-goroutine", "standalone-epoll"]
for metric in ["messagesPerSec", "rttP50Micros", "rttP99Micros", "cpuPercentOfOneCore"]:
    print(f"\n{metric} (mean of runs)")
    print(f"{'payload x clients':>18} " + " ".join(f"{v:>21}" for v in order))
    for key in sorted(bench["baseline"]):
        cells = []
        for v in order:
            rs = bench[v][key]
            mean = sum(r.get(metric, 0) for r in rs) / len(rs)
            bad = sum(r["failures"] + r["corrupt"] for r in rs)
            cells.append(f"{mean:21.0f}" if not bad else f"{'FAILED':>21}")
        print(f"{f'{key[0]} B x {key[1]}':>18} " + " ".join(cells))
