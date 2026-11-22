"""Fold the CPU samples of `xperf -a dumper -stacktimeshifting` output into flame graph stacks.

Stdlib only. Reads the dumper text (file or "-" for stdin), keeps the SampledProfile events of
the selected processes, and writes one "process;outer;...;leaf <count>" line per unique stack
(root first). Optionally prints a summary: samples per process, user/kernel split, top modules
and functions by self samples, and inclusive shares for --bucket NAME=REGEX rules matched
against each whole stack (first matching rule wins, in the given order).

    xperf -i t.etl -symbols -a dumper -stacktimeshifting -o t.txt
    python tools/profile/fold.py t.txt --pid 1234 -o t.folded --report
"""

import argparse
import collections
import re
import sys

KERNEL_BASE = 0xFFFF800000000000


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", help="xperf dumper output, or - for stdin")
    ap.add_argument("-o", "--out", help="folded stacks output")
    ap.add_argument("--pid", type=int, action="append", default=[], help="keep this process id (repeatable)")
    ap.add_argument("--process", action="append", default=[], help="keep processes whose name matches this regex")
    ap.add_argument("--range", nargs=2, type=int, metavar=("LO_US", "HI_US"), help="keep samples in [lo, hi] microseconds")
    ap.add_argument("--report", action="store_true", help="print a summary to stdout")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--bucket", action="append", default=[], metavar="NAME=REGEX", help="inclusive bucket rule")
    ap.add_argument("--hz", type=float, default=1000.0, help="sampling rate, to convert samples to CPU seconds")
    return ap.parse_args()


def clean(frame):
    # "wincrawl.exe!wc::crawl::Engine::run" -> unchanged; drop argument lists xperf sometimes keeps.
    frame = frame.strip()
    p = frame.find("(")
    if p > 0 and "!" in frame[:p]:
        frame = frame[:p]
    return frame.replace(";", ":")


def main():
    args = parse_args()
    pids = set(args.pid)
    proc_res = [re.compile(r) for r in args.process]
    buckets = []
    for b in args.bucket:
        name, _, rx = b.partition("=")
        buckets.append((name, re.compile(rx)))

    stacks = collections.Counter()  # (process, frames tuple root-first) -> samples
    per_proc = collections.Counter()
    src = sys.stdin if args.dump == "-" else open(args.dump, encoding="utf-8", errors="replace")

    cur = None  # [process, count, frames leaf-first, sample-function, kernel?]

    def flush():
        if cur is None:
            return
        proc, count, frames, fallback, kernel = cur
        if not frames:
            frames = [fallback]
        stacks[(proc, kernel, tuple(reversed(frames)))] += count
        per_proc[proc] += count

    proc_cache = {}
    for line in src:
        head = line[:26].strip()
        if head == "Stack,":
            if cur is not None:
                parts = line.split(",", 5)
                cur[2].append(clean(parts[5]))
            continue
        if head.startswith("SampledProfile,"):
            flush()
            cur = None
            # SampledProfile, TimeStamp, Process Name ( PID), ThreadID, PrgrmCtr, CPU, ThreadStart, Image!Function,
            # Count, type. Symbols may contain commas (template arguments), so split the fixed fields off both ends.
            parts = [p.strip() for p in line.split(",", 6)]
            if not parts[1].isdigit():
                continue  # the column legend in the dump header
            ts = int(parts[1])
            if args.range and not (args.range[0] <= ts <= args.range[1]):
                continue
            pname = parts[2]
            sel = proc_cache.get(pname)
            if sel is None:
                m = re.match(r"(.*) \(\s*(\d+)\)$", pname)
                name, pid = (m.group(1).strip(), int(m.group(2))) if m else (pname, -1)
                keep = (not pids and not proc_res) or pid in pids or any(r.search(name) for r in proc_res)
                sel = proc_cache[pname] = (name if keep else "")
            if not sel:
                continue
            kernel = int(parts[4], 16) >= KERNEL_BASE
            middle, count, _ = parts[6].rsplit(",", 2)
            # The sampled function is the last "<image>!" token; ThreadStart precedes it.
            starts = [m.start(1) for m in re.finditer(r",\s*([^\s,!<>()]+!)", middle)]
            leaf = middle[starts[-1]:] if starts else middle
            cur = [sel, int(count), [], clean(leaf), kernel]
            continue
        if cur is not None and head:
            flush()
            cur = None
    flush()

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            for (proc, _, frames), n in sorted(stacks.items(), key=lambda kv: kv[0][2]):
                f.write(";".join((proc,) + frames) + f" {n}\n")

    if args.report:
        report(stacks, per_proc, buckets, args.top, args.hz)


def module(frame):
    return frame.split("!", 1)[0] if "!" in frame else frame


def report(stacks, per_proc, buckets, top, hz):
    total = sum(per_proc.values())
    pct = lambda n: f"{100.0 * n / total:5.1f}%" if total else "-"
    print(f"samples: {total:,} ({total / hz:.2f} CPU s at {hz:g} Hz)")
    for p, n in per_proc.most_common():
        print(f"  {p:<30} {n:>9,} {pct(n)}")
    kern = sum(n for (_, k, _), n in stacks.items() if k)
    print(f"kernel mode {pct(kern)}  user mode {pct(total - kern)}")

    self_mod = collections.Counter()
    self_fn = collections.Counter()
    incl_mod = collections.Counter()
    bucket_n = collections.Counter()
    for (proc, _, frames), n in stacks.items():
        leaf = frames[-1] if frames else proc
        self_fn[leaf] += n
        self_mod[module(leaf)] += n
        for m in {module(f) for f in frames}:
            incl_mod[m] += n
        if buckets:
            joined = ";".join(frames)
            for name, rx in buckets:
                if rx.search(joined):
                    bucket_n[name] += n
                    break
            else:
                bucket_n["(other)"] += n

    def table(title, counter):
        print(f"\n{title}")
        for k, n in counter.most_common(top):
            print(f"  {pct(n)}  {n:>9,}  {k}")

    table("self samples by module", self_mod)
    table("inclusive samples by module", incl_mod)
    table("self samples by function", self_fn)
    if buckets:
        print("\nbuckets (inclusive, first match wins)")
        for name, _ in buckets + [("(other)", None)]:
            print(f"  {pct(bucket_n[name])}  {bucket_n[name]:>9,}  {name}")


if __name__ == "__main__":
    main()
