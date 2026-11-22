"""Runs N single-threaded Unbound processes on consecutive loopback ports.

The Windows build of Unbound serves one listening socket from one thread and
caps each thread at 64 sockets, so one process tops out near 48 upstream
queries in flight. wincrawl rotates over every --dns server it is given, so a
farm of processes behind a --dns list scales where one process cannot.

    python bench/unbound/farm.py --unbound C:/path/unbound.exe --conf bench/unbound/recursive.conf -n 32
    # prints the --dns argument, runs until Ctrl+C, then stops every process

Each instance gets the config with its interface/port and control-port
rewritten (base port + i, control port + i) and logs to <workdir>/unbound-<i>.log.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import time


def start(unbound, conf, count, base_port, control_base, workdir):
    text = open(conf, encoding="utf-8").read()
    procs = []
    for i in range(count):
        port = base_port + i
        cfg = re.sub(r"(?m)^(\s*interface:\s*127\.0\.0\.1)@\d+", rf"\g<1>@{port}", text)
        cfg = re.sub(r"(?m)^(\s*port:\s*)\d+", rf"\g<1>{port}", cfg)
        cfg = re.sub(r"(?m)^(\s*control-port:\s*)\d+", rf"\g<1>{control_base + i}", cfg)
        path = os.path.join(workdir, f"unbound-{i}.conf")
        with open(path, "w", encoding="utf-8") as f:
            f.write(cfg)
        log = open(os.path.join(workdir, f"unbound-{i}.log"), "w")
        procs.append(subprocess.Popen([unbound, "-d", "-c", path], stdout=log, stderr=subprocess.STDOUT))
    time.sleep(1.5)
    dead = [i for i, p in enumerate(procs) if p.poll() is not None]
    if dead:
        stop(procs)
        raise RuntimeError(f"unbound instances {dead} exited at startup; see {workdir}")
    return procs


def stop(procs):
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def dns_arg(count, base_port):
    return ",".join(f"127.0.0.1:{base_port + i}" for i in range(count))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--unbound", required=True, help="path to unbound.exe")
    ap.add_argument("--conf", required=True, help="recursive.conf or forward.conf")
    ap.add_argument("-n", "--count", type=int, default=32)
    ap.add_argument("--base-port", type=int, default=5400)
    ap.add_argument("--control-base", type=int, default=5500)
    ap.add_argument("--workdir", default=None, help="config/log directory (default: a new temp dir)")
    a = ap.parse_args()
    workdir = a.workdir or tempfile.mkdtemp(prefix="unbound-farm-")
    os.makedirs(workdir, exist_ok=True)
    procs = start(a.unbound, a.conf, a.count, a.base_port, a.control_base, workdir)
    print(f"--dns {dns_arg(a.count, a.base_port)}", flush=True)
    print(f"{a.count} instances running, logs in {workdir}; Ctrl+C stops them", file=sys.stderr, flush=True)
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        print("an instance exited; stopping the farm", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        stop(procs)


if __name__ == "__main__":
    main()
