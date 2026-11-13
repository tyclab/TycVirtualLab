"""Authored synthetic subprocess fixture; it never loads vendor firmware."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vfl.demo import capture


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="valid")
    parser.add_argument("--request")
    parser.add_argument("--capture")
    parser.add_argument("--auxiliary")
    args = parser.parse_args()
    if args.mode == "nested":
        from vfl.runner import run_process
        Path(args.auxiliary + ".backend.pid").write_text(str(os.getpid()))
        run_process([sys.executable, __file__, "--mode", "nested-leaf", "--auxiliary", args.auxiliary],
                    Path(args.auxiliary).parent, args.auxiliary + ".nested.out", args.auxiliary + ".nested.err",
                    30, termination_grace_s=0.0)
        return
    if args.mode == "nested-leaf":
        from vfl.runner import inherited_resource_lock_fds
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        program = "import pathlib,sys,time,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(1.2); pathlib.Path(sys.argv[1]).write_text('nested child survived'); time.sleep(30)"
        child = subprocess.Popen([sys.executable, "-c", program, args.auxiliary],
                                 pass_fds=inherited_resource_lock_fds())
        Path(args.auxiliary + ".nested-child.pid").write_text(str(child.pid))
        Path(args.auxiliary + ".leaf.pid").write_text(str(os.getpid()))
        time.sleep(30)
        return
    if args.mode == "log-limit":
        sys.stdout.write("x" * 16_384)
        sys.stdout.flush()
        time.sleep(2)
        return
    if args.mode == "log-exit":
        sys.stdout.write("x" * 16_384)
        return
    if args.mode == "timeout-child":
        # The child would write this marker if process-group cleanup failed.
        program = "import pathlib,sys,time,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(0.8); pathlib.Path(sys.argv[1]).write_text('survived')"
        child = subprocess.Popen([sys.executable, "-c", program, args.auxiliary])
        Path(args.auxiliary + ".pid").write_text(str(child.pid))
        Path(args.auxiliary + ".backend.pid").write_text(str(os.getpid()))
        time.sleep(5)
        return
    if args.mode == "missing":
        return
    if args.mode == "truncated":
        Path(args.capture).write_text('{"schema":')
        return
    if args.mode == "stale":
        shutil.copyfile(args.auxiliary, args.capture)
        return
    request = json.loads(Path(args.request).read_text())
    result = capture(request["profile"], request["trace"])
    result["manifest"].update(request["identities"])
    result["manifest"]["request_id"] = request["request_id"]
    if args.mode == "wrong-frames":
        result["frames"].pop()
    elif args.mode == "wrong-time":
        result["frames"][-1]["time_us"] += 1
    elif args.mode == "wrong-kind":
        result["manifest"]["execution_kind"] = "original-firmware"
    elif args.mode == "wrong-hash":
        result["manifest"]["input_sha256"] = "0" * 64
    elif args.mode == "missing-hash":
        result["manifest"].pop("input_sha256", None)
    elif args.mode == "wrong-run":
        result["manifest"]["request_id"] = "0" * 32
    elif args.mode != "valid":
        raise ValueError("unknown fixture mode")
    Path(args.capture).write_text(json.dumps(result))


if __name__ == "__main__":
    main()
