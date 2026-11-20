"""Bounded subprocess execution and immutable experiment manifests."""

from __future__ import annotations

import contextlib
import copy
import fcntl
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .model import (MAX_JSON_BYTES, LabError, compatible_input, digest, execution_scope, experiment_digest, file_digest,
                    load_json, number, private_path, require, validate_capture, validate_profile,
                    validate_trace, write_json)

RESOURCE_LOCK_ENV = "TYCVL_RESOURCE_LOCK_FDS"


def inherited_resource_lock_fds():
    """Descriptors forwarded by a parent TycVirtualLab runner, never file paths."""
    encoded = os.environ.get(RESOURCE_LOCK_ENV, "")
    if not encoded:
        return ()
    require(len(encoded) <= 1024, "inherited resource-lock metadata exceeds limit")
    parts = encoded.split(",")
    require(len(parts) <= 64 and all(part.isascii() and part.isdigit() for part in parts),
            "invalid inherited resource-lock descriptors")
    descriptors = tuple(sorted({int(part) for part in parts}))
    for fd in descriptors:
        require(3 <= fd <= 1_048_576, "invalid inherited resource-lock descriptor")
        try:
            os.fstat(fd)
        except OSError as exc:
            raise LabError("inherited resource-lock descriptor is no longer open") from exc
    return descriptors


def resolve_profile(path):
    p = Path(path).expanduser()
    if not p.is_file():
        p = Path(__file__).with_name("profiles") / (str(path).removesuffix(".json") + ".json")
    require(p.is_file(), f"profile not found: {path}")
    return p.resolve(), validate_profile(load_json(p))


def _path(value, base):
    p = Path(value).expanduser()
    return p.resolve() if p.is_absolute() else (base / p).resolve()


def assets(profile, base):
    result = []
    for asset in profile.get("firmware", []):
        p = _path(asset["path"], base)
        require(p.is_file(), f"missing asset: {asset['role']}")
        actual = file_digest(p)
        require(not asset.get("sha256") or actual == asset["sha256"], f"asset hash mismatch: {asset['role']}")
        result.append({"role": asset["role"], "path": str(p), "sha256": actual, "bytes": p.stat().st_size})
    if profile["backend"].get("execution_kind") == "original-firmware":
        require(bool(result), "original-firmware execution requires declared firmware assets")
    return result


def _command(backend, base, request, capture, workdir):
    values = {"{request}": str(request), "{capture}": str(capture), "{workdir}": str(workdir)}
    command = []
    for item in backend["command"]:
        for placeholder, value in values.items():
            item = item.replace(placeholder, value)
        require("{request}" not in item and "{capture}" not in item, "unresolved argument")
        # Existing relative script/program paths are relative to the profile, never the shell.
        if not item.startswith("-") and not Path(item).is_absolute() and (base / item).is_file():
            item = str((base / item).resolve())
        command.append(item)
    executable = shutil.which(command[0])
    require(executable is not None, f"backend executable unavailable: {command[0]}")
    command[0] = executable
    return command


def _hold(backend, base):
    if backend.get("hold_file"):
        require(not _path(backend["hold_file"], base).exists(), "backend HOLD is present; execution not started")


@contextlib.contextmanager
def resource_lock(backend, base, workdir):
    _hold(backend, base)
    lock = backend.get("resource_lock")
    if not lock:
        yield None
        return
    path = _path(lock, base)
    private_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    timeout = backend.get("queue_timeout_s", 30)
    require(type(timeout) in (int, float) and 0 <= timeout <= 86400, "invalid queue timeout")
    with path.open("a+b") as f:
        until = time.monotonic() + timeout
        while True:
            _hold(backend, base)
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                require(time.monotonic() < until, "resource queue timeout")
                time.sleep(0.05)
        try:
            _hold(backend, base)
            yield f.fileno()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


@contextlib.contextmanager
def _termination_handlers():
    require(threading.current_thread() is threading.main_thread(),
            "external processes require the main thread for signal cleanup")
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP)}

    def interrupted(signum, _frame):
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        raise LabError(f"runner interrupted by {signal.Signals(signum).name}")

    try:
        for sig in previous:
            signal.signal(sig, interrupted)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _leader_exited(pid):
    # Observe exit without reaping: retaining the PID prevents reuse before the
    # final process-group kill has cleaned up descendants.
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def run_process(command, cwd, stdout, stderr, timeout_s, env=None, output_limit=8*1024*1024,
                *, pass_fds=(), resource_lock_fds=(), termination_grace_s=1.0):
    """Manage one process group, forwarding resource locks through nested adapters.

    Nested adapters use termination_grace_s=0 so an outer runner's grace cannot
    expire while the inner runner is also waiting. SIGKILL still needs external
    supervision; inherited locks prevent a surviving backend losing its lock.
    """
    number(termination_grace_s, "termination_grace_s")
    require(0 <= termination_grace_s <= 60, "termination_grace_s must be in [0, 60]")
    lock_fds = tuple(sorted(set(inherited_resource_lock_fds()) | set(resource_lock_fds)))
    for fd in lock_fds:
        require(type(fd) is int and fd >= 3, "invalid resource lock descriptor")
        os.fstat(fd)
    child_env = os.environ.copy() if env is None else dict(env)
    if lock_fds:
        child_env[RESOURCE_LOCK_ENV] = ",".join(map(str, lock_fds))
    else:
        child_env.pop(RESOURCE_LOCK_ENV, None)
    forwarded_fds = tuple(sorted(set(pass_fds) | set(lock_fds)))
    started = time.monotonic()
    with _termination_handlers(), Path(stdout).open("xb") as out, Path(stderr).open("xb") as err:
        p = subprocess.Popen(command, cwd=cwd, stdout=out, stderr=err, env=child_env,
                             stdin=subprocess.DEVNULL, start_new_session=True, pass_fds=forwarded_fds)
        failure = None
        try:
            while not _leader_exited(p.pid):
                if time.monotonic() - started > timeout_s:
                    failure = "backend execution timeout"
                    break
                if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > output_limit:
                    failure = "backend log size limit exceeded"
                    break
                time.sleep(0.03)
            if not failure and os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > output_limit:
                failure = "backend log size limit exceeded"
        finally:
            for sig in (signal.SIGTERM, signal.SIGHUP):
                signal.signal(sig, signal.SIG_IGN)
            # Also clean up descendants left by a process that exited early.
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            grace_end = time.monotonic() + termination_grace_s
            while not _leader_exited(p.pid) and time.monotonic() < grace_end:
                time.sleep(0.01)
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        require(failure is None, failure)
        require(p.returncode == 0, f"backend exited {p.returncode}; see private stderr.log")
    return time.monotonic() - started


def _source_fingerprint():
    root = Path(__file__).parent
    return digest({str(p.relative_to(root)): file_digest(p) for p in sorted(root.rglob("*"))
                   if p.is_file() and p.suffix in {".py", ".java", ".cpp", ".h", ".c", ".ld"}})


def load_completed_capture(path):
    """Verify local completed-run consistency, not a cryptographic attestation."""
    candidate = Path(path).expanduser()
    candidate = candidate / "capture.json" if candidate.is_dir() else candidate
    require(candidate.name == "capture.json" and candidate.is_file() and not candidate.is_symlink(),
            "verified comparison requires a run directory or its regular capture.json; use --unverified for imports")
    directory = candidate.parent
    for name in ("status.json", "request.json"):
        require((directory / name).is_file() and not (directory / name).is_symlink(), f"missing regular run {name}")
    status = load_json(directory / "status.json")
    require(isinstance(status, dict) and status.get("status") == "complete", "run is not complete")
    capture = validate_capture(load_json(candidate))
    require(status.get("capture_sha256") == digest(capture), "completed capture hash mismatch")
    request = load_json(directory / "request.json")
    if isinstance(request, dict) and request.get("schema") == "tycvl.board.request.v1":
        from .board import verify_completed
        return verify_completed(directory, request, status, capture)
    require(isinstance(request, dict) and request.get("schema") == "vfl.request.v1", "invalid run request")
    profile = validate_profile(request.get("profile"))
    trace = validate_trace(request.get("trace"))
    compatible_input(profile, trace)
    validate_capture(capture, profile, trace)
    identities = {"input_sha256": digest(trace), "profile_sha256": digest(profile),
                  "experiment_sha256": experiment_digest(profile, trace)}
    manifest = capture["manifest"]
    require(manifest.get("tool") == "TycVirtualLab" and isinstance(manifest.get("tool_version"), str)
            and manifest["tool_version"], "capture lacks runner identity")
    require(isinstance(manifest.get("tool_source_sha256"), str) and len(manifest["tool_source_sha256"]) == 64,
            "capture lacks runner source fingerprint")
    require(manifest.get("request_id") == request.get("request_id") and manifest.get("request_id"), "run request identity differs")
    require(request.get("identities") == identities, "run request identity hashes differ")
    for key, expected in identities.items():
        require(manifest.get(key) == expected, f"completed run {key} differs")
    expected_kind = profile["backend"].get("execution_kind", "synthetic")
    require(manifest["execution_kind"] == status.get("execution_kind") == expected_kind, "completed run execution kind differs")
    require(status.get("frames") == len(capture["frames"]), "completed run frame count differs")
    return capture


def doctor(profile_path):
    path, profile = resolve_profile(profile_path)
    issues = []
    try:
        asset_records = assets(profile, path.parent)
    except (LabError, OSError) as exc:
        asset_records = []
        issues.append(str(exc))
    backend = profile["backend"]
    if backend["kind"] == "external":
        try:
            _command(backend, path.parent, Path("request.json"), Path("capture.json"), Path("."))
            _hold(backend, path.parent)
        except LabError as exc:
            issues.append(str(exc))
    return {"schema": "vfl.doctor.v1", "profile_id": profile["id"], "ready": not issues,
            "execution_kind": backend.get("execution_kind", "synthetic"),
            "assets": [{"role": a["role"], "sha256": a["sha256"]} for a in asset_records],
            "issues": issues, "scope": "Configuration and declared assets; does not prove emulator/device support"}


def run_capture(profile_path, trace_path, output_dir):
    from .identity import validate_target, validate_asset_targets
    path, profile = resolve_profile(profile_path)
    trace = validate_trace(load_json(trace_path))
    compatible_input(profile, trace)
    require(len(trace["frames"]) * sum(bus["pixels"] * 6 for bus in profile["buses"]) < MAX_JSON_BYTES,
            "RGB payload alone exceeds capture size limit; reduce frames or pixels")
    recorded_assets = assets(profile, path.parent)
    inspected_assets = validate_asset_targets(profile, recorded_assets)
    source_fingerprint = _source_fingerprint()
    output = private_path(output_dir)
    require(not output.exists(), "run directory already exists; choose a fresh path")
    output.mkdir(parents=True, mode=0o700)
    profile = copy.deepcopy(profile)
    for asset in profile.get("firmware", []):
        asset["path"] = str(_path(asset["path"], path.parent))
    identities = {"input_sha256": digest(trace), "profile_sha256": digest(profile),
                  "experiment_sha256": experiment_digest(profile, trace)}
    request_id = secrets.token_hex(16)
    request = {"schema": "vfl.request.v1", "profile": profile, "trace": trace, "workdir": str(output),
               "request_id": request_id, "identities": identities}
    write_json(output / "request.json", request)
    started = time.monotonic()
    try:
        backend = profile["backend"]
        expected_kind = backend.get("execution_kind", "synthetic")
        with resource_lock(backend, path.parent, output) as lock_fd:
            if backend["kind"] == "demo":
                from .demo import capture
                result = capture(profile, trace)
            else:
                target = output / "adapter.capture.json"
                command = _command(backend, path.parent, output / "request.json", target, output)
                cwd = _path(backend["cwd"], path.parent) if backend.get("cwd") else output
                env = os.environ.copy()
                extra_env = backend.get("env", {})
                require(isinstance(extra_env, dict) and all(isinstance(k, str) and isinstance(v, str) and "\x00" not in k+v and "=" not in k for k,v in extra_env.items()), "invalid backend environment")
                env.update(extra_env)
                run_process(command, cwd, output / "stdout.log", output / "stderr.log", backend.get("timeout_s", 300), env,
                            resource_lock_fds=() if lock_fd is None else (lock_fd,))
                require(target.is_file() and not target.is_symlink(), "backend produced no regular capture file")
                result = load_json(target)
        validate_capture(result, profile, trace)
        if backend["kind"] == "external":
            require(result["manifest"].get("request_id") == request_id,
                    "adapter request_id missing or differs; stale output rejected")
            for key, expected in identities.items():
                require(result["manifest"].get(key) == expected,
                        f"adapter identity {key} missing or differs")
        require(result["manifest"]["execution_kind"] == expected_kind, "adapter execution kind differs from profile")
        require(assets(profile, path.parent) == recorded_assets, "firmware assets changed during execution")
        require(_source_fingerprint() == source_fingerprint, "runner source changed during execution")
        manifest = result["manifest"]
        # These identity fields come only from the runner, never from a backend's claim.
        manifest.update({"execution_scope": execution_scope(manifest), "tool": "TycVirtualLab", "tool_version": __version__,
                         "python_version": sys.version.split()[0],
                         "tool_source_sha256": source_fingerprint,
                         "target": validate_target(profile.get("target")), "asset_inspection": inspected_assets,
                         **identities, "request_id": request_id, "assets": recorded_assets,
                         "duration_s": time.monotonic() - started})
        validate_capture(result, profile, trace)
        write_json(output / "capture.json", result)
        write_json(output / "status.json", {"status": "complete", "capture_sha256": digest(result),
                                            "execution_kind": expected_kind, "frames": len(result["frames"])})
        return output / "capture.json"
    except BaseException as exc:
        write_json(output / "status.json", {"status": "failed", "error": str(exc), "error_type": type(exc).__name__})
        raise
