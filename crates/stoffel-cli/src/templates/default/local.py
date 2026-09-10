#!/usr/bin/env python3
"""Run separate coordinator, stoffel-run parties, and the app client on loopback."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    runner = shutil.which(os.environ.get("STOFFEL_RUN_BIN", "stoffel-run"))
    if not runner:
        raise RuntimeError("stoffel-run not found; install the matching Stoffel release or set STOFFEL_RUN_BIN")
    subprocess.run(["stoffel", "build", "--output", "artifacts/program.stflb"], cwd=ROOT, check=True)
    subprocess.run(["cargo", "build", "--bins", "--examples"], cwd=ROOT, check=True)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=ROOT
    ))
    package = next(p for p in metadata["packages"] if Path(p["manifest_path"]).parent == ROOT)
    suffix = ".exe" if os.name == "nt" else ""
    target = Path(metadata["target_directory"]) / "debug"
    coordinator = target / "examples" / ("local-coordinator" + suffix)
    client = target / (package["name"] + suffix)
    config_dir = ROOT / "deploy/local"
    if not config_dir.exists():
        subprocess.run([str(coordinator), "prepare"], cwd=ROOT, check=True)
    config = json.loads((config_dir / "deployment.json").read_text())
    # This helper deliberately runs only the checked-in loopback topology.
    expected_mesh = [f"127.0.0.1:{19200 + 2 * i}" for i in range(5)]
    expected_mesh[0] = "127.0.0.1:20200"  # Leader mesh; bootnode uses 19200.
    expected_rpc = [f"127.0.0.1:{19400 + i}" for i in range(5)]
    if (config["servers"] != expected_mesh or config["node_rpc_addresses"] != expected_rpc
            or config["coordinator_host"] != "127.0.0.1" or config["coordinator_port"] != 19300):
        raise RuntimeError("local.py requires the original loopback config; run remote services separately")
    logs = ROOT / "target/local-logs"
    logs.mkdir(parents=True, exist_ok=True)
    children = []
    handles = []

    def start(name, args):
        log = (logs / f"{name}.log").open("w")
        handles.append(log)
        child = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                 env={**os.environ, "TOKIO_WORKER_THREADS": "2",
                                      "STOFFEL_AUTH_TOKEN": "stoffel-local-example"})
        children.append(child)
        return child

    def wait_for(name, marker, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(child.poll() is not None for child in children):
                raise RuntimeError(f"service exited while starting {name}; see {logs}")
            if marker in (logs / f"{name}.log").read_text(errors="replace"):
                return
            time.sleep(0.1)
        raise TimeoutError(f"{name} did not become ready; see {logs}")

    try:
        start("coordinator", [str(coordinator), "serve"])
        wait_for("coordinator", "Coordinator ready")
        for party in range(5):
            args = [runner, str(ROOT / "artifacts/program.stflb"), "main",
                    "--n-parties", "5", "--threshold", "1", "--mpc-backend", "honeybadger",
                    "--bind", "127.0.0.1:19200" if party == 0 else expected_mesh[party],
                    "--rpc-bind", expected_rpc[party],
                    "--off-chain-coord", "127.0.0.1:19300",
                    "--cert", str(config_dir / f"node-{party}.cert.der"),
                    "--key", str(config_dir / f"node-{party}.key.der"),
                    "--expected-clients", str(config_dir / "client-0.cert.der"),
                    "--client-roster", "0", "--client-input-slots", "0",
                    "--client-input-count", "1", "--client-input-total", "1"]
            args += ["--leader"] if party == 0 else ["--party-id", str(party), "--bootstrap", "127.0.0.1:19200"]
            start(f"node-{party}", args)
            if party == 0:
                wait_for("node-0", "Party listening on")
        # RPC readiness is emitted after the party mesh is established.
        for party in range(5):
            wait_for(f"node-{party}", "Creating MPC engine")
        # The SDK client immediately reserves its mask index. Wait until the
        # leader has completed the coordinator transition and every node has
        # installed its mask share, not merely until the sockets are listening.
        wait_for("node-0", "waiting for reserved input indices")
        print("Five independent stoffel-run nodes are ready. Starting the app client.", flush=True)
        app = subprocess.Popen([str(client), str(config_dir / "deployment.json")], cwd=ROOT)
        children.append(app)
        status = app.wait(timeout=150)
        if status:
            raise RuntimeError(f"app client exited with status {status}; see {logs}")
    finally:
        # Stop only processes owned by this invocation, including on Ctrl-C/failure.
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in reversed(children):
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for handle in handles:
            handle.close()


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        raise SystemExit(str(error) or "Interrupted")
