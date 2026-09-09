#!/usr/bin/env python3
"""Docker acceptance for the concurrent, long-running standing node.

The driver intentionally checks public behavior: immutable admissions, client
results, concurrent intervals, cooperative scheduling, restart recovery, and
bounded mesh faults. Protocol/store unit tests own internal data structures and
log formatting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable


PARTIES = [f"party{party}" for party in range(5)]
NODE_RPC_SERVERS = ",".join(
    f"172.33.0.{party + 10}:16180" for party in range(5)
)
NODE_CLIENT_TRANSPORT_SERVERS = ",".join(
    ["172.33.0.10:10000"]
    + [f"172.33.0.{party + 10}:{9000 + party}" for party in range(1, 5)]
)
COORDINATOR = "coordinator:31415"
HEX_ID = re.compile(r"^[0-9a-f]{64}$")


class AcceptanceFailure(RuntimeError):
    pass


@dataclass
class ClientJob:
    label: str
    container: str
    process: subprocess.Popen[str]
    stream: Any
    log: Path
    expected: list[int]
    outputs: int


def execution_id(number: int) -> str:
    return f"{number:064x}"


class Harness:
    def __init__(self, campaign: str) -> None:
        self.campaign = campaign
        self.root = Path(__file__).resolve().parents[2]
        self.compose_file = self.root / "docker-compose.standing-concurrency.yml"
        self.project = os.environ.get("PROJECT_NAME", f"stoffel-standing-{campaign}")
        self.wait_seconds = int(os.environ.get("WAIT_TIMEOUT_SECS", "900"))
        default_coordination = "120" if campaign == "concurrency" else "30"
        default_protocol = "600" if campaign == "concurrency" else "45"
        self.coordination_seconds = int(
            os.environ.get("COORDINATION_TIMEOUT_SECS", default_coordination)
        )
        self.protocol_seconds = int(
            os.environ.get("PROTOCOL_TIMEOUT_SECS", default_protocol)
        )
        configured_state = os.environ.get("STOFFEL_STANDING_STATE_DIR")
        self.state = (
            Path(configured_state)
            if configured_state
            else Path(tempfile.mkdtemp(prefix=f"stoffel-standing-{campaign}."))
        )
        pool_id = os.environ.get("STOFFEL_STANDING_POOL_ID") or hashlib.sha256(
            b"stoffel-standing-compose-pool-v1\0"
            + self.project.encode()
            + b"\0"
            + str(self.state.resolve()).encode()
        ).hexdigest()
        if not HEX_ID.fullmatch(pool_id) or int(pool_id, 16) == 0:
            raise AcceptanceFailure("STOFFEL_STANDING_POOL_ID must be nonzero 64-hex")
        self.keep_state = os.environ.get("STOFFEL_KEEP_STANDING_STATE", "0") == "1"
        self.image = os.environ.get(
            "STOFFEL_STANDING_NODE_IMAGE", "stoffel-standing-node:local"
        )
        self.env = os.environ.copy()
        self.manages_client_certificates = "STOFFEL_STANDING_CLIENT_CERTS_DIR" not in self.env
        if self.manages_client_certificates:
            self.env["STOFFEL_STANDING_CLIENT_CERTS_DIR"] = str(
                (self.state / "client-certificates").resolve()
            )
        self.env.update(
            {
                "STOFFEL_STANDING_STATE_DIR": str(self.state),
                "STOFFEL_STANDING_POOL_ID": pool_id,
                "STOFFEL_EXECUTION_COORDINATION_TIMEOUT_SECONDS": str(
                    self.coordination_seconds
                ),
                "STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS": str(self.protocol_seconds),
                "RUST_LOG": os.environ.get("STOFFEL_ACCEPTANCE_RUST_LOG", "info"),
            }
        )
        self.paused: set[str] = set()
        self.client_jobs: list[ClientJob] = []
        self.network = ""
        self.programs: dict[str, str] = {}
        self.allocation_digests: dict[str, str] = {}

    def command(
        self,
        args: list[str],
        *,
        check: bool = True,
        capture: bool = False,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            cwd=self.root,
            env=self.env,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            output = f"\n{result.stdout}" if capture and result.stdout else ""
            raise AcceptanceFailure(
                f"command failed ({result.returncode}): {' '.join(args)}{output}"
            )
        return result

    def compose_args(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "--project-name",
            self.project,
            "--file",
            str(self.compose_file),
            *args,
        ]

    def compose(self, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return self.command(self.compose_args(*args), **kwargs)

    def logs(self, party: str | None = None, tail: int | None = None) -> str:
        args = ["logs", "--no-color"]
        if tail is not None:
            args.extend(["--tail", str(tail)])
        args.extend([party] if party else [*PARTIES, "coordinator"])
        return self.compose(*args, check=False, capture=True).stdout or ""

    def require_source(self, variable: str, marker: str, *, require_git: bool) -> Path:
        raw = self.env.get(variable, "")
        path = Path(raw)
        if not path.is_absolute() or not path.is_dir() or not (path / marker).is_file():
            raise AcceptanceFailure(
                f"{variable} must be an absolute source tree containing {marker}"
            )
        if require_git:
            result = self.command(
                ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
                check=False,
                capture=True,
            )
            if result.returncode != 0:
                raise AcceptanceFailure(f"{variable} must be a Git checkout")
        resolved = path.resolve()
        self.env[variable] = str(resolved)
        return resolved

    def initialize(self, fixtures: dict[str, str]) -> None:
        for tool in ("docker", "git"):
            if shutil.which(tool) is None:
                raise AcceptanceFailure(f"required tool not found: {tool}")
        coordinator = self.require_source(
            "STOFFEL_COORDINATOR_CONTEXT",
            "crates/off-chain/Cargo.toml",
            require_git=True,
        )
        networking = self.require_source(
            "STOFFEL_NETWORK_CONTEXT", "Cargo.toml", require_git=True
        )
        if self.coordination_seconds < 8:
            raise AcceptanceFailure("COORDINATION_TIMEOUT_SECS must be at least 8")

        self.compose(
            "--profile", "tools", "down", "--remove-orphans", "--volumes", check=False
        )
        self.reset_control()
        if self.manages_client_certificates:
            client_certificates = Path(self.env["STOFFEL_STANDING_CLIENT_CERTS_DIR"])
            client_certificates.mkdir(parents=True, exist_ok=True)
            for certificate in sorted((self.root / "ids" / "clients").glob("*.crt")):
                shutil.copy2(certificate, client_certificates / certificate.name)
        (self.state / "programs").mkdir(parents=True, exist_ok=True)
        (self.state / "logs").mkdir(parents=True, exist_ok=True)
        print(
            "== Building the exact VM, coordinator, and networking worktrees ==",
            flush=True,
        )
        self.compose("--profile", "tools", "build")
        self.command(["docker", "image", "inspect", self.image], capture=True)
        self.record_provenance(coordinator, networking)
        self.assert_credentials()
        for name, fixture in fixtures.items():
            self.programs[name] = self.install_artifact(fixture)
        self.compose("--profile", "tools", "config", capture=True)

    def record_provenance(self, coordinator: Path, networking: Path) -> None:
        lines = []
        for label, path in (
            ("vm", self.root),
            ("coordinator", coordinator),
            ("networking", networking),
        ):
            git_root = self.command(
                ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                capture=True,
                check=False,
            )
            is_checkout_root = git_root.returncode == 0 and Path(
                git_root.stdout.strip()
            ).resolve() == path.resolve()
            if is_checkout_root:
                head = self.command(
                    ["git", "-C", str(path), "rev-parse", "HEAD"], capture=True
                ).stdout.strip()
                status = self.command(
                    ["git", "-C", str(path), "status", "--short"], capture=True
                ).stdout.rstrip()
            else:
                digest = hashlib.sha256()
                for source in sorted(item for item in path.rglob("*") if item.is_file()):
                    relative = source.relative_to(path)
                    if "target" in relative.parts:
                        continue
                    digest.update(str(relative).encode())
                    digest.update(b"\0")
                    digest.update(source.read_bytes())
                head = f"vendored-sha256:{digest.hexdigest()}"
                status = ""
            lines.extend([f"{label}_context={path}", f"{label}_head={head}", status])
        image = self.command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", self.image],
            capture=True,
        ).stdout.strip()
        lines.append(f"image_id={image}")
        (self.state / "logs" / "build-provenance.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

    def assert_credentials(self) -> None:
        public_only = r"""
unexpected="$(find /app/ids -type f ! -name '*.crt' -print)"
test -z "$unexpected"
test -r /app/ids/server_cert.crt
for n in 0 1 2 3 4; do test -r "/app/ids/nodes/cert${n}.crt"; done
for n in 0 1; do test -r "/app/ids/clients/cert${n}.crt"; done
"""
        self.command(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "/bin/sh",
                self.image,
                "-ec",
                public_only,
            ]
        )

        isolated = r"""
cert=/run/secrets/stoffel_identity.crt
key=/run/secrets/stoffel_identity.key
test "$(find /run/secrets -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2
test "$(sha256sum "$cert" | cut -d ' ' -f 1)" = "$EXPECTED_CERT"
test "$(sha256sum "$key" | cut -d ' ' -f 1)" = "$EXPECTED_KEY"
test -z "$(find /app /run/secrets -type f \( -name '*.der' -o -name '*.key' \) ! -path "$key" -print)"
"""
        credentials = [
            *[
                (
                    f"party{slot}",
                    self.root / f"ids/nodes/cert{slot}.crt",
                    self.root / f"ids/nodes/key{slot}.der",
                )
                for slot in range(5)
            ],
            *[
                (
                    f"client{slot}",
                    self.root / f"ids/clients/cert{slot}.crt",
                    self.root / f"ids/clients/key{slot}.der",
                )
                for slot in range(2)
            ],
        ]
        for service, cert, key in credentials:
            cert_hash = hashlib.sha256(cert.read_bytes()).hexdigest()
            key_hash = hashlib.sha256(key.read_bytes()).hexdigest()
            self.compose(
                "--profile",
                "tools",
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "--env",
                f"EXPECTED_CERT={cert_hash}",
                "--env",
                f"EXPECTED_KEY={key_hash}",
                "--entrypoint",
                "/bin/sh",
                service,
                "-ec",
                isolated,
            )

    def install_artifact(self, fixture: str) -> str:
        output = self.command(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "/app/stoffel-run",
                self.image,
                "--print-program-id",
                fixture,
            ],
            capture=True,
        ).stdout
        matches = re.findall(r"[0-9a-f]{64}", output)
        if not matches:
            raise AcceptanceFailure(f"could not derive program ID for {fixture}")
        program = matches[-1]
        self.command(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "/bin/sh",
                "--volume",
                f"{self.state / 'programs'}:/out",
                self.image,
                "-ec",
                f"cp '{fixture}' '/out/{program}.stflb'",
            ]
        )
        return program

    def reset_control(self) -> None:
        for party in PARTIES:
            control = self.state / party / "control"
            shutil.rmtree(control, ignore_errors=True)
            (control / "commands").mkdir(parents=True, exist_ok=True)
            (control / "events" / party).mkdir(parents=True, exist_ok=True)

    def marker_count(self, party: str, marker: str) -> int:
        return self.logs(party).count(marker)

    def reservoir_rebuild_count(self, party: str) -> int:
        return sum(
            "standing preprocessing agreement:" in line
            and "action=Rebuild" in line
            for line in self.logs(party).splitlines()
        )

    def start_nodes(
        self, expected_programs: int, expected_rebuild: bool | None = None
    ) -> None:
        baseline = {
            party: (
                self.marker_count(party, "standing node ready:"),
                self.marker_count(party, "standing reservoir ready:"),
                self.reservoir_rebuild_count(party),
            )
            for party in PARTIES
        }
        self.compose("up", "--no-build", "--detach", *PARTIES)
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            ready = True
            for party in PARTIES:
                container = self.compose(
                    "ps", "--all", "--quiet", party, capture=True
                ).stdout.strip()
                if not container:
                    ready = False
                    continue
                state = self.command(
                    ["docker", "inspect", "--format", "{{.State.Status}}", container],
                    check=False,
                    capture=True,
                ).stdout.strip()
                before_node, before_reservoir, _ = baseline[party]
                if (
                    state != "running"
                    or self.marker_count(party, "standing node ready:") <= before_node
                    or self.marker_count(party, "standing reservoir ready:")
                    < before_reservoir + expected_programs
                ):
                    ready = False
            if ready:
                if expected_rebuild is not None:
                    expected = expected_programs if expected_rebuild else 0
                    agreed_generations: dict[str, str] | None = None
                    for party in PARTIES:
                        observed = self.reservoir_rebuild_count(party) - baseline[party][2]
                        if observed != expected:
                            raise AcceptanceFailure(
                                f"{party} rebuilt {observed} reservoirs; expected {expected}"
                            )
                        ready_lines = [
                            line
                            for line in self.logs(party).splitlines()
                            if "standing reservoir ready:" in line
                        ][baseline[party][1] :]
                        generations = {
                            match.group(1): match.group(2)
                            for line in ready_lines
                            if (
                                match := re.search(
                                    r"program=([0-9a-f]{64}).*generation=([0-9a-f]{64})",
                                    line,
                                )
                            )
                        }
                        if len(generations) != expected_programs:
                            raise AcceptanceFailure(
                                f"{party} did not report {expected_programs} complete reservoir generations"
                            )
                        if agreed_generations is None:
                            agreed_generations = generations
                        elif generations != agreed_generations:
                            raise AcceptanceFailure(
                                f"startup reservoir generations diverged on {party}"
                            )
                return
            time.sleep(2)
        raise AcceptanceFailure(
            "timed out waiting for five standing nodes and reservoirs"
        )

    def node_snapshot(self) -> dict[str, tuple[str, str]]:
        snapshot = {}
        for party in PARTIES:
            container = self.compose(
                "ps", "--quiet", party, capture=True
            ).stdout.strip()
            identity = self.command(
                ["docker", "inspect", "--format", "{{.Id}} {{.State.Pid}}", container],
                capture=True,
            ).stdout.strip()
            snapshot[party] = tuple(identity.split())  # type: ignore[assignment]
        return snapshot

    def assert_snapshot(self, expected: dict[str, tuple[str, str]]) -> None:
        if self.node_snapshot() != expected:
            raise AcceptanceFailure("a standing party container or process changed")

    def publish(self, party: str, filename: str, payload: str) -> None:
        directory = self.state / party / "control" / "commands"
        temporary = directory / f".{filename}.{os.getpid()}"
        temporary.write_text(payload + "\n", encoding="utf-8")
        os.replace(temporary, directory / filename)

    def publish_all(self, filename: str, payload: dict[str, Any] | str) -> None:
        encoded = (
            payload
            if isinstance(payload, str)
            else json.dumps(payload, separators=(",", ":"))
        )
        for party in PARTIES:
            self.publish(party, filename, encoded)

    def assert_control_file_rejected(
        self,
        sequence: int,
        payload: str,
        snapshot: dict[str, tuple[str, str]],
    ) -> None:
        self.publish_all(f"{sequence:020}.json", payload)
        for party in PARTIES:
            self.wait_event(
                party,
                lambda item: item.get("_filename") == f"{sequence:020}.json"
                and item.get("outcome") == "rejected",
                f"invalid command sequence {sequence}",
                20,
            )
        self.assert_snapshot(snapshot)

    def event_files(self, party: str) -> Iterable[tuple[Path, dict[str, Any]]]:
        directory = self.state / party / "control" / "events" / party
        for path in directory.glob("*.json"):
            try:
                event = json.loads(path.read_text(encoding="utf-8"))
                event["_filename"] = path.name
                event["_mtime_ns"] = path.stat().st_mtime_ns
                yield path, event
            except (OSError, json.JSONDecodeError):
                continue

    def find_event(
        self, party: str, predicate: Callable[[dict[str, Any]], bool]
    ) -> dict[str, Any] | None:
        for _, event in self.event_files(party):
            if predicate(event):
                return event
        return None

    def wait_event(
        self,
        party: str,
        predicate: Callable[[dict[str, Any]], bool],
        description: str,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + (timeout or self.wait_seconds)
        while time.monotonic() < deadline:
            event = self.find_event(party, predicate)
            if event is not None:
                return event
            time.sleep(0.2)
        raise AcceptanceFailure(f"timed out waiting for {description} on {party}")

    def expect_command(
        self,
        sequence: int,
        accepted: bool = True,
        parties: Iterable[str] = PARTIES,
        timeout: int | None = None,
    ) -> dict[str, dict[str, Any]]:
        events = {}
        for party in parties:
            event = self.wait_event(
                party,
                lambda item, sequence=sequence: item.get("_filename")
                == f"{sequence:020}.json",
                f"command sequence {sequence}",
                timeout,
            )
            expected = "event" if accepted else "rejected"
            if event.get("outcome") != expected:
                raise AcceptanceFailure(
                    f"command sequence {sequence} on {party} was {event.get('outcome')}, expected {expected}: {event}"
                )
            events[party] = event
        return events

    @staticmethod
    def node_event(record: dict[str, Any]) -> dict[str, Any]:
        event = record.get("event", {})
        return event if isinstance(event, dict) else {}

    @classmethod
    def event_execution_id(cls, record: dict[str, Any]) -> str | None:
        value = cls.node_event(record).get("execution_id")
        if isinstance(value, str):
            return value
        if isinstance(value, list) and len(value) == 32:
            try:
                return bytes(value).hex()
            except (TypeError, ValueError):
                pass
        return None

    def expect_ready(
        self,
        sequence: int,
        execution: dict[str, Any],
        timeout: int | None = None,
    ) -> dict[str, dict[str, Any]]:
        acknowledgements = self.expect_command(sequence, timeout=timeout)
        for party, event in acknowledgements.items():
            preparing = self.node_event(event)
            if preparing.get("event") != "preparing":
                raise AcceptanceFailure(
                    f"command sequence {sequence} was not acknowledged as Preparing on {party}: {event}"
                )

        ready = {}
        for party in PARTIES:
            event = self.wait_event(
                party,
                lambda item, identifier=execution["execution_id"]: self.event_execution_id(item)
                == identifier
                and self.node_event(item).get("event")
                in {"ready", "failed", "cancelled"},
                f"execution {execution['execution_id']} ready",
                timeout,
            )
            if (
                event.get("outcome") != "event"
                or self.node_event(event).get("event") != "ready"
            ):
                raise AcceptanceFailure(
                    f"execution {execution['name']} did not become Ready on {party}: {event}"
                )
            ready[party] = event
        return ready

    def terminal(
        self,
        execution: str,
        party: str,
        phases: set[str] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        phases = phases or {"Completed", "Failed", "Cancelled"}
        lowered = {phase.lower() for phase in phases}
        event = self.wait_event(
            party,
            lambda item: self.event_execution_id(item) == execution
            and self.node_event(item).get("event") in lowered,
            f"terminal execution {execution}",
            timeout,
        )
        observed = str(self.node_event(event).get("event", ""))
        if observed not in lowered:
            raise AcceptanceFailure(
                f"execution {execution} reached {observed}, expected {sorted(lowered)}: {event}"
            )
        return event

    @staticmethod
    def prepare_payload(
        execution: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "operation": "prepare",
            "admission": {
                "execution_id": execution["execution_id"],
                "program_id": execution["program_id"],
                "entry": execution.get("entry", "main"),
                "clients": [
                    {
                        "certificate": client["certificate"],
                        "manifest_slot": client["manifest_slot"],
                    }
                    for client in execution.get("clients", [])
                ],
            },
        }

    def publish_prepare(
        self, sequence: int, execution: dict[str, Any]
    ) -> int:
        self.publish_all(
            f"{sequence:020}.json",
            self.prepare_payload(execution),
        )
        return sequence

    def publish_cancel(
        self, sequence: int, execution: dict[str, Any]
    ) -> int:
        self.publish_all(
            f"{sequence:020}.json",
            {
                "operation": "cancel",
                "execution_id": execution["execution_id"],
            },
        )
        return sequence

    def start_client(
        self, prefix: str, execution: dict[str, Any], client: dict[str, Any]
    ) -> ClientJob:
        certificate = str(client["certificate"])
        match = re.fullmatch(r"cert([01])\.crt", certificate)
        if match is None:
            raise AcceptanceFailure(
                f"unsupported Compose client certificate {certificate!r}"
            )
        identity_slot = int(match.group(1))
        manifest_slot = int(client["manifest_slot"])
        label = (
            f"{prefix}-{execution['name']}-client{identity_slot}-slot{manifest_slot}"
        )
        container = f"{self.project}-{re.sub('[^a-zA-Z0-9_.-]', '-', label)}"
        log = self.state / "logs" / f"{label}.log"
        args = self.compose_args(
            "--profile",
            "tools",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--name",
            container,
            "--entrypoint",
            "/app/stoffel-run",
            f"client{identity_slot}",
            "--client",
            "--execution-id",
            execution["execution_id"],
            "--program",
            f"/var/lib/stoffel/programs/{execution['program_id']}.stflb",
            "--client-slot",
            str(manifest_slot),
        )
        inputs = client.get("inputs", [])
        if inputs:
            args.extend(["--inputs", ",".join(str(value) for value in inputs)])
            input_index = 0
            for admitted in execution.get("clients", []):
                if admitted is client or admitted == client:
                    break
                input_index += len(admitted.get("inputs", []))
            args.extend(["--client-index", str(input_index)])
        args.extend(
            [
                "--outputs",
                str(client["outputs"]),
                "--servers",
                NODE_RPC_SERVERS,
                "--client-transport-servers",
                NODE_CLIENT_TRANSPORT_SERVERS,
                "--off-chain-coord",
                COORDINATOR,
                "--n-parties",
                "5",
                "--threshold",
                "1",
                "--mpc-backend",
                execution["backend"],
                "--mpc-curve",
                execution["curve"],
                "--cert",
                "/run/secrets/stoffel_identity.crt",
                "--key",
                "/run/secrets/stoffel_identity.key",
            ]
        )
        stream = log.open("w", encoding="utf-8")
        process = subprocess.Popen(
            args,
            cwd=self.root,
            env=self.env,
            text=True,
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        job = ClientJob(
            label,
            container,
            process,
            stream,
            log,
            list(client.get("expected", [])),
            int(client["outputs"]),
        )
        self.client_jobs.append(job)
        return job

    def wait_client(self, job: ClientJob, timeout: int | None = None) -> None:
        deadline = time.monotonic() + (timeout or self.protocol_seconds + 30)
        while job.process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.2)
        if job.process.poll() is None:
            self.command(["docker", "rm", "--force", job.container], check=False)
            job.process.wait(timeout=10)
            job.stream.close()
            raise AcceptanceFailure(f"client {job.label} timed out; see {job.log}")
        job.stream.close()
        output = job.log.read_text(encoding="utf-8")
        if job.process.returncode != 0:
            raise AcceptanceFailure(
                f"client {job.label} failed; see {job.log}\n{output}"
            )
        if job.outputs and f"outputs: {job.expected}" not in output:
            raise AcceptanceFailure(
                f"client {job.label} expected {job.expected}; see {job.log}\n{output}"
            )

    def assert_unauthorized_client(self, execution: dict[str, Any]) -> None:
        snapshot = self.node_snapshot()
        rogue = self.start_client(
            "unauthorized",
            execution,
            {
                "certificate": "cert1.crt",
                "manifest_slot": 0,
                "inputs": [99],
                "outputs": 1,
                "expected": [],
            },
        )
        time.sleep(3)
        if rogue.process.poll() is None:
            self.command(["docker", "rm", "--force", rogue.container], check=False)
            rogue.process.wait(timeout=10)
        rogue.stream.close()
        output = rogue.log.read_text(encoding="utf-8")
        if "Received INST:" in output or "outputs:" in output:
            raise AcceptanceFailure("an unadmitted client entered the execution")
        self.assert_snapshot(snapshot)

    def assert_completed(
        self,
        execution: dict[str, Any],
        parties: Iterable[str] = PARTIES,
        timeout: int | None = None,
        yield_kind: str = "cooperative",
    ) -> dict[str, dict[str, Any]]:
        parties = tuple(parties)
        events = {}
        for party in parties:
            event = self.terminal(
                execution["execution_id"],
                party,
                {"Completed", "Failed", "Cancelled"},
                timeout,
            )
            if (
                event.get("outcome") != "event"
                or self.node_event(event).get("event") != "completed"
            ):
                raise AcceptanceFailure(
                    f"execution {execution['name']} failed on {party}: {event}"
                )
            metrics = self.node_event(event).get("metrics", {})
            if yield_kind == "instruction":
                progressed = int(metrics.get("instruction_budget_yields", 0)) > 0
            elif yield_kind == "online":
                progressed = int(metrics.get("online_effect_yields", 0)) > 0
            else:
                progressed = (
                    int(metrics.get("instruction_budget_yields", 0))
                    + int(metrics.get("online_effect_yields", 0))
                    > 0
                )
            if not progressed:
                raise AcceptanceFailure(
                    f"execution {execution['name']} did not cooperatively yield on {party}"
                )
            events[party] = event
        digests = set()
        marker = (
            f"[execution {execution['execution_id']}] reservoir allocation ready:"
        )
        for party in parties:
            lines = [line for line in self.logs(party).splitlines() if marker in line]
            if len(lines) != 1:
                raise AcceptanceFailure(
                    f"expected one destructive allocation for {execution['name']} on {party}, found {len(lines)}"
                )
            match = re.search(r"\bdigest=([0-9a-f]{64})\b", lines[0])
            if match is None:
                raise AcceptanceFailure(
                    f"allocation digest missing for {execution['name']} on {party}"
                )
            digests.add(match.group(1))
        if len(digests) != 1:
            raise AcceptanceFailure(
                f"parties allocated different material for {execution['name']}: {digests}"
            )
        digest = digests.pop()
        prior = self.allocation_digests.get(execution["execution_id"])
        if prior is not None and prior != digest:
            raise AcceptanceFailure(
                f"execution {execution['name']} changed allocation digest"
            )
        if any(
            other_id != execution["execution_id"] and other_digest == digest
            for other_id, other_digest in self.allocation_digests.items()
        ):
            raise AcceptanceFailure(
                f"execution {execution['name']} reused another execution's allocation digest"
            )
        self.allocation_digests[execution["execution_id"]] = digest
        self.assert_inventory_decreases_between_refills(parties)
        return events

    def assert_inventory_decreases_between_refills(
        self, parties: Iterable[str]
    ) -> None:
        reset = re.compile(
            r"(?:standing reservoir ready:|RESERVOIR_REFILL_COMPLETED) program=([0-9a-f]{64})"
        )
        allocation = re.compile(
            r"reservoir allocation ready: program=([0-9a-f]{64}).*"
            r"remaining=PoolAvailability \{ beaver: (\d+), random: (\d+), "
            r"prand_bit: (\d+), prand_int: (\d+) \}"
        )
        for party in parties:
            previous: dict[str, tuple[int, ...]] = {}
            for line in self.logs(party).splitlines():
                if match := reset.search(line):
                    previous.pop(match.group(1), None)
                if match := allocation.search(line):
                    program = match.group(1)
                    remaining = tuple(int(value) for value in match.groups()[1:])
                    before = previous.get(program)
                    if before is not None and any(
                        current > prior
                        for current, prior in zip(remaining, before, strict=True)
                    ):
                        raise AcceptanceFailure(
                            f"{party} inventory increased without a refill for program {program}: {before} -> {remaining}"
                        )
                    previous[program] = remaining

    def run_wave(
        self,
        prefix: str,
        executions: list[dict[str, Any]],
        first_sequence: int = 1,
    ) -> tuple[int, dict[str, dict[str, dict[str, Any]]]]:
        sequence = first_sequence
        prepared = []
        for execution in executions:
            prepared.append((execution, self.publish_prepare(sequence, execution)))
            sequence += 1
        ready = {
            execution["name"]: self.expect_ready(command_sequence, execution)
            for execution, command_sequence in prepared
        }

        clients = [
            self.start_client(prefix, execution, client)
            for execution in executions
            for client in execution.get("clients", [])
        ]
        for client in clients:
            self.wait_client(client)

        completed = {
            execution["name"]: self.assert_completed(execution)
            for execution in executions
        }
        for execution in executions:
            name = execution["name"]
            for party in PARTIES:
                completed[name][party]["_ready_mtime_ns"] = ready[name][party]["_mtime_ns"]
        return sequence, completed

    def assert_overlap(
        self,
        executions: list[dict[str, Any]],
        completed: dict[str, dict[str, dict[str, Any]]],
        parties: Iterable[str] = PARTIES,
    ) -> None:
        for party in parties:
            intervals = [
                (
                    int(completed[item["name"]][party]["_ready_mtime_ns"]),
                    int(completed[item["name"]][party]["_mtime_ns"]),
                )
                for item in executions
            ]
            if max(start for start, _ in intervals) >= min(
                finish for _, finish in intervals
            ):
                raise AcceptanceFailure(
                    f"execution intervals did not overlap on {party}: {intervals}"
                )

    def stop_nodes(self) -> None:
        self.compose("stop", *PARTIES)

    def kill_nodes(self) -> None:
        self.compose("kill", "--signal", "SIGKILL", *PARTIES)

    def remove_party2_preprocessing(self) -> None:
        container = self.compose(
            "ps", "--all", "--quiet", "party2", capture=True
        ).stdout.strip()
        volume = self.command(
            [
                "docker",
                "inspect",
                "--format",
                '{{range .Mounts}}{{if eq .Destination "/var/lib/stoffel/preproc"}}{{.Name}}{{end}}{{end}}',
                container,
            ],
            capture=True,
        ).stdout.strip()
        if not volume:
            raise AcceptanceFailure("could not resolve party2 preprocessing volume")
        self.compose("rm", "--force", "--stop", "party2")
        self.command(["docker", "volume", "rm", volume])

    def pause(self, *parties: str) -> None:
        for party in parties:
            container = self.compose(
                "ps", "--quiet", party, capture=True
            ).stdout.strip()
            self.command(["docker", "pause", container])
            self.paused.add(container)

    def resume_all(self) -> None:
        for container in list(self.paused):
            self.command(["docker", "unpause", container], check=False)
            self.paused.discard(container)

    def discover_network(self) -> None:
        container = self.compose("ps", "--quiet", "party0", capture=True).stdout.strip()
        output = self.command(
            [
                "docker",
                "inspect",
                "--format",
                "{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}",
                container,
            ],
            capture=True,
        ).stdout.splitlines()
        if not output:
            raise AcceptanceFailure("could not discover the standing network")
        self.network = output[0]

    def disconnect(self, *parties: str) -> None:
        for party in parties:
            container = self.compose(
                "ps", "--quiet", party, capture=True
            ).stdout.strip()
            self.command(
                ["docker", "network", "disconnect", "--force", self.network, container]
            )

    def reconnect(self, *parties: str) -> None:
        addresses = {"party3": "172.33.0.13", "party4": "172.33.0.14"}
        for party in parties:
            container = self.compose(
                "ps", "--quiet", party, capture=True
            ).stdout.strip()
            self.command(
                [
                    "docker",
                    "network",
                    "connect",
                    "--ip",
                    addresses[party],
                    self.network,
                    container,
                ],
            )

    def wait_log(self, path: Path, marker: str, timeout: int | None = None) -> None:
        deadline = time.monotonic() + (timeout or self.wait_seconds)
        while time.monotonic() < deadline:
            if path.is_file() and marker in path.read_text(encoding="utf-8"):
                return
            time.sleep(0.1)
        raise AcceptanceFailure(f"timed out waiting for {marker!r} in {path}")

    def malformed_datagrams(self) -> None:
        script = r"""
for endpoint in 172.33.0.10:10000 172.33.0.11:9001 172.33.0.12:9002 172.33.0.13:9003 172.33.0.14:9004; do
  host=${endpoint%:*}; port=${endpoint##*:}
  printf 'not-a-quic-frame' | nc -u -w 1 "$host" "$port" || true
done
"""
        self.compose(
            "--profile",
            "tools",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--entrypoint",
            "/bin/sh",
            "client1",
            "-ec",
            script,
        )

    def roster_guards(self) -> None:
        common = [
            "--standing-node",
            "--party-id",
            "0",
            "--n-parties",
            "5",
            "--threshold",
            "1",
            "--pool-id",
            execution_id(240),
            "--control-dir",
            "/tmp/control",
            "--program-dir",
            "/tmp/programs",
            "--client-cert-dir",
            "/app/ids/clients",
            "--off-chain-coord",
            COORDINATOR,
            "--bind",
            "127.0.0.1:19000",
            "--rpc-bind",
            "127.0.0.1:19001",
        ]
        for service, roster, expected_error in (
            ("party1", "/app/ids/nodes", "does not match"),
            (
                "party0",
                "/app/ids/missing-party-roster",
                "read standing party certificate",
            ),
        ):
            result = self.compose(
                "--profile",
                "tools",
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "--entrypoint",
                "/app/stoffel-run",
                service,
                *common,
                "--party-cert-dir",
                roster,
                "--cert",
                "/run/secrets/stoffel_identity.crt",
                "--key",
                "/run/secrets/stoffel_identity.key",
                check=False,
                capture=True,
            )
            if result.returncode == 0:
                raise AcceptanceFailure(
                    f"{service} accepted an invalid party certificate roster"
                )
            if expected_error not in (result.stdout or ""):
                raise AcceptanceFailure(
                    f"{service} failed before enforcing its party roster:\n{result.stdout}"
                )

    def cleanup(self, success: bool) -> None:
        self.resume_all()
        if shutil.which("docker") is not None:
            for job in self.client_jobs:
                if job.process.poll() is None:
                    self.command(
                        ["docker", "rm", "--force", job.container], check=False
                    )
                    try:
                        job.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        job.process.kill()
                        job.process.wait()
                if not job.stream.closed:
                    job.stream.close()
        if not success:
            try:
                (self.state / "logs").mkdir(parents=True, exist_ok=True)
                (self.state / "logs" / "failure-party.log").write_text(
                    self.logs(), encoding="utf-8"
                )
            except Exception:
                pass
        if shutil.which("docker") is not None:
            self.compose(
                "--profile",
                "tools",
                "down",
                "--remove-orphans",
                "--volumes",
                check=False,
            )
        if self.keep_state or not success:
            print(
                f"Standing acceptance state retained at {self.state}", file=sys.stderr
            )
        else:
            shutil.rmtree(self.state, ignore_errors=True)


def load_matrix(harness: Harness) -> list[dict[str, Any]]:
    matrix = json.loads(
        (harness.root / "docker/standing-concurrency/matrix.json").read_text(
            encoding="utf-8"
        )
    )["executions"]
    artifact = {
        ("single_client_io", "honeybadger"): "single-hb",
        ("multi_client_io", "honeybadger"): "multi-hb",
        ("output_only_client_io", "honeybadger"): "output-hb",
        ("multi_client_io", "avss"): "multi-avss",
    }
    for item in matrix:
        if not HEX_ID.fullmatch(item["execution_id"]):
            raise AcceptanceFailure(f"invalid execution ID in matrix: {item}")
        item["program_id"] = harness.programs[
            artifact[(item["fixture"], item["backend"])]
        ]
    singles = [
        item
        for item in matrix
        if item["fixture"] == "single_client_io" and item["backend"] == "honeybadger"
    ]
    if (
        len(matrix) != 6
        or len({item["execution_id"] for item in matrix}) != 6
        or len(singles) != 3
        or {item["backend"] for item in matrix} != {"honeybadger", "avss"}
        or not any(len(item["clients"]) > 1 for item in matrix)
        or not any(
            any(client["outputs"] == 0 for client in item["clients"])
            and any(not client["inputs"] for client in item["clients"])
            for item in matrix
        )
        or singles[0]["clients"][0]["inputs"] != singles[1]["clients"][0]["inputs"]
        or singles[2]["clients"][0]["inputs"] == singles[0]["clients"][0]["inputs"]
    ):
        raise AcceptanceFailure(
            "matrix does not cover same-program same/different inputs"
        )
    return matrix


def simple_execution(
    name: str,
    number: int,
    program: str,
    value: int,
    expected: int,
    backend: str = "honeybadger",
) -> dict[str, Any]:
    return {
        "name": name,
        "execution_id": execution_id(number),
        "program_id": program,
        "backend": backend,
        "curve": "bls12-381",
        "clients": [
            {
                "certificate": "cert0.crt",
                "manifest_slot": 0,
                "inputs": [value],
                "outputs": 1,
                "expected": [expected],
            }
        ],
    }


def run_concurrency(harness: Harness) -> None:
    harness.initialize(
        {
            "single-hb": "/app/standing-fixtures/single-client-io-honeybadger.stflb",
            "multi-hb": "/app/standing-fixtures/multi-client-io-honeybadger.stflb",
            "output-hb": "/app/standing-fixtures/output-only-client-io-honeybadger.stflb",
            "multi-avss": "/app/standing-fixtures/multi-client-io-avss.stflb",
            "cpu-hb": "/app/standing-fixtures/cpu-fairness-honeybadger.stflb",
        }
    )
    matrix = load_matrix(harness)

    print("== Concurrent HoneyBadger/AVSS matrix ==", flush=True)
    harness.start_nodes(expected_programs=5)
    snapshot = harness.node_snapshot()
    sequence, completed = harness.run_wave("fresh", matrix)
    harness.assert_overlap(matrix, completed)

    cpu = [
        {
            "name": "cpu-long",
            "execution_id": execution_id(27),
            "program_id": harness.programs["cpu-hb"],
            "entry": "cpu_long",
            "backend": "honeybadger",
            "clients": [],
        },
        {
            "name": "cpu-short",
            "execution_id": execution_id(28),
            "program_id": harness.programs["cpu-hb"],
            "entry": "cpu_short",
            "backend": "honeybadger",
            "clients": [],
        },
    ]
    sequence, cpu_completed = harness.run_wave("fresh", cpu, sequence)
    harness.assert_overlap(cpu, cpu_completed)
    for item in cpu:
        for party, event in cpu_completed[item["name"]].items():
            metrics = harness.node_event(event)["metrics"]
            if int(metrics.get("instruction_budget_yields", 0)) < 1:
                raise AcceptanceFailure(
                    f"{item['name']} did not yield its instruction budget on {party}"
                )
    for party in PARTIES:
        short = cpu_completed["cpu-short"][party]["_mtime_ns"]
        long = cpu_completed["cpu-long"][party]["_mtime_ns"]
        if int(short) >= int(long):
            raise AcceptanceFailure(
                f"CPU-short did not finish before CPU-long on {party}"
            )
    harness.assert_snapshot(snapshot)

    print("== Retained preprocessing volumes and durable control cursor ==", flush=True)
    harness.kill_nodes()
    harness.start_nodes(expected_programs=5, expected_rebuild=False)
    snapshot = harness.node_snapshot()
    retired = {**matrix[0], "name": "retired-replay"}
    replay = harness.publish_prepare(sequence, retired)
    replay_events = harness.expect_command(replay, accepted=False)
    if any(
        "retired" not in str(event.get("error", "")).lower()
        for event in replay_events.values()
    ):
        raise AcceptanceFailure(
            "retained control state accepted a retired execution ID"
        )
    sequence += 1

    refill_marker = (
        f"RESERVOIR_REFILL_COMPLETED program={harness.programs['single-hb']}"
    )
    refill_baseline = {
        party: harness.marker_count(party, refill_marker) for party in PARTIES
    }
    retained = [
        simple_execution("retained-a", 49, harness.programs["single-hb"], 8, 24),
        simple_execution("retained-b", 50, harness.programs["single-hb"], 5, 15),
        simple_execution("retained-c", 51, harness.programs["single-hb"], 2, 6),
        simple_execution("retained-d", 52, harness.programs["single-hb"], 9, 27),
        simple_execution("retained-e", 53, harness.programs["single-hb"], 12, 36),
        simple_execution("retained-f", 54, harness.programs["single-hb"], 4, 12),
        simple_execution("retained-g", 55, harness.programs["single-hb"], 7, 21),
        simple_execution("retained-h", 56, harness.programs["single-hb"], 11, 33),
        simple_execution("retained-i", 57, harness.programs["single-hb"], 13, 39),
    ]
    sequence, retained_completed = harness.run_wave("retained", retained, sequence)
    harness.assert_overlap(retained, retained_completed)

    refill_deadline = time.monotonic() + harness.wait_seconds
    while time.monotonic() < refill_deadline:
        if all(
            harness.marker_count(party, refill_marker) > refill_baseline[party]
            for party in PARTIES
        ):
            break
        time.sleep(1)
    else:
        raise AcceptanceFailure(
            "single-program reservoir did not refill on every party"
        )

    post_refill = [
        simple_execution("post-refill-a", 58, harness.programs["single-hb"], 3, 9),
        simple_execution("post-refill-b", 59, harness.programs["single-hb"], 10, 30),
    ]
    _, post_refill_completed = harness.run_wave("retained", post_refill, sequence)
    harness.assert_overlap(post_refill, post_refill_completed)
    harness.assert_snapshot(snapshot)

    print("== Asymmetric party2 preprocessing loss and common recovery ==", flush=True)
    harness.stop_nodes()
    harness.reset_control()
    harness.remove_party2_preprocessing()
    harness.start_nodes(expected_programs=5, expected_rebuild=True)
    snapshot = harness.node_snapshot()
    recovered = [
        simple_execution(
            "asymmetric-recovery", 65, harness.programs["single-hb"], 6, 18
        )
    ]
    harness.run_wave("asymmetric", recovered)
    harness.assert_snapshot(snapshot)
    print(
        "Standing concurrency passed: same/different inputs, different programs, "
        "HoneyBadger+AVSS, single/multiple/split client I/O, cooperative CPU fairness, "
        "SIGKILL journal recovery, elastic refill, and asymmetric-store recovery.",
        flush=True,
    )


def prepare_and_run(
    harness: Harness,
    prefix: str,
    execution: dict[str, Any],
    prepare_sequence: int,
    *,
    delayed_party: bool = False,
    unauthorized_probe: bool = False,
) -> None:
    if delayed_party:
        harness.pause("party4")
    command_sequence = harness.publish_prepare(prepare_sequence, execution)
    if delayed_party:
        time.sleep(int(os.environ.get("FAULT_DELAY_SECS", "3")))
        harness.resume_all()
    harness.expect_ready(command_sequence, execution, harness.coordination_seconds + 30)
    if unauthorized_probe:
        harness.assert_unauthorized_client(execution)
    client = harness.start_client(prefix, execution, execution["clients"][0])
    harness.wait_client(client)
    harness.assert_completed(execution, timeout=harness.protocol_seconds + 30)


def run_stalled_sibling(harness: Harness, first_sequence: int) -> int:
    stalled = simple_execution(
        "absent-client", 167, harness.programs["single-hb"], 1, 3
    )
    sibling = simple_execution(
        "runnable-sibling", 168, harness.programs["single-hb"], 5, 15
    )
    for sequence, execution in zip(
        (first_sequence, first_sequence + 1), (stalled, sibling)
    ):
        command_sequence = harness.publish_prepare(sequence, execution)
        harness.expect_ready(
            command_sequence, execution, harness.coordination_seconds + 30
        )

    sibling_client = harness.start_client("fault", sibling, sibling["clients"][0])
    harness.wait_client(sibling_client)
    sibling_events = harness.assert_completed(sibling)

    for party in PARTIES:
        if harness.find_event(
            party,
            lambda event, identifier=stalled["execution_id"]: harness.event_execution_id(event)
            == identifier
            and harness.node_event(event).get("event")
            in {"completed", "failed", "cancelled"},
        ):
            raise AcceptanceFailure(
                f"absent-client execution became terminal before sibling progress on {party}"
            )

    cancel_sequence = first_sequence + 2
    cancel = harness.publish_cancel(cancel_sequence, stalled)
    cancel_events = harness.expect_command(cancel)
    for party, event in cancel_events.items():
        if harness.node_event(event).get("event") != "cancel_accepted":
            raise AcceptanceFailure(f"stalled execution cancellation failed on {party}")
        cancelled = harness.terminal(stalled["execution_id"], party, {"Cancelled"}, 20)
        sibling_finished = int(sibling_events[party]["_mtime_ns"])
        stalled_finished = int(cancelled["_mtime_ns"])
        if sibling_finished >= stalled_finished:
            raise AcceptanceFailure(
                f"stalled execution resolved before sibling completion on {party}"
            )
    return cancel_sequence + 1


def run_adversarial(harness: Harness) -> None:
    harness.initialize(
        {
            "single-hb": "/app/standing-fixtures/single-client-io-honeybadger.stflb",
            "slow-hb": "/app/standing-fixtures/slow-client-io-honeybadger.stflb",
            "single-avss": "/app/standing-fixtures/single-client-io-avss.stflb",
        }
    )
    harness.roster_guards()
    harness.start_nodes(expected_programs=3)
    harness.discover_network()
    snapshot = harness.node_snapshot()

    print("== Malformed control and unauthenticated mesh traffic ==", flush=True)
    harness.assert_control_file_rejected(
        1,
        "{ this is not json",
        snapshot,
    )
    harness.assert_control_file_rejected(
        2,
        "x" * (1024 * 1024 + 1),
        snapshot,
    )
    harness.malformed_datagrams()
    harness.assert_snapshot(snapshot)

    print("== Delayed HoneyBadger and AVSS parties ==", flush=True)
    delayed = simple_execution("hb-delayed", 161, harness.programs["single-hb"], 7, 21)
    prepare_and_run(
        harness,
        "fault",
        delayed,
        3,
        delayed_party=True,
        unauthorized_probe=True,
    )
    avss = simple_execution(
        "avss-delayed", 162, harness.programs["single-avss"], 6, 18, "avss"
    )
    prepare_and_run(harness, "fault", avss, 4, delayed_party=True)

    print(
        "== Runnable sibling progresses past an absent-client execution ==", flush=True
    )
    sequence = run_stalled_sibling(harness, 5)

    print("== One frozen party across two concurrent online executions ==", flush=True)
    online = [
        simple_execution("online-a", 163, harness.programs["slow-hb"], 7, 7),
        simple_execution("online-b", 164, harness.programs["slow-hb"], 11, 11),
    ]
    online_ready = {}
    for item in online:
        command_sequence = harness.publish_prepare(sequence, item)
        sequence += 1
        online_ready[item["name"]] = harness.expect_ready(
            command_sequence, item, harness.coordination_seconds + 30
        )
    input_marker = "masked client inputs received"
    party4_inputs = harness.marker_count("party4", input_marker)
    jobs = [harness.start_client("fault", item, item["clients"][0]) for item in online]
    deadline = time.monotonic() + harness.coordination_seconds + 30
    while harness.marker_count("party4", input_marker) < party4_inputs + len(online):
        if time.monotonic() >= deadline:
            raise AcceptanceFailure(
                "party4 did not enter both concurrent online executions"
            )
        time.sleep(0.01)
    for item in online:
        if harness.find_event(
            "party4",
            lambda event, identifier=item["execution_id"]: harness.event_execution_id(event)
            == identifier
            and harness.node_event(event).get("event")
            in {"completed", "failed", "cancelled"},
        ):
            raise AcceptanceFailure(
                f"{item['name']} became terminal before party4 could be frozen"
            )
    harness.pause("party4")
    try:
        for job in jobs:
            harness.wait_client(job, harness.protocol_seconds + 30)
        online_completed = {}
        for item in online:
            online_completed[item["name"]] = harness.assert_completed(
                item,
                parties=PARTIES[:4],
                timeout=harness.protocol_seconds + 30,
                yield_kind="online",
            )
            for party in PARTIES[:4]:
                online_completed[item["name"]][party]["_ready_mtime_ns"] = (
                    online_ready[item["name"]][party]["_mtime_ns"]
                )
        harness.assert_overlap(online, online_completed, PARTIES[:4])
    finally:
        harness.resume_all()
    for item in online:
        harness.terminal(
            item["execution_id"],
            "party4",
            {"Completed", "Failed", "Cancelled"},
            harness.protocol_seconds + 30,
        )

    print("== Two offline parties fail closed, then the mesh recovers ==", flush=True)
    harness.disconnect("party3", "party4")
    offline = simple_execution("two-offline", 165, harness.programs["single-hb"], 3, 9)
    failure_started = time.monotonic()
    offline_command = harness.publish_prepare(sequence, offline)
    sequence += 1
    try:
        acknowledgements = harness.expect_command(offline_command, timeout=20)
        if any(
            harness.node_event(event).get("event") != "preparing"
            for event in acknowledgements.values()
        ):
            raise AcceptanceFailure("offline Prepare was not acknowledged as Preparing")
        for party in PARTIES:
            failed = harness.terminal(
                offline["execution_id"],
                party,
                {"Failed"},
                harness.coordination_seconds + 20,
            )
            if harness.node_event(failed).get("event") != "failed":
                raise AcceptanceFailure(
                    f"offline Prepare did not fail on {party}: {failed}"
                )
    finally:
        harness.reconnect("party3", "party4")
    if time.monotonic() - failure_started > harness.coordination_seconds + 20:
        raise AcceptanceFailure(
            "two-party outage did not fail within the coordination bound"
        )
    time.sleep(3)

    recovery = simple_execution(
        "mesh-recovery", 166, harness.programs["single-hb"], 4, 12
    )
    prepare_and_run(harness, "fault", recovery, sequence)
    harness.assert_snapshot(snapshot)
    print(
        "Adversarial standing mode passed: invalid rosters, malformed traffic, delayed "
        "HB/AVSS parties, stalled-sibling progress/cancellation, concurrent one-party "
        "online faults, bounded two-party outage, and same-process mesh recovery.",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign", choices=("concurrency", "adversarial"))
    args = parser.parse_args()
    harness = Harness(args.campaign)
    success = False
    try:
        if args.campaign == "concurrency":
            run_concurrency(harness)
        else:
            run_adversarial(harness)
        success = True
        return 0
    except (AcceptanceFailure, subprocess.TimeoutExpired, OSError, ValueError) as error:
        print(f"acceptance failed: {error}", file=sys.stderr)
        return 1
    finally:
        harness.cleanup(success)


if __name__ == "__main__":
    raise SystemExit(main())
