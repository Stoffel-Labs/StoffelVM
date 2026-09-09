#!/usr/bin/env python3
"""Compile and run the complete StoffelLang example catalog on standing nodes.

The campaign deliberately uses one long-lived five-party mesh. Every independent
example is prepared before clients are started, so the online phases overlap.
Programs with an ordering dependency are run in a final, explicitly ordered wave.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from acceptance import (
    AcceptanceFailure,
    ClientJob,
    COORDINATOR,
    HEX_ID,
    Harness,
    NODE_CLIENT_TRANSPORT_SERVERS,
    NODE_RPC_SERVERS,
    PARTIES,
    execution_id,
)


PARAMETERIZED_ENTRY_WRAPPERS = {
    "mpc_bitwise_share": """
def __standing_example_main() -> None:
  __example_parameterized_main([Share.from_clear_int(0, 1), Share.from_clear_int(1, 1), Share.from_clear_int(0, 1), Share.from_clear_int(1, 1)], [Share.from_clear_int(1, 1), Share.from_clear_int(0, 1), Share.from_clear_int(1, 1), Share.from_clear_int(0, 1)])
""",
    "mpc_polynomial_unbounded_or": """
def __standing_example_main() -> bool:
  return __example_parameterized_main([Share.from_clear_int(0, 1), Share.from_clear_int(1, 1), Share.from_clear_int(0, 1)])
""",
    "mpc_aes128_transcipher": """
def __standing_example_main() -> int64:
  var ciphertext: list[int64] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  while ciphertext.len() < 128:
    ciphertext.append(0)
  var key: list[secret bool] = []
  var i: int64 = 0
  while i < 128:
    key.append(bit(0))
    i += 1
  return __example_parameterized_main(ciphertext, key)
""",
}

# A full 189-way online fan-out is useful as a stress/profile mode, but the MPC
# dependency can intermittently strand first-round batch multiplications at
# that load even when the VM dispatcher and transport remain healthy. Sixteen
# preserves substantial overlap while the complete catalog has demonstrated
# end-to-end progress on one persistent mesh. The environment override retains
# explicit stress testing at any desired fan-out.
DEFAULT_ALL_EXAMPLES_WAVE_SIZE = 16


# Examples that intentionally rely on a dedicated SDK/Compose harness rather
# than a `# run-args:` line. Zero is a valid smoke input unless a documented
# fixture is more useful.
SPECIAL_CLIENT_INPUTS: dict[str, dict[int, list[str]]] = {
    "mpc_client_federated_average": {
        0: ["1", "2", "3", "4", "5", "6"],
        1: ["7", "8", "9", "10", "11", "12"],
    },
    "mpc_client_private_score": {0: ["100"], 1: ["20"]},
    "mpc_fixed_div_stress": {0: ["1"]},
    "mpc_protocol_coordination": {0: ["1"]},
    "mpc_share_arithmetic": {0: ["2"]},
}

# Canonical Arkworks-compressed BLS12-381 G1 generator, split exactly as the
# DH-PSI and OPRF SDK clients split it into two 24-byte little-endian field
# limbs. Reusing a valid non-identity point is sufficient for the catalog smoke
# run and keeps the VM's strict curve-point validation exercised.
BLS12_381_G1_GENERATOR_LIMBS = (
    "0x5b974974f8c68c30faca94f8c63952694d79731a7d3f197",
    "0xbbc622db0af03afbef1a7af93fe8556c58ac1b173f3a4ea1",
)
SPECIAL_CLIENT_INPUTS.update(
    {
        "mpc_dh_psi": {
            0: list(BLS12_381_G1_GENERATOR_LIMBS) * 1_000,
            1: list(BLS12_381_G1_GENERATOR_LIMBS) * 1_000,
        },
        "mpc_oprf": {0: list(BLS12_381_G1_GENERATOR_LIMBS) * 3},
    }
)

# A legacy local runner required equal input counts from every client. This
# example documents two padding values which its program intentionally never
# reads. Standing admission is schema-driven and supports unequal counts, so
# omit only that explicitly documented padding.
LEGACY_PADDED_CLIENT_INPUT_LIMITS = {
    ("polynomials/secret/cross_correlation", 1): 2,
}


def backend_and_curve(name: str) -> tuple[str, str]:
    if name.startswith("avss_certificate/"):
        return "avss", "p-256"
    if name == "avss_share_auditor":
        return "avss", "bls12-381"
    if name == "mpc_oprf":
        return "avss", "bls12-381"
    if name == "threshold_signatures/threshold_ecdsa_p256":
        return "avss", "p-256"
    if name == "threshold_signatures/threshold_ecdsa_secp256k1":
        return "avss", "secp256k1"
    if name in {
        "threshold_signatures/threshold_schnorr_ed25519",
        "threshold_signatures/threshold_eddsa_ed25519",
    }:
        return "avss", "ed25519"
    return "honeybadger", "bls12-381"


def parse_run_args(source: str) -> tuple[dict[int, list[str]], int]:
    inputs: dict[int, list[str]] = defaultdict(list)
    output_clients = 0
    match = re.search(r"^# run-args:\s*(.*)$", source, re.MULTILINE)
    if match is None:
        return {}, 0
    args = shlex.split(match.group(1))
    index = 0
    while index < len(args):
        if args[index] == "--client-input" and index + 1 < len(args):
            slot, value = args[index + 1].split("=", 1)
            # Preserve boolean spelling through source augmentation so typed
            # client-schema inference can distinguish it from a 64-bit integer.
            # The catalog converts it to the CLI's numeric field spelling only
            # after compilation.
            inputs[int(slot)].append(value)
            index += 2
        elif args[index] == "--expected-output-clients" and index + 1 < len(args):
            output_clients = int(args[index + 1])
            index += 2
        else:
            # Named entry arguments are handled by generated standing wrappers.
            index += 2 if index + 1 < len(args) and args[index].startswith("--") else 1
    return dict(inputs), output_clients


def augment_source(name: str, source: str, _inputs: dict[int, list[str]]) -> tuple[str, str]:
    additions: list[str] = []
    entry = "main"
    if wrapper := PARAMETERIZED_ENTRY_WRAPPERS.get(name):
        source = re.sub(
            r"^def main\(",
            "def __example_parameterized_main(",
            source,
            count=1,
            flags=re.MULTILINE,
        )
        additions.append(wrapper)
        entry = "__standing_example_main"

    return source.rstrip() + "\n" + "\n".join(additions) + "\n", entry


class AllExamplesHarness(Harness):
    def __init__(self, selected_examples: set[str] | None = None) -> None:
        super().__init__("all-examples")
        self.examples_dir = self.root / "crates/stoffel-lang/examples"
        self.selected_examples = selected_examples
        self.client_identities = self.state / "client-identities"
        self.client_certificates = self.state / "client-certificates"
        self.client_host = f"{self.project}-client-host"
        self.client_host_started = False
        self.catalog: list[dict[str, Any]] = []
        self.env.update(
            {
                "STOFFEL_STANDING_CLIENT_CERTS_DIR": str(self.client_certificates),
                "STOFFEL_STANDING_CLIENT_CERT_DIR": "/var/lib/stoffel/client-certs",
                # Keep two ready allocations beyond the currently executing
                # catalog item. With a capacity of one, allocating the first
                # bundle lands exactly on the refill watermark and launches a
                # large background MPC refill beside the online protocol. The
                # catalog executes each unique program once, so capacity two
                # exercises the standing allocation path without turning the
                # run into a refill-contention benchmark.
                "STOFFEL_STANDING_RESERVOIR_BURST_CAPACITY": os.environ.get(
                    "STOFFEL_STANDING_RESERVOIR_BURST_CAPACITY", "2"
                ),
                "STOFFEL_STANDING_EXTRA_ARGS": "--allow-dynamic-preprocessing",
                # A zero value disables the small-fixture override and lets each
                # compiler manifest size its own reservoir.
                "STOFFEL_STANDING_TEST_TRIPLES": "0",
                "RUST_LOG": os.environ.get("STOFFEL_EXAMPLES_RUST_LOG", "warn"),
            }
        )

    def start_client_host(self) -> None:
        """Start one network endpoint that can host every concurrent client.

        Creating hundreds of `docker run` endpoints at once can transiently
        exhaust Docker Desktop's bridge setup and surface misleading
        `No route to host` client failures. The client processes are still all
        independent and concurrent; only their immutable image, mounts, and
        network namespace are shared through `docker exec`.
        """
        if self.client_host_started:
            return
        self.command(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--network",
                self.network,
                "--name",
                self.client_host,
                "--entrypoint",
                "/bin/sh",
                "--volume",
                f"{self.client_certificates}:/run/client-certs:ro",
                "--volume",
                f"{self.client_identities}:/run/client-identities:ro",
                "--volume",
                f"{self.state / 'programs'}:/run/programs:ro",
                "--env",
                f"STOFFEL_AUTH_TOKEN={self.env.get('STOFFEL_AUTH_TOKEN', 'stoffel-standing-compose-token')}",
                "--env",
                f"STOFFEL_EXECUTION_COORDINATION_TIMEOUT_SECONDS={self.coordination_seconds}",
                "--env",
                f"STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS={self.protocol_seconds}",
                "--env",
                f"RUST_LOG={self.env.get('RUST_LOG', 'warn')}",
                self.image,
                "-c",
                "exec sleep infinity",
            ]
        )
        self.client_host_started = True

    def initialize_catalog(self) -> None:
        for tool in ("docker", "git", "cargo", "openssl"):
            if shutil.which(tool) is None:
                raise AcceptanceFailure(f"required tool not found: {tool}")
        coordinator = self.require_source(
            "STOFFEL_COORDINATOR_CONTEXT",
            "crates/off-chain/Cargo.toml",
            require_git=False,
        )
        networking = self.require_source(
            "STOFFEL_NETWORK_CONTEXT", "Cargo.toml", require_git=True
        )
        self.compose(
            "--profile", "tools", "down", "--remove-orphans", "--volumes", check=False
        )
        self.reset_control()
        self.prepare_client_identities()
        # `programs` is the production catalog mounted into every standing
        # node. Content-addressed artifacts from an earlier campaign are still
        # valid bytecode, but leaving them here makes the node warm reservoirs
        # which this run can never execute. More importantly, the harness may
        # observe its expected number of ready markers and start the online
        # wave while those stale programs are still preprocessing. Install an
        # exact catalog for every campaign; durable reservoir volumes remain
        # intact and are reused for IDs which are still present.
        for directory in ("programs", "sources", "artifacts"):
            shutil.rmtree(self.state / directory, ignore_errors=True)
            (self.state / directory).mkdir(parents=True, exist_ok=True)
        (self.state / "logs").mkdir(parents=True, exist_ok=True)

        print("== Building the standing node and host compiler ==", flush=True)
        if os.environ.get("STOFFEL_SKIP_BUILD") == "1":
            print("Using the existing standing-node images (STOFFEL_SKIP_BUILD=1).", flush=True)
        else:
            self.compose("--profile", "tools", "build")
        self.command(
            [
                "cargo",
                "build",
                "-p",
                "stoffellang",
                "-p",
                "stoffel-vm-runner",
                "--bins",
            ]
        )
        self.record_provenance(coordinator, networking)
        self.compile_catalog()
        self.compose("--profile", "tools", "config", capture=True)

    def prepare_client_identities(self) -> None:
        self.client_identities.mkdir(parents=True, exist_ok=True)
        self.client_certificates.mkdir(parents=True, exist_ok=True)
        for slot in range(2):
            shutil.copyfile(
                self.root / f"ids/clients/cert{slot}.crt",
                self.client_certificates / f"cert{slot}.crt",
            )
            shutil.copyfile(
                self.root / f"ids/clients/key{slot}.der",
                self.client_identities / f"key{slot}.der",
            )
        for slot in range(2, 5):
            certificate = self.client_certificates / f"cert{slot}.crt"
            identity = self.client_identities / f"key{slot}.der"
            if identity.is_file() and certificate.is_file():
                valid = self.command(
                    [
                        "openssl",
                        "x509",
                        "-inform",
                        "DER",
                        "-checkend",
                        "3600",
                        "-noout",
                        "-in",
                        str(certificate),
                    ],
                    check=False,
                    capture=True,
                )
                if valid.returncode == 0:
                    continue
            pem_key = self.client_identities / f"key{slot}.pem"
            self.command(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-keyout",
                    str(pem_key),
                    "-out",
                    str(certificate),
                    "-outform",
                    "DER",
                    "-subj",
                    f"/CN=stoffel-standing-example-client-{slot}",
                    "-days",
                    "2",
                ]
            )
            self.command(
                [
                    "openssl",
                    "pkcs8",
                    "-topk8",
                    "-nocrypt",
                    "-in",
                    str(pem_key),
                    "-outform",
                    "DER",
                    "-out",
                    str(identity),
                ]
            )
            pem_key.unlink()

    def compile_catalog_only(self) -> None:
        for directory in ("programs", "sources", "artifacts"):
            shutil.rmtree(self.state / directory, ignore_errors=True)
            (self.state / directory).mkdir(parents=True, exist_ok=True)
        (self.state / "logs").mkdir(parents=True, exist_ok=True)
        self.command(
            [
                "cargo",
                "build",
                "-p",
                "stoffellang",
                "-p",
                "stoffel-vm-runner",
                "--bins",
            ]
        )
        self.compile_catalog()

    def compile_catalog(self) -> None:
        compiler = self.root / "target/debug/stoffellang"
        inspector = self.root / "target/debug/stoffel-run"
        sources = sorted(self.examples_dir.rglob("main.stfl"))
        if len(sources) != 190:
            raise AcceptanceFailure(f"expected 190 canonical examples, found {len(sources)}")
        if self.selected_examples is not None:
            by_name = {
                path.parent.relative_to(self.examples_dir).as_posix(): path for path in sources
            }
            unknown = self.selected_examples - set(by_name)
            if unknown:
                raise AcceptanceFailure(
                    f"unknown canonical examples: {', '.join(sorted(unknown))}"
                )
            sources = [by_name[name] for name in sorted(self.selected_examples)]

        print(f"== Compiling {len(sources)} canonical examples ==", flush=True)
        for number, source_path in enumerate(sources, 1):
            name = source_path.parent.relative_to(self.examples_dir).as_posix()
            source = source_path.read_text(encoding="utf-8")
            run_inputs, output_clients = parse_run_args(source)
            if name in SPECIAL_CLIENT_INPUTS:
                run_inputs = SPECIAL_CLIENT_INPUTS[name]
            augmented, entry = augment_source(name, source, run_inputs)
            safe = name.replace("/", "__")
            compiled_source_dir = self.state / "sources" / safe
            shutil.copytree(
                source_path.parent,
                compiled_source_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("target", "dist"),
            )
            compiled_source = compiled_source_dir / "main.stfl"
            artifact = self.state / "artifacts" / f"{safe}.stflb"
            compiled_source.write_text(augmented, encoding="utf-8")
            backend, curve = backend_and_curve(name)
            result = self.command(
                [
                    str(compiler),
                    "--binary",
                    "--opt-level",
                    "0",
                    "--mpc-backend",
                    backend,
                    "--mpc-curve",
                    curve,
                    "--output",
                    str(artifact),
                    str(compiled_source),
                ],
                check=False,
                capture=True,
            )
            if result.returncode != 0:
                raise AcceptanceFailure(f"compile failed for {name}:\n{result.stdout}")
            report = json.loads(
                self.command(
                    [str(inspector), "--print-program-manifest", str(artifact)],
                    capture=True,
                ).stdout.strip()
            )
            program_id = report["program_id"]
            if not HEX_ID.fullmatch(program_id):
                raise AcceptanceFailure(f"invalid program ID for {name}: {program_id}")
            target = self.state / "programs" / f"{program_id}.stflb"
            if not target.exists():
                shutil.copyfile(artifact, target)

            schemas = sorted(
                report["manifest"]["clients"], key=lambda item: item["client_slot"]
            )
            for schema in schemas:
                slot = int(schema["client_slot"])
                required = len(schema["inputs"])
                values = run_inputs.get(slot, [])
                if required and not values:
                    values = ["0"] * required
                if (limit := LEGACY_PADDED_CLIENT_INPUT_LIMITS.get((name, slot))) is not None:
                    if required != limit or len(values) < limit:
                        raise AcceptanceFailure(
                            f"{name} client {slot} padding contract expected {limit} manifest inputs, got {required}"
                        )
                    values = values[:limit]
                if len(values) != required:
                    raise AcceptanceFailure(
                        f"{name} client {slot} has {len(values)} run inputs, manifest requires {required}"
                    )
                run_inputs[slot] = values
            manifest_slots = {int(schema["client_slot"]) for schema in schemas}
            missing = set(run_inputs) - manifest_slots
            if missing:
                raise AcceptanceFailure(f"{name} manifest omitted input slots {sorted(missing)}")
            if output_clients and not set(range(output_clients)).issubset(manifest_slots):
                raise AcceptanceFailure(
                    f"{name} manifest omitted declared output clients 0..{output_clients - 1}"
                )

            self.catalog.append(
                {
                    "name": name,
                    "program_id": program_id,
                    "entry": entry,
                    "backend": backend,
                    "curve": curve,
                    "dynamic": bool(
                        report["manifest"]["preprocessing_demand"]["dynamic"]
                    ),
                    "clients": [
                        {
                            "certificate": f"cert{int(schema['client_slot'])}.crt",
                            "manifest_slot": int(schema["client_slot"]),
                            "inputs": [
                                {"true": "1", "false": "0"}.get(value, value)
                                for value in run_inputs.get(int(schema["client_slot"]), [])
                            ],
                            "outputs": len(schema["outputs"]),
                        }
                        for schema in schemas
                    ],
                }
            )
            print(f"  [{number:03d}/{len(sources):03d}] {name}", flush=True)

        expected_programs = {
            f"{item['program_id']}.stflb" for item in self.catalog
        }
        installed_programs = {
            path.name for path in (self.state / "programs").glob("*.stflb")
        }
        if installed_programs != expected_programs:
            raise AcceptanceFailure(
                "installed standing-node catalog does not exactly match the compiled catalog"
            )

        report_path = self.state / "logs" / "catalog.json"
        report_path.write_text(json.dumps(self.catalog, indent=2) + "\n", encoding="utf-8")
        print(
            f"Compiled {len(self.catalog)}/{len(sources)}; "
            f"{len({item['program_id'] for item in self.catalog})} unique artifacts; "
            f"{sum(item['dynamic'] for item in self.catalog)} dynamic-demand examples.",
            flush=True,
        )

    def start_catalog_client(
        self, prefix: str, execution: dict[str, Any], client: dict[str, Any]
    ) -> ClientJob:
        self.start_client_host()
        certificate = str(client["certificate"])
        match = re.fullmatch(r"cert([0-4])\.crt", certificate)
        if match is None:
            raise AcceptanceFailure(f"unsupported example client certificate {certificate!r}")
        identity_slot = int(match.group(1))
        manifest_slot = int(client["manifest_slot"])
        label = f"{prefix}-{execution['name'].replace('/', '-')}-client{identity_slot}"
        container = self.client_host
        log = self.state / "logs" / f"{label}.log"
        args = [
            "docker",
            "exec",
            container,
            "/app/stoffel-run",
            "--client",
            "--execution-id",
            execution["execution_id"],
            "--program",
            f"/run/programs/{execution['program_id']}.stflb",
            "--client-slot",
            str(manifest_slot),
        ]
        inputs = client.get("inputs", [])
        if inputs:
            args.extend(["--inputs", ",".join(str(value) for value in inputs)])
            input_index = 0
            for admitted in execution.get("clients", []):
                if admitted is client:
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
                f"/run/client-certs/cert{identity_slot}.crt",
                "--key",
                f"/run/client-identities/key{identity_slot}.der",
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
        job = ClientJob(label, container, process, stream, log, [], int(client["outputs"]))
        self.client_jobs.append(job)
        return job

    def wait_catalog_client(self, job: ClientJob) -> None:
        deadline = time.monotonic() + self.protocol_seconds + 60
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
            raise AcceptanceFailure(f"client {job.label} failed; see {job.log}\n{output}")
        if job.outputs:
            match = re.search(r"outputs:\s*\[(.*?)\]", output, re.DOTALL)
            observed = 0 if match is None or not match.group(1).strip() else match.group(1).count(",") + 1
            if observed != job.outputs:
                raise AcceptanceFailure(
                    f"client {job.label} received {observed} outputs, expected {job.outputs}; see {job.log}"
                )

    def cleanup(self, success: bool) -> None:
        # Remove the shared endpoint first so any still-running `docker exec`
        # clients are interrupted before the base harness waits on them and
        # tears down the Compose network.
        if self.client_host_started and shutil.which("docker") is not None:
            self.command(["docker", "rm", "--force", self.client_host], check=False)
            self.client_host_started = False
        super().cleanup(success)


def run_wave(
    harness: AllExamplesHarness,
    examples: list[dict[str, Any]],
    first_sequence: int,
    first_execution: int,
) -> tuple[int, int]:
    executions = []
    sequence = first_sequence
    number = first_execution
    for example in examples:
        execution = dict(example)
        execution["execution_id"] = execution_id(number)
        number += 1
        executions.append(execution)
        harness.publish_prepare(sequence, execution)
        sequence += 1

    print(f"Waiting for {len(executions)} concurrent preparations...", flush=True)
    for offset, execution in enumerate(executions):
        harness.expect_ready(first_sequence + offset, execution)

    jobs = [
        harness.start_catalog_client("all", execution, client)
        for execution in executions
        for client in execution["clients"]
    ]
    print(f"Started {len(jobs)} clients across {len(executions)} executions.", flush=True)
    for job in jobs:
        harness.wait_catalog_client(job)

    failures = []
    for execution in executions:
        for party in PARTIES:
            event = harness.terminal(
                execution["execution_id"], party, {"Completed", "Failed", "Cancelled"}
            )
            if harness.node_event(event).get("event") != "completed":
                failures.append(
                    {
                        "example": execution["name"],
                        "party": party,
                        "event": harness.node_event(event),
                    }
                )
    if failures:
        raise AcceptanceFailure(f"catalog execution failures: {json.dumps(failures, indent=2)}")
    return sequence, number


def run_all_examples(harness: AllExamplesHarness) -> None:
    harness.initialize_catalog()
    unique_programs = len({item["program_id"] for item in harness.catalog})
    print(f"== Warming {unique_programs} standing reservoirs ==", flush=True)
    harness.start_nodes(expected_programs=unique_programs)
    harness.discover_network()
    snapshot = harness.node_snapshot()

    # Certificate signing is self-contained today, but retaining the explicit
    # keygen-before-sign stage preserves the intended example relationship.
    ordered_names = {"avss_certificate/sign"}
    concurrent = [item for item in harness.catalog if item["name"] not in ordered_names]
    ordered = [item for item in harness.catalog if item["name"] in ordered_names]

    configured_wave_size = os.environ.get(
        "STOFFEL_ALL_EXAMPLES_WAVE_SIZE", str(DEFAULT_ALL_EXAMPLES_WAVE_SIZE)
    )
    try:
        wave_size = int(configured_wave_size)
    except ValueError as error:
        raise AcceptanceFailure(
            "STOFFEL_ALL_EXAMPLES_WAVE_SIZE must be a positive integer"
        ) from error
    if wave_size <= 0:
        raise AcceptanceFailure(
            "STOFFEL_ALL_EXAMPLES_WAVE_SIZE must be a positive integer"
        )
    wave_size = min(wave_size, len(concurrent))
    wave_count = (len(concurrent) + wave_size - 1) // wave_size
    print(
        f"== Running {len(concurrent)} examples in {wave_count} concurrent "
        f"wave(s) of up to {wave_size} ==",
        flush=True,
    )
    sequence, number = 1, 10_000
    for start in range(0, len(concurrent), wave_size):
        wave = concurrent[start : start + wave_size]
        print(
            f"== Concurrent wave {start // wave_size + 1}/{wave_count}: "
            f"{len(wave)} examples ==",
            flush=True,
        )
        sequence, number = run_wave(harness, wave, sequence, number)
    if ordered:
        print(f"== Running {len(ordered)} dependency-ordered examples ==", flush=True)
        run_wave(harness, ordered, sequence, number)
    harness.assert_snapshot(snapshot)
    print(
        f"All {len(harness.catalog)} selected StoffelLang examples completed on the same "
        "standing node processes.",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--compile-only",
        action="store_true",
        help="compile and validate all manifests without starting Docker services",
    )
    parser.add_argument(
        "--example",
        action="append",
        default=[],
        help="run only this canonical example (repeatable; intended for diagnosis)",
    )
    args = parser.parse_args()
    harness = AllExamplesHarness(set(args.example) if args.example else None)
    success = False
    try:
        if args.compile_only:
            harness.compile_catalog_only()
        else:
            run_all_examples(harness)
        success = True
        return 0
    except (AcceptanceFailure, subprocess.TimeoutExpired, OSError, ValueError) as error:
        print(f"all-example acceptance failed: {error}", file=sys.stderr)
        return 1
    finally:
        harness.cleanup(success)


if __name__ == "__main__":
    raise SystemExit(main())
