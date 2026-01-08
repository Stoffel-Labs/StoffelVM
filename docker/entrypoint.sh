#!/bin/bash
set -e

# StoffelVM Docker Entrypoint Script
# Handles both leader and party node startup with proper coordination

echo "=========================================="
echo "StoffelVM Node Startup"
echo "=========================================="
echo "Role: ${STOFFEL_ROLE}"
echo "Party ID: ${STOFFEL_PARTY_ID}"
echo "Bind Address: ${STOFFEL_BIND_ADDR}"
echo "N Parties: ${STOFFEL_N_PARTIES}"
echo "Threshold: ${STOFFEL_THRESHOLD}"
echo "Program: ${STOFFEL_PROGRAM}"
echo "Entry: ${STOFFEL_ENTRY}"
echo "Bootstrap: ${STOFFEL_BOOTSTRAP_ADDR:-N/A}"
echo "NAT Enabled: ${STOFFEL_ENABLE_NAT:-false}"
echo "STUN Servers: ${STOFFEL_STUN_SERVERS:-N/A}"
echo "=========================================="

# Wait for a host:port to be available (UDP check for QUIC)
wait_for_host() {
    local host=$1
    local port=$2
    local max_attempts=${3:-60}
    local attempt=1

    echo "Waiting for ${host}:${port} to be available (QUIC/UDP)..."

    # For QUIC (UDP), we can't easily check with nc, so we use a simple
    # connectivity test by trying to send a UDP packet and checking if
    # the host is reachable. The application has its own retry logic.
    while [ $attempt -le $max_attempts ]; do
        # Check if host is reachable via ping (basic network connectivity)
        if ping -c 1 -W 1 "$host" >/dev/null 2>&1; then
            # Try UDP connection test with nc -u
            if timeout 1 bash -c "echo '' | nc -u -w 1 $host $port" 2>/dev/null; then
                echo "${host}:${port} appears reachable!"
                return 0
            fi
            # If UDP check is inconclusive, just verify ping works and continue
            # The application will handle connection retries
            echo "Host ${host} is reachable, assuming bootnode is starting..."
            sleep 2
            return 0
        fi
        echo "Attempt ${attempt}/${max_attempts}: ${host} not reachable, waiting..."
        sleep 1
        attempt=$((attempt + 1))
    done

    echo "ERROR: ${host}:${port} did not become available after ${max_attempts} attempts"
    return 1
}

# Build command based on role
build_command() {
    local cmd="/app/stoffel-run"

    # Add program path and entry function
    cmd="${cmd} ${STOFFEL_PROGRAM} ${STOFFEL_ENTRY}"

    if [ "${STOFFEL_ROLE}" = "leader" ]; then
        # Leader mode: runs bootnode + party 0
        cmd="${cmd} --leader"
        cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
        cmd="${cmd} --threshold ${STOFFEL_THRESHOLD}"
    elif [ "${STOFFEL_ROLE}" = "bootnode" ]; then
        # Bootnode-only mode (no program execution)
        cmd="/app/stoffel-run --bootnode"
        cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
    else
        # Regular party mode
        cmd="${cmd} --party-id ${STOFFEL_PARTY_ID}"
        cmd="${cmd} --bootstrap ${STOFFEL_BOOTSTRAP_ADDR}"
        cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
        cmd="${cmd} --threshold ${STOFFEL_THRESHOLD}"
    fi

    # Add optional trace flags
    if [ "${STOFFEL_TRACE_INSTR}" = "true" ]; then
        cmd="${cmd} --trace-instr"
    fi
    if [ "${STOFFEL_TRACE_REGS}" = "true" ]; then
        cmd="${cmd} --trace-regs"
    fi
    if [ "${STOFFEL_TRACE_STACK}" = "true" ]; then
        cmd="${cmd} --trace-stack"
    fi

    # Add NAT traversal flags if enabled
    if [ "${STOFFEL_ENABLE_NAT}" = "true" ]; then
        cmd="${cmd} --nat"
        if [ -n "${STOFFEL_STUN_SERVERS}" ]; then
            cmd="${cmd} --stun-servers ${STOFFEL_STUN_SERVERS}"
        fi
    fi

    echo "$cmd"
}

# Main execution logic
main() {
    # If we're a party (not leader), wait for the bootnode to be ready
    if [ "${STOFFEL_ROLE}" = "party" ] && [ -n "${STOFFEL_BOOTSTRAP_ADDR}" ]; then
        # Parse host and port from bootstrap address
        BOOTSTRAP_HOST=$(echo "${STOFFEL_BOOTSTRAP_ADDR}" | cut -d: -f1)
        BOOTSTRAP_PORT=$(echo "${STOFFEL_BOOTSTRAP_ADDR}" | cut -d: -f2)

        # Add startup delay based on party ID to stagger connections
        # This helps avoid thundering herd issues
        DELAY=$((STOFFEL_PARTY_ID * 2))
        echo "Party ${STOFFEL_PARTY_ID}: waiting ${DELAY}s before connecting..."
        sleep $DELAY

        # Wait for bootnode to be available
        if ! wait_for_host "$BOOTSTRAP_HOST" "$BOOTSTRAP_PORT" 120; then
            echo "Failed to connect to bootnode at ${STOFFEL_BOOTSTRAP_ADDR}"
            exit 1
        fi
    fi

    # Build and execute the command
    CMD=$(build_command)
    echo ""
    echo "Executing: ${CMD}"
    echo "=========================================="
    echo ""

    exec $CMD
}

main "$@"
