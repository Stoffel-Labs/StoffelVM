BEGIN {
  hz = 199.0
  names[1] = "reservation_registry_init"
  names[2] = "mask_pool_prepare"
  names[3] = "reservation_propose_rpc"
  names[4] = "reservation_round_wait"
  names[5] = "reserved_indices_wait"
  names[6] = "reservation_mirror"
  names[7] = "mask_shares_materialize"
  names[8] = "reserved_indices_publish"
  names[9] = "mask_share_batch_build"
  names[10] = "mask_shares_publish"
  names[11] = "input_collection_propose_rpc"
  names[12] = "input_collection_round_wait"
  names[13] = "masked_inputs_wait_reconstruct"
  names[14] = "mask_retire"
  names[15] = "vm_input_hydration"
  printf "%-36s %11s %11s %9s\n", "phase", "wall_ms", "cpu_ms~", "cpu_pct~"
}

/^INPUT_PATH_PHASE / {
  delete values
  for (i = 2; i <= NF; i++) {
    split($i, pair, "=")
    values[pair[1]] = pair[2]
  }
  wall_ms = values["wall_ns"] / 1000000.0
  cpu_ms = values["oncpu_samples"] * 1000.0 / hz
  cpu_pct = wall_ms > 0 ? 100.0 * cpu_ms / wall_ms : 0.0
  printf "%-36s %11.3f %11.3f %8.1f%%\n", names[values["id"]], wall_ms, cpu_ms, cpu_pct
}

/^INPUT_PATH_TOTAL / {
  delete values
  for (i = 2; i <= NF; i++) {
    split($i, pair, "=")
    values[pair[1]] = pair[2]
  }
  wall_ms = values["wall_ns"] / 1000000.0
  cpu_ms = values["oncpu_samples"] * 1000.0 / hz
  cpu_pct = wall_ms > 0 ? 100.0 * cpu_ms / wall_ms : 0.0
  printf "%-36s %11.3f %11.3f %8.1f%%\n", "TOTAL", wall_ms, cpu_ms, cpu_pct
  printf "clients=%s inputs=%s sample_hz=199\n", values["clients"], values["inputs"]
}
