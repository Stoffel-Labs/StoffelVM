# Coordinator browser transport snapshot

This minimal source snapshot is based on
`Stoffel-Labs/stoffel-mpc-coordinator` commit
`4e65b55f64d735800240070f835b5f3c91676065`, the revision previously locked by
the parent workspace.

Only the `coord-shared` and `off-chain` crates needed by StoffelVM are included.
`off-chain` adds `browser_rpc.rs`, browser-listener lifecycle hooks, and the
`STOFFEL_BROWSER_NODE_RPC_BIND` opt-in used by the private calculator demo.
