#[test]
fn configured_topology_has_a_valid_threshold() {
    let config: toml::Value = toml::from_str(include_str!("../Stoffel.toml")).unwrap();
    let parties = config["mpc"]["parties"].as_integer().unwrap();
    let threshold = config["mpc"]["threshold"].as_integer().unwrap();
    assert!(parties > 0);
    assert!(threshold < parties);
}
