use std::{
    env,
    process::{self, ExitCode},
};

use stoffel::prelude::*;

const PROGRAM: &str = r#"
def gcd(a: int64, b: int64) -> int64:
  var x: int64 = a
  var y: int64 = b
  while y != 0:
    var remainder: int64 = x % y
    x = y
    y = remainder
  return x

def digit_sum(n: int64) -> int64:
  var value: int64 = n
  var total: int64 = 0
  while value != 0:
    total += value % 10
    value = value / 10
  return total

def divisor_count(n: int64) -> int64:
  var divisors: int64 = 0
  var candidate: int64 = 1
  while candidate <= n / candidate:
    if n % candidate == 0:
      divisors += 2
      if candidate == n / candidate:
        divisors -= 1
    candidate += 1
  return divisors

def largest_prime_factor(n: int64) -> int64:
  var value: int64 = n
  var largest: int64 = 1
  var factor: int64 = 2
  while factor <= value / factor:
    while value % factor == 0:
      largest = factor
      value = value / factor
    factor += 1
  if value > 1:
    largest = value
  return largest

def main(input: int64) -> list[int64]:
  return [
    input,
    gcd(input, 360360),
    digit_sum(input),
    divisor_count(input),
    largest_prime_factor(input)
  ]
"#;

fn run() -> stoffel::Result<()> {
    let raw_input = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: complex_clear_cli <positive-integer>");
        process::exit(2);
    });
    let input = raw_input.parse::<i64>().unwrap_or_else(|error| {
        eprintln!("invalid positive integer '{raw_input}': {error}");
        process::exit(2);
    });
    if input < 2 {
        eprintln!("input must be at least 2");
        process::exit(2);
    }

    let values = Stoffel::compile(PROGRAM)?
        .with_input("input", input)
        .execute_clear()?;
    let labels = [
        "input",
        "gcd(input, 360360)",
        "digit sum",
        "divisor count",
        "largest prime factor",
    ];

    println!("Single-VM Stoffel analysis:");
    for (label, value) in labels.iter().zip(&values) {
        println!("  {label}: {value}");
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Stoffel execution failed: {error}");
            ExitCode::FAILURE
        }
    }
}
