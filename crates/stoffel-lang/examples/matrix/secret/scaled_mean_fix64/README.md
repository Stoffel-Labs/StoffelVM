# Secure Mean with On-Share Division (secret fix64)

Three clients submit one private `fix64` value each; the sum is divided by the public headcount with secure fixed-point division by a constant, so only the mean is ever opened — even the sum stays secret.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=1.5 --client-input 1=2.5 --client-input 2=2
```

Fixed-point client inputs use ordinary values; Q16 scaling is derived from the
program manifest. Secure division is approximate (probabilistic truncation),
so the result is correct to within fixed-point tolerance. The program asserts
its own result.
