# Weighted Fixed-Point Sensor Fusion

Three stations' private fix64 readings are fused with public reliability weights (local share scalings); only the weighted totals are opened.

Run from this directory with the documented client inputs:

```sh
stoffel run . --client-input 0=1 --client-input 0=2 --client-input 1=1.5 --client-input 1=0.5 --client-input 2=2.5 --client-input 2=1
```

The program asserts its own results and prints a summary; a non-zero exit
or a failed assertion means the example regressed.
