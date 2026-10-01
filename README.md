# Kyber GA Optimizer

This repository is the technical implementation of my thesis titled by:Multi-Objective Evolutionary Optimization of CRYSTALS-Kyber Parameters for Resource-Constrained IoT Devices, exploring the following question:

> Can we find Kyber-like parameter sets that are smaller, faster, or more bandwidth-efficient than the standard Kyber tiers while still meeting the same security and reliability constraints?

The project builds a full optimization pipeline around the CRYSTALS-Kyber parameter space and searches for Pareto-optimal configurations using a multi-objective genetic algorithm (NSGA-II), backed by a security and failure-probability model derived from the Kyber specification and the reference estimator code.

---

## 1. What this project does

The code enumerates valid Kyber parameter combinations of the form:

- k: module rank
- eta1: secret-noise parameter
- eta2: error-noise parameter
- du: u-compression bits
- dv: v-compression bits

It then filters those candidates against two hard constraints:

1. Security must be at least as strong as the chosen Kyber baseline tier.
2. Decryption failure must stay below a strict reliability threshold.

The optimization objective is to minimize:

- ciphertext size (bandwidth)
- decryption failure probability / log2(delta)

The result is a Pareto front of candidate parameters that are competitive with or better than standard Kyber parameter sets for a given tier.

This repository is not just a toy benchmark. It implements a full workflow:

- define the parameter space
- precompute raw security/failure metrics
- filter feasible candidates
- run NSGA-II to approximate the Pareto front
- validate against exhaustive brute force
- benchmark the selected candidates

---

## 2. High-level architecture

The project is organized into a few focused modules:

### Module 0: sanity check
File: `modules/m0_sanity_check.py`

This validates the building blocks against known reference values:

- Kyber key/ciphertext sizes match the FIPS 203 formulas
- failure-probability estimates match the published Kyber deltas
- security estimates align with the published Core-SVP values for Kyber-512, 768, and 1024

This is the project’s “ground-truth sanity layer” before trusting any non-standard candidate.

### Module 1: parameter-space definition
File: `modules/m1_parameters.py`

This enumerates the valid search space:

- k in {2, 3, 4}
- eta1 in {1, 2, 3, 4, 5}
- eta2 in {1, 2, 3}
- du in {8, 9, 10, 11, 12}
- dv in {3, 4, 5, 6}

The script computes exact size formulas and saves the full candidate list to `results/parameter_space.json`.

### Module 2: coupled precomputation
File: `modules/m2_precompute.py`

This is the expensive stage. For each candidate, it computes:

- log2_delta using the reference Kyber failure model
- security for the public-key and ciphertext MLWE instances
- minimum of the two as the final security score
- size metadata for PK / SK / CT

The lookup table is saved to `results/lookup_table.json`.

Important: the raw security values are baseline-agnostic. Feasibility is computed later based on the chosen tier.

### Module 3: NSGA-II optimization
File: `modules/m3_nsga2.py`

This runs a multi-objective NSGA-II search over the feasible set for a target baseline:

- Kyber-512
- Kyber-768
- Kyber-1024

The objective is:

- minimize ciphertext size
- minimize log2(delta)

The output is a Pareto front saved to files like:

- `results/nsga2_front_kyber512.json`
- `results/nsga2_front_kyber768.json`
- `results/nsga2_front_kyber1024.json`

### Module 4: validation
File: `modules/m4_validate.py`

This checks whether the NSGA-II front matches the true brute-force Pareto front for the same baseline.

It measures:

- coverage
- IGD (inverted generational distance)
- convergence behavior
- whether the optimizer reproduces the exact front

### Module 5: benchmarking
File: `modules/m5_benchmark.py`

This benchmarks candidate parameter sets by instantiating them in `kyber-py` and measuring:

- size
- latency for keygen / encaps / decaps
- peak memory
- Monte Carlo correctness checks

Outputs are saved under `results/benchmark_kyber*.json`.

### Feasibility logic
File: `modules/feasibility.py`

This file answers the question:

> Which candidates are feasible for a given baseline tier?

It uses:

- the security value for that tier’s standard parameter set as a threshold
- a ceiling on decryption failure: log2(delta) <= -128

A candidate is feasible if:

- its security meets or exceeds the baseline threshold
- its decryption failure is below the reliability ceiling

---

## 3. Scientific problem and model

The project is centered on the Kyber parameter-selection tradeoff.

In Kyber, larger noise parameters and different compression levels affect:

- performance
- ciphertext size
- decryption failure probability
- security

The repository models this with two main quantities:

### Security
Security is computed using the LWE estimator from the `estimator` package and the Kyber reference instantiations.

For each candidate:

- the public-key instance is modeled as Xs = CBD(eta1), Xe = CBD(eta1)
- the ciphertext instance is modeled as Xs = CBD(eta1), Xe = CBD(eta2)
- the final security number is the minimum of the two

This is the project’s central security assumption.

### Failure probability (delta)
The project tracks decryption failure using the Kyber failure model. The reference implementation is used as the authoritative source for the lookup table, while `modules/custom_delta.py` provides an independent engineering approximation used for validation and sanity checking.

The threshold for a reliable design is:

- log2(delta) <= -128

This is a core design rule in the project.

---

## 4. Project workflow

From a clean checkout, the normal pipeline is:

1. Check sanity
   ```bash
   uv run python modules/m0_sanity_check.py
   ```

2. Generate the parameter space
   ```bash
   uv run python modules/m1_parameters.py
   ```

3. Precompute security and delta values
   ```bash
   uv run python modules/m2_precompute.py
   ```

4. Search the Pareto front for a target baseline
   ```bash
   uv run python modules/m3_nsga2.py Kyber-512
   uv run python modules/m3_nsga2.py Kyber-768
   uv run python modules/m3_nsga2.py Kyber-1024
   ```

5. Validate the front against brute force
   ```bash
   uv run python modules/m4_validate.py Kyber-512
   uv run python modules/m4_validate.py Kyber-768
   uv run python modules/m4_validate.py Kyber-1024
   ```

6. Benchmark the front candidates
   ```bash
   uv run python modules/m5_benchmark.py Kyber-512
   uv run python modules/m5_benchmark.py Kyber-768
   uv run python modules/m5_benchmark.py Kyber-1024
   ```

7. Optional deeper validation/analysis
   ```bash
   uv run python analysis/model_checks.py
   ```

---

## 5. Results and generated artifacts

The project saves every major stage under the `results/` directory.

### Parameter-space output
- `results/parameter_space.json`

Contains the full enumeration of valid candidates and the summary statistics of the space.

### Lookup table
- `results/lookup_table.json`

Contains the raw values for each candidate:

- k, eta1, eta2, du, dv
- security
- security_pk
- security_ct
- security_matzov
- log2_delta
- pk_bytes
- sk_bytes
- ct_bytes

### Pareto-front outputs
- `results/nsga2_front_kyber512.json`
- `results/nsga2_front_kyber768.json`
- `results/nsga2_front_kyber1024.json`

These hold the optimized candidates for each baseline tier.

### Validation outputs
- `results/validation_kyber512.json`
- `results/validation_kyber768.json`
- `results/validation_kyber1024.json`

These summarize coverage, IGD, and exact-vs-approximate front comparison.

### Benchmark outputs
- `results/benchmark_kyber512.json`
- `results/benchmark_kyber768.json`
- `results/benchmark_kyber1024.json`

These include latency, memory, and correctness measurements by configuration.

---

## 6. Key design constraints and caveats

This project is intentionally opinionated and research-oriented.

### Search space is intentionally bounded
The parameter ranges were chosen to keep the space tractable while covering the relevant Kyber operating region.

### Security is not the same as “safest possible”
The model uses a chosen threshold tied to the baseline standard Kyber tier rather than absolute optimality. A candidate is only “feasible” if it is at least as secure as the target standard parameter set.

### The project treats delta as a hard reliability gate
A candidate with better ciphertext size but unacceptably large decryption failure is rejected.

### SageMath / estimator dependency matters
Some modules rely on the LWE estimator and SageMath. The repository comments and scripts assume a WSL/Linux environment or equivalent Sage-enabled environment. In particular, Model 2 is expensive and is designed to be run once, then reused.

### kyber-py caveat
The benchmarking code notes a known issue with `kyber-py` for du = 12: some ciphertexts are decoded incorrectly. This does not invalidate size or latency benchmarks for those configurations, but it does affect correctness assessment.

---

## 7. Repository layout

```text
.
├── README.md
├── pyproject.toml
├── diag_security.py
├── analysis/
│   ├── kyberpy_du12_bug.py
│   ├── model_checks.py
│   └── per_run_stats.py
├── hardware/
│   ├── README.md
│   ├── build_kyber1024_p1.sh
│   ├── log_benchmark.py
│   └── ...
├── modules/
│   ├── __init__.py
│   ├── custom_delta.py
│   ├── feasibility.py
│   ├── m0_sanity_check.py
│   ├── m1_parameters.py
│   ├── m2_precompute.py
│   ├── m3_nsga2.py
│   ├── m4_validate.py
│   ├── m5_benchmark.py
│   └── reference/
│       ├── reference_delta.py
│       └── ...
├── results/
│   ├── benchmark_kyber512.json
│   ├── benchmark_kyber768.json
│   ├── benchmark_kyber1024.json
│   ├── lookup_table.json
│   ├── nsga2_front_kyber512.json
│   ├── nsga2_front_kyber768.json
│   ├── nsga2_front_kyber1024.json
│   ├── parameter_space.json
│   ├── validation_kyber512.json
│   ├── validation_kyber768.json
│   └── validation_kyber1024.json
└── ...
```

---

## 8. Why this project matters

This project sits at the intersection of three areas:

- cryptographic parameter design
- security estimation for lattice-based schemes
- optimization and Pareto-front search under hard constraints

The core idea is that Kyber parameter tuning is not just a single scalar optimization problem; it is a constrained multi-objective design exercise.

The repository treats the problem as a real engineering search:

- the full candidate space is explicit
- the raw metrics are computed once
- feasibility is handled separately from data collection
- optimization is separated from validation
- benchmark results are measured in a realistic runtime environment

This structure makes the project easy to reason about and easy to extend.

---

## 9. Setup

The project uses `uv` and declares a Python requirement of 3.12 or newer.

Install dependencies:

```bash
uv sync
```

Or, if you are running directly:

```bash
uv run python <script>
```

The project depends on:

- `deap`
- `kyber-py`
- `lattice-estimator`
- `matplotlib`
- `mpmath`
- `numpy`
- `scipy`

It also pulls the lattice-estimator dependency from GitHub via the `pyproject.toml` configuration.

---

## 10. Typical research questions this project answers

- What is the full feasible parameter space around Kyber?
- Which non-standard parameter choices reduce ciphertext size while preserving security?
- How close is NSGA-II to the true Pareto front?
- Which configurations are likely to be practical in embedded or constrained environments?
- Which candidates preserve correctness while reducing bandwidth?

---

## 11. Recommended way to read the codebase

If you want to understand the project quickly, read in this order:

1. `modules/feasibility.py`
2. `modules/m1_parameters.py`
3. `modules/m2_precompute.py`
4. `modules/m3_nsga2.py`
5. `modules/m4_validate.py`
6. `modules/m5_benchmark.py`
7. `modules/m0_sanity_check.py`

This sequence follows the actual design flow of the project: define, precompute, optimize, validate, benchmark.


