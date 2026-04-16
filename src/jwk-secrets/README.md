# JWK Secrets (OpenGrep)

Specification for this directory: **rule packs**, **generated test corpus**, **benchmark harness**, and **ground-truth labeling** for detecting private JWK-shaped material in source and text.

Run commands below from **`src/jwk-secrets`** (this directory).

---

## Rule packs

| Path | Definition |
| --- | --- |
| `rules` | Default profile: recall-oriented patterns for private JWK fields and stringified forms. |
| `rules-strict` | Strict profile: extra charset/length constraints on matched values. |
| `rules-strict-baseline` | Frozen snapshot of strict rules for A/B comparison against `rules-strict`. |

Detection scope (all profiles): private JWK parameters such as `d`, CRT fields `p`, `q`, `dp`, `dq` where applicable, and `k` for `kty: "oct"`. Object literals and stringified JSON (including escaped quotes in strings) are in scope. Rules do **not** assert cryptographic validity of keys—only presence of sensitive-shaped material.

---

## Paths and languages

Rules are organized per language plus one **generic** rule (`generic-jwk-secrets.yml`) that covers JSON files and common text/config extensions. `paths.include` in each YAML lists file extensions; summarized:

| Bucket | Extensions |
| --- | --- |
| Python | `.py`, `.pyw`, `.pyi` |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx` |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` |
| Java | `.java` |
| C# | `.cs`, `.csx` |
| Go | `.go` |
| Generic (JSON + text / config) | `.json`, `.txt`, `.conf`, `.ini`, `.env`, `.yaml`, `.yml`, `.toml`, `.cfg`, `.config`, `.properties`, `.tfvars`, `.tfvars.json` |

---

## Tests and ground truth

- **Manifest:** `generated/ground-truth-generated.json` (generated; primary label field `expected_match`).
- **Invariants and acceptance criteria:** `tests/invariants.md`.
- **Corpus generator:** `scripts/generate_pathological_corpus.py` writes under `generated/` (gitignored by default).

```bash
python scripts/generate_pathological_corpus.py --output generated --files-per-language 50
```

```bash
python scripts/generate_pathological_corpus.py --output generated --files-per-language 50 --no-include-stress-fixtures
```

---

## Benchmarks

**Script:** `scripts/benchmark_rules.py`.

**Reference corpus** for the table below: `generated` — 424 labeled cases, 424 files, ~2014 lines; labels from `ground-truth-generated.json`. Figures are for comparing rule **profiles** on that corpus and machine; they are not a general performance or accuracy claim outside this test setup.

**Profile summary** (one row per rule pack). **⟨P⟩ ⟨R⟩ ⟨F1⟩** are **unweighted arithmetic means** over the eight per-language buckets in `quality.per_language` from `benchmark_rules.py --two-pass-report` (the `json` and `plaintext` buckets both use `generic-jwk-secrets.yml`). **Agnostic P/R/F1** are from `quality.agnostic_pass` (Java, C#, and generic rules on the full corpus, including `json/` fixtures). Timings from a representative run; your numbers will differ.

| Profile | One full scan (ms) | Findings | ⟨P⟩ langs | ⟨R⟩ langs | ⟨F1⟩ langs | Agnostic P | Agnostic R | Agnostic F1 | Two-pass total (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rules` | 9810 | 394 | 0.9808 | 0.9205 | 0.9479 | 1.0000 | 0.9091 | 0.9524 | 23359 |
| `rules-strict-baseline` | 10166 | 332 | 0.6023 | 0.4659 | 0.5233 | 0.0000 | 0.0000 | 0.0000 | 23723 |
| `rules-strict` | 10104 | 332 | 0.6023 | 0.4659 | 0.5233 | 0.0000 | 0.0000 | 0.0000 | 23527 |

**Column definitions**

- **One full scan** — one OpenGrep invocation over the full `generated/` tree with every YAML in the profile directory.
- **⟨P⟩ ⟨R⟩ ⟨F1⟩ langs** — mean of per-language precision / recall / F1 from the eight `per_language` scans (`quality.per_language`).
- **Agnostic P/R/F1** — combined embedded-text pass (`quality.agnostic_pass`): Java, C#, and generic (JSON + text/config) rule files on the full corpus.
- **Two-pass total (ms)** — `performance.total_two_pass_duration_ms`: eight per-language scans plus the agnostic pass.

```bash
python scripts/benchmark_rules.py --target generated --config-dir rules --two-pass-report
python scripts/benchmark_rules.py --target generated --config-dir rules-strict-baseline --two-pass-report
python scripts/benchmark_rules.py --target generated --config-dir rules-strict --two-pass-report
```

```bash
python scripts/benchmark_rules.py --target generated --config-dir rules --check-generated-ground-truth --two-pass-report
```

---

## OpenGrep invocation (reference)

Example flags used in benchmark runs so scans are comparable and paths are not skipped via ignore files:

```bash
opengrep scan --config rules --json --no-git-ignore --x-ignore-semgrepignore-files <path>
```

Strict profile: substitute `rules-strict` for `--config`.

---

## Endor Labs (any customer tenant)

The published copy under [Endor-Solutions-Architecture/scripts](https://github.com/Endor-Solutions-Architecture/scripts) (`opengrep_jwk_private_material/`) is the same benchmarks and rules, with Semgrep `metadata` limited to fields accepted by the Endor Labs API so packs register in any tenant. See that README for import instructions.

---

## Labeling contract

- Manifest labels are **security-truth** oriented (recall-first for sensitive-shaped material), not full key validation.
- Strict profiles add heuristics (length/charset); they do **not** verify RSA/EC relationships (e.g. `p*q=n`).
