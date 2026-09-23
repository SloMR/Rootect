# Scoring

How a pile of signals becomes one number.

## Confidence weights

Every signal has a fixed heuristic weight. It is not a measured probability.

| Confidence | Weight | Means |
|---|---|---|
| `WEAK` | 10 | Common on honest devices |
| `MODERATE` | 25 | Unusual but explainable |
| `STRONG` | 50 | Hard to explain away |
| `CONCLUSIVE` | 100 | Maximum heuristic weight; not proof of compromise |

## Combining them: noisy-OR

**Why not just add the weights up?** Because adding turns a handful of small, innocent signals
into a false alarm, and a false alarm gets the library deleted. The formula combines heuristic weights; it does not estimate an actual probability
of compromise. Evidence still accumulates, but with
**diminishing returns**, so weak signals never stack up linearly and one strong signal is never
diluted.

```
score = (1 − Π(1 − weightᵢ/100)) × 100
```

**A real scan.** An unrooted test phone (`isRooted = false`, root score 0) fired five signals —
a historically tripped Knox fuse, a debug build, developer options and USB debugging on, and a
sideloaded installer:

| Signal | Confidence | Weight |
|---|---|---|
| `KNOX_WARRANTY_BIT_TRIPPED` | STRONG | 50 |
| `DEBUGGABLE_BUILD` | MODERATE | 25 |
| `DEVELOPER_OPTIONS_ENABLED` | WEAK | 10 |
| `ADB_ENABLED` | WEAK | 10 |
| `UNTRUSTED_INSTALLER` | WEAK | 10 |

| Method | Score | Band |
|---|---|---|
| Add the weights | 50 + 25 + 10 + 10 + 10 = **105**, off the 0–100 scale | `CRITICAL` |
| Noisy-OR | (1 − 0.50 × 0.75 × 0.90 × 0.90 × 0.90) × 100 ≈ **73** | `HIGH` |

These are score bands, not diagnoses. One `CONCLUSIVE`-weighted signal scores **100**, even
with a benign cause such as an incorrect expected signing hash.

The implementation rounds to the nearest integer and clamps to 0–100. Because signals can be correlated,
read the score as a ranking, not a true probability.

Duplicate `SignalId`s count once — two probes finding `su` in two places is one finding.

## Risk bands

| Score | `RiskLevel` |
|---|---|
| 0 | `SAFE` |
| 1–24 | `LOW` |
| 25–49 | `MEDIUM` |
| 50–79 | `HIGH` |
| 80–100 | `CRITICAL` |

These are a starting point, not a policy. A bank and a puzzle game should not use the same
cut-off, and only you know what a false positive costs you.

## Per-category scores

The same maths runs per category, over that category's signals only:

```kotlin
report.score                        // everything
report.scoreFor(Category.ROOT)      // root evidence alone
```

The rollup booleans are just a threshold on that:

```kotlin
report.isRooted   // scoreFor(ROOT) >= 50
```

**50 means one `STRONG` signal, or three `MODERATE` ones.** Two moderate signals reach 44 and
do not trip it — deliberately, because two mildly odd things are a Tuesday.

## The trap this creates

A category score and the overall score answer different questions, and they can disagree
loudly. Measured on a rooted phone with Magisk DenyList active:

```
risk = CRITICAL   score = 94   isRooted = false
```

Nothing is broken. DenyList hid the root artefacts, so `ROOT` scored 25 — but the device
still reported an unlocked bootloader and permissive SELinux, which is why overall risk is
`CRITICAL`.

**Choose evidence relevant to your policy.** A high total can reflect legitimate posture;
a low total can still miss hidden root. Neither total nor category scores prove compromise.

## Inconclusive checks

```kotlin
report.inconclusiveChecks   // probes that could not complete
```

A denied read is not a negative result. If this is non-zero, "no signals" is weaker than it
looks — treat it as *unknown*, which is a valid third state. Some probe errors are not
counted, so zero does not establish that every check succeeded.
