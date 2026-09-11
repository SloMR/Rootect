# Scoring

How a pile of signals becomes one number.

## Confidence weights

Every signal has a fixed heuristic weight. It is not a measured probability.

| Confidence | Weight | Means |
|---|---|---|
| `WEAK` | 10 | Common on honest devices |
| `MODERATE` | 25 | Unusual but explainable |
| `STRONG` | 50 | Hard to explain away |
| `CONCLUSIVE` | 100 | No innocent explanation |

## Combining them

Signals combine with **noisy-OR**, not addition:

```
score = (1 − Π(1 − weightᵢ/100)) × 100
```

The formula rewards multiple distinct signals without simple addition. Correlated signals
mean the result must not be read as a statistical probability.

Adding instead would let five `WEAK` signals outweigh one `CONCLUSIVE` one, and five weak
signals are exactly what an honest custom ROM produces. Noisy-OR also cannot exceed 100, so
there is no need to clamp it into nonsense.

Duplicate `SignalId`s count once. Two probes finding `su` in two places is one finding.

**Worked example** — one `STRONG` and one `MODERATE`:

```
1 − (1 − 0.50) × (1 − 0.25) = 0.625  →  63
```

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
loudly. Measured on a rooted Pixel 5 with Magisk DenyList active:

```
risk = CRITICAL   score = 94   isRooted = false
```

Nothing is broken. DenyList hid the root artefacts, so `ROOT` scored 25 — but the device
still reported an unlocked bootloader and permissive SELinux, which is why overall risk is
`CRITICAL`.

**Branch on `risk` or `score`. Use `isRooted` for telemetry, not for decisions.** The rollups
are deliberately conservative, and being conservative about root means saying "no" on a
device that is quite obviously modified.

## Inconclusive checks

```kotlin
report.inconclusiveChecks   // probes that could not complete
```

A denied read is not a negative result. If this is non-zero, "no signals" is weaker than it
looks — treat it as *unknown*, which is a valid third state.
