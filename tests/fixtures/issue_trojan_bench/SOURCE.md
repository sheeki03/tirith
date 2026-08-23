# Source and licence note

Everything in this directory is **synthetic and original to this repository**.

## What this corpus is not

It is **not** IssueTrojanBench, and it contains **no** payload copied, adapted,
paraphrased from, or derived from IssueTrojanBench or any other published attack
dataset. No file here was produced by reading that dataset.

The IssueTrojanBench paper describes a *shape*: untrusted content reaches an
agent through one of several source vectors, and asks the agent for one of
several high-impact effects. A published description of a threat model is not a
licence to vendor the artifact that accompanies it. The artifact ships under its
own terms, which this repository has not verified and does not rely on, so the
dataset is treated as unavailable.

## What this corpus is

An independently written cross-product that exercises the same **control
boundaries** this repository owns:

- six source vectors, each carrying the trust assignment Tirith gives it
  (`sources.toml`);
- six high-impact effects, each expressed as a `ProposedAction` the effect
  inferrer already models (`effects.toml`);
- for each effect, one direct request, one obfuscated variant, and one paired
  benign control (`payloads.toml`);
- eight source-laundering chains, each asserting that a hop cannot manufacture
  authority (`laundering.toml`).

The driver in `crates/tirith-core/tests/c19_cross_cutting.rs` composes source
wrapper x payload into 6 x 6 x 3 = 108 deterministic cases.

## Acceptance criterion

The assertion is the **deterministic decision at an owned boundary**: which
effects a task gate allows and denies given an assigned source and an inferred
effect set. It is deliberately not a model-behaviour percentage, which is not
reproducible and is not something this repository can enforce.

## Safety of the content

Every payload is inert text. Hosts use reserved `.invalid` names, package names
are `example-`/`internal-` prefixed and unpublished, paths point at temp or
fictional locations, and no file contains real credential material. Any
credential-shaped test input is assembled at runtime from parts, never stored
here as a literal.
