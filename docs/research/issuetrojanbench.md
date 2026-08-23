# Research note: the issue-trojan threat shape

This note records what tirith took from the IssueTrojanBench literature, what it
deliberately did not take, and how the resulting test corpus is built. It exists
because the honest answer to "did you use that benchmark" is more interesting
than a yes or a no.

## Nothing was vendored, and why

**No payload in this repository is copied, adapted, paraphrased from, or derived
from IssueTrojanBench or any other published attack dataset. No file in the
corpus was produced by reading that dataset.**

The reasoning is short. A published description of a threat model is not a
licence to vendor the artifact that accompanies it. The dataset ships under its
own terms, which this repository has not verified and does not rely on, so it is
treated as unavailable. That is a licensing decision, and it is also a technical
one: a vendored corpus would tie the test suite to somebody else's revision
history and would make a licence review a prerequisite for every future change.

What the paper contributes is a *shape*: untrusted content reaches an agent
through one of several source vectors and asks the agent for one of several
high-impact effects. A shape is not copyrightable and is not what the licence
covers. Tirith reimplemented the shape against the control boundaries it owns.

## What the corpus actually is

`tests/fixtures/issue_trojan_bench/`, driven by
`crates/tirith-core/tests/c19_cross_cutting.rs`. Four declarative files:

| File | Contents |
|---|---|
| `sources.toml` | six source vectors, each with the trust assignment tirith gives it |
| `effects.toml` | six high-impact effects, each expressed as a `ProposedAction` the effect inferrer already models |
| `payloads.toml` | per effect: one direct request, one obfuscated variant, and one paired benign control |
| `laundering.toml` | eight source-laundering chains, each asserting that a hop cannot manufacture authority |

The driver composes source wrapper by payload into 6 x 6 x 3 = 108 deterministic
cases, asserted by
`synthetic_issue_trojan_corpus_decides_every_cell_at_an_owned_boundary`.

The six sources are `issue_body`, `issue_comment`, `web_content`,
`pdf_extracted_text`, `source_comment`, and `alt_hidden_rendered_text`. The six
effects are `package_install`, `persistence`, `policy_weakening`,
`resource_exhaustion`, `secret_access`, and `production_web3_write`.

Each source fixture carries both what the DOCUMENT claims and which ingress
adapter actually did the reading, and asserts the effective source tirith
assigns. Several claims are deliberate lies: the web-content vector claims
something other than a web page, and the assertion is that an `http-fetch`
adapter ignores the claim.

## The acceptance criterion, and why it is not a percentage

The assertion is the **deterministic decision at an owned boundary**: which
effects a task gate allows and denies, given an assigned source and an inferred
effect set.

It is deliberately not a model-behaviour percentage. A number of the form "the
agent complied 43% of the time" is not reproducible, is a property of a model
that tirith does not ship, and is not something this repository can enforce.
Publishing one would be a claim about somebody else's system.

Two design rules keep the corpus from passing vacuously:

1. **Every control's denied set is a proper subset of its attack's.** A gate
   that refused everything would pass a same-denial pair while being useless, so
   the pairing has to distinguish. The one exception is `resource_exhaustion`,
   where both denial sets are empty by construction and the discriminator is
   completeness instead.
2. **`expected_complete = false` is a first-class outcome.** An action the
   grammar does not model must leave the assessment incomplete, so an enforcing
   boundary fails closed. A fixture that asserted completeness everywhere would
   be asserting a capability tirith does not have.

## Where the corpus is honest about detection

The `direct` payload variants assert `expect_output_detection = false` on
purpose. Paraphrase is an explicit non-goal of the deobfuscation pass, and a
fixture claiming otherwise would be a test that lies about the product. That is
exactly why the corpus's real acceptance criterion is the boundary decision
rather than whether a rule happened to notice the wording.

The `obfuscated` variants each hide a genuine instruction-override seed behind a
DIFFERENT evasion: inter-character spacing, a leetspeak fold, a base64 body, an
upper-case variant, and two raw alternate seed families. Every obfuscation is
ASCII, because invisible characters would be unreviewable in a fixture file, and
the zero-width strip is already covered by `injection_evasion.toml`.

## Safety of the content

Every payload is inert text. Hosts use reserved `.invalid` names, package names
are `example-` or `internal-` prefixed and unpublished, paths point at temporary
or fictional locations, and no file contains real credential material. Any
credential-shaped test input is assembled at runtime from parts, never stored as
a literal, because a complete credential assignment in a source file is exactly
what a secret scanner refuses to accept on push.

## What this corpus does not measure

- It does not measure whether any particular agent obeys an injected
  instruction.
- It does not measure detection recall against real-world issue trojans.
- It does not stand in for the benchmark it is named after. If you need
  IssueTrojanBench numbers, run IssueTrojanBench.

## See also

- `tests/fixtures/issue_trojan_bench/SOURCE.md`, the in-tree licence note
- [Task envelope](../task-envelope.md), the boundary the corpus asserts against
- [Enforcement coverage](../enforcement-coverage.md), what the boundary can and cannot do
