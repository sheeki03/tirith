# Review of the native resource growth inputs

Reviewed protocol draft SHA256
`8797f61cb752b58ec75fe3d7b48852c0a8bc73dd44ea968e8f4f6410d6f1b768`
and variant manifest SHA256
`3de6be6550d8326d5940d30cdde63f3d6f4a52eace81278ac8b174f91b889cb7`.

All twelve commits have the exact `415565d3` base as their sole parent and change
only their declared product file. Commit trees and source digests were checked
against Git. Each control/growth pair differs only in its declared allocation
dose. The six mutations were read in full and their selectors checked against
the unchanged allocation and local-control producers.

The buffers make real allocation requests, touch each page and remain live for
the selected call. The RSS variant additionally observes its buffer on drop at
command return. Short-circuit command matching increments the first/subsequent
counter only for the selected workload. The zero-dose controls retain the same
branch and counter structure.

The separate threshold review covers these exact host, source, compiler, Python
and measurement contracts. No numerical ceiling, dose, producer or evaluator
was changed to obtain admission. The unchanged collector requires one boot for
each pair, exact source and executable identities, 100 samples, a passing control
and a growth failure on exactly the selected metric. Its allocation and sustained
RSS delta checks remain mandatory.

No blocker was found to one bounded existing-workflow dispatch per experiment.
This review permits marking this protocol reviewed and collecting all six pairs;
it does not certify their results or activate a CI budget. Keep every failure or
host mismatch. These historical-source detector checks do not replace three
final-source baselines, final release qualification or other WP17 workloads.
