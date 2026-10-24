# MOKOSH: unfinished application, preliminary analysis only

This is a frozen analysis copy, not a release, production readiness declaration,
certification, or independent product security audit. Stage2.47 was accepted
internally. Stage2.48 is NOT_ACCEPTED; D005 remains OPEN.

The 263 files in project/ and their five dependency pins are unchanged. Six
candidates/R3/ files are separate static-analysis inputs, never overlaid or
executed by these workflows. Normal LocalV2Service explicitly requires Linux.
Windows/macOS product storage, dependencies, native GUI and physical acceptance
remain separate work; a CI reader fix does not grant product support.

## Recorded executions

Run40087175055/attempt1 at838bd591b7a5d2a677e2f0d9511c410762442ea7 failed overall.
Linux completed2509 unique PASS/0FAIL/ERROR/SKIP and189 compilations. macOS ARM64
completed a limited compilation/runtime portability probe only. Windows failed
in the initial disposable-copy guard before compilation/probing; that old
run did not record the precise input or field. Security completed320 baseline
and7 separate R3 pattern flags, not327 confirmed defects. The completed five-pin
cloud dependency audit contains one distinct cryptography49 advisory,
CVE-2026-69247/GHSA-g6cj-pr64-35w5, NOT_FIXED. No upgrade is applied here.

The separately approved diagnostic run40096716338/attempt1 at
8f62fa6256dbe923beefc654705d6dfe574df6b9 also failed. Windows Server2022/x64,
Python3.12.3 rejected mokosh_vault_recovery_source_selection.py (17741 bytes,
SHA256856143153b21cc6c3ff81e908cbf875c0433492a79a023ee2ab3e4b793024600)
during BOOTSTRAP_BEFORE and BOOTSTRAP_FINAL. Only cross-API ctime differed:
lstat used birthtime, fstat used ChangeTime; both same-API pairs and the expected
bytes/hash were stable. This confirms an invalid assumption in our shared CI
reader, supported by the exact CPythonv3.12.3 source. It does not restore the
missing old-run observations. Full263-file before/after snapshots, app venv/pip,
copy, compilation, probe and worker were not completed/reached in this run.
The old rejected pip report was not reproduced. Its cause remains OPEN.

The diagnostic bootstrap has a final receipt and explicit raw exit1. Stage has
a receipt and runner success, but no printed numeric0; zero is an inference from
the exact runner2.338.0 implementation. That historical strict numeric-evidence
gap is retained, not relabelled complete.

## Local CI reader correction candidate

The approved correction compares all seven fields, including ctime, separately
for path-before/path-after and held-descriptor-opened/after-read. It binds
identity, regular-file/link/size/mode/mtime across APIs without equating their
different ctime meanings. The post-read path sample is mandatory while the
descriptor is held. Bounded reads, exact lengths, manifest SHA/count/canonical,
executable metadata, final frozen/copy checks, cleanup and artifact limits stay.
No retries, sleeps, tolerance or dependency upgrade are added to the reader.
Windows path ctime is not a pre-open ChangeTime observation. The descriptor
baseline begins at its first validated fstat; no universal history/ACL/owner
or product-key-storage guarantee follows.

New rejection records explicitly distinguish lstat_guard_after from the later
lstat_failure_probe, with observation_contract LIKE_API_GUARD_PAIRS_V2. Historical
raw records remain unchanged. A failed guard post-path sample cannot become a
complete collection just because a later diagnostic probe succeeds. Metadata
logging still has fixed16/32/16 channel allocations, at most64 records of4096
bytes; it contains no file bodies or environment dump. Original exceptions,
collection limits and exit2/INCOMPLETE behavior remain protected.

The immutable pre-fix baseline is local0eccbc1832459c98e19142d2907cba3786c2185a,
whose tree bcefce72f530fda20b66cb1d8663aa5446c4fe0b equals published8f62fa6.
Stable Windows-shaped cross-API ctime tests are deliberately aligned to the
measured, approved contract. Privacy/sink/phase negative goals are retained
using genuine descriptor changes. Old code, test expectations and failures
remain in that baseline and the preserved execution evidence.

## Prepared native verification

The two existing workflows remain byte-exact. A third manual-only workflow,
MOKOSH Windows CI reader verification only, is prepared locally for one
Windows2022/x64/Python3.12.3 job: guarded hashed bootstrap, owned real-metadata
reader fixtures, the existing limited compilation/runtime portability probe,
and allowlisted report sealing. Actions are pinned and contents permissions
are read-only. No full matrix, product GUI, autofix, merge or release is added.
Publishing and starting this candidate require the next review decision.

The owned non-secret fixtures must exercise an observed stable Windows
creation/change difference and an actual same-handle metadata-only change.
The scheduler returns real kernel stat results; it does not fabricate them.
Fixture-only waits separate real timestamp events. An unexercised condition
is nonzero/UNEXERCISED, never native PASS. The production reader never waits.
A bounded wrapper prints the actual completed child exit, including0, and
propagates failure. Timeout, collection, write, flush or cleanup failure cannot
produce a successful wrapper. The marker plus actual wrapper exit and exact
run/job/attempt/commit must be reviewed together; child0 alone is not acceptance.

Local verification:89 integrated CI controls PASS (44 controller,26 diagnostic,
19 verification), including all33 byte-identical original guard methods.
Independent29+17 controls,8 reader fault/positive pairs,32 workflow/wrapper
controls and1 exit-projection fault/positive pair passed. The full compatible
controller passed2509 unique tests with0FAIL/ERROR/SKIP on qualified local
Linux/Python3.12.14, the same five pins and existing private headless Tk loader.
Development fixture mistakes and initial review failures are preserved.
Detailed results are in ANALYSIS_STATUS.json. Local Linux
checks, including the full compatible suite, do not establish exact Dell,
native Windows/macOS, physical GUI or product security acceptance.
LOCAL_VALIDATION.json, history/ and draft_workflows/ retain historical states;
their old DNS/no-account/run-pending notes are not current cloud conclusions.
Git executable bits do not reproduce all POSIX modes, ownership or ACLs;
Windows POSIX bits remain NOT_VERIFIED. D005 and all product findings stay open
unless their own evidence and acceptance gates are completed.
