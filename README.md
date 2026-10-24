# MOKOSH: unfinished application, preliminary analysis only

This is a frozen analysis copy, not a release, a declaration of production
readiness, a certification, or an independent product security audit.
Stage2.47 was accepted internally. Stage2.48 is NOT_ACCEPTED; D005 remains OPEN.

The 263 files in project/ remain byte-exact to the supplied Stage2.48 worktree.
Their tests and five pinned dependencies are unchanged. Six files in
candidates/R3/ are separate static-analysis inputs; they are not overlaid on
project/ or executed by these workflows. The normal LocalV2Service currently
explicitly requires Linux. Windows/macOS product support needs its own reviewed
filesystem, dependency, native GUI and physical acceptance work.

## Recorded first GitHub run

Run 40087175055, attempt1, at commit
838bd591b7a5d2a677e2f0d9511c410762442ea7 completed with overall failure:

- Linux:2509 unique PASS, no FAIL/ERROR/SKIP;189 Python files compiled.
- macOS ARM64:limited compilation/runtime portability probe only; no full2509 or native GUI acceptance.
- Windows x64:initial disposable-copy metadata read guard failed before compilation/runtime probing. The failing relative file and differing fields were not recorded.
- Security:reports completed with320 baseline and7 separate R3 pattern flags. Flags are not confirmed defect counts. The completed five-pin cloud dependency audit contains one distinct cryptography49 advisory (CVE-2026-69247/GHSA-g6cj-pr64-35w5), NOT_FIXED.

The exact Windows cause remains unmeasured. CPython3.12.3 path/handle ctime
semantics are a primary-source-supported lead, not an established cause of that
particular failure. The approved report rejected during artifact sealing also
needs its own measured path/reason.

## CI diagnostic preparation

The candidate adds a separate manual-only workflow,
MOKOSH Windows stat diagnosis only. The original preliminary-analysis workflow
and matrix are byte-unchanged. Both use read-only contents permissions,
pinned actions, disposable copies and explicit report allowlists; neither
applies product fixes or dependency upgrades.

The new Windows2022/x64/Python3.12.3 job observes bootstrap, the initial source-copy
guard, and approved-report rejection metadata. It stops before product
compilation/runtime probing/worker execution. It does not rerun the full matrix
or grant Windows compatibility acceptance. Starting it requires a separate
review decision; there is no automatic push/PR trigger.

Structured metadata logging is bounded to16/32/16 records for bootstrap/audit/
stage, at most64 records of4096 bytes. No file bodies or environment dumps are
part of the new diagnostic channel. Existing read guards, including ctime,
retain their refusal behavior. Rejected artifact contents remain blocked.

A complete final channel receipt must be checked together with that step's
actual raw exit code and run/job/attempt/commit identity. New-entry exit2 or a
missing receipt/exit is INCOMPLETE. Audit exit1 retains a guard failure or
DIAGNOSTIC_NON_REPRODUCED; neither is compatibility PASS. An artifact marked
PENDING_FINAL_RECEIPT cannot establish final collection completeness.

Local preparation passed33 existing CI guards,20 targeted checks,17 independent
checks and3 deliberate-fault/positive pairs. The normal controller passed2509
tests on qualified local Linux/Python3.12.14 with the five exact dependency pins.
An initial run without the existing private Tk loader configuration failed;
that failure is preserved. No exact-Dell, Windows/macOS native or physical
acceptance follows from these local results.

ANALYSIS_STATUS.json distinguishes the completed first run from this unexecuted
diagnostic candidate. LOCAL_VALIDATION.json, history/ and draft_workflows/
retain historical preparation states; their old DNS/no-account/run-pending
notes are not current cloud conclusions. Git executable bits do not reproduce
all POSIX permissions, ownership or ACLs; Windows POSIX bits remain NOT_VERIFIED.
