# MOKOSH: unfinished application, preliminary analysis only

This repository contains a frozen source copy for preliminary self-analysis,
comparison and advice. It is not a release or a declaration that MOKOSH is
complete, secure, production-ready or independently audited.

The 263 files in project/ are byte-exact to the supplied Stage2.48 worktree,
not just the earlier accepted Git HEAD. Their tests and pinned dependencies
are unchanged. Stage2.47 was accepted; Stage2.48 is NOT_ACCEPTED and D005,
the Dell maximized-parent-return defect, remains OPEN.

ci/ holds separate analysis infrastructure. The only workflow uses a manual
workflow_dispatch trigger and read-only repository permissions. It compares
the frozen source and metadata before/after work, uses disposable copies,
and reports findings without applying application fixes or dependency updates.
No merge, release, deployment, automatic code edits or push/PR trigger exists.

## Recorded scope

Local Linux/Python3.12.14 headless: 2509 unique baseline tests passed without
failures, errors or skips, plus 33 infrastructure guards. This is not the exact
Dell runtime or physical/native GUI acceptance. Previous failures are retained.
Windows x64 and macOS ARM64 workflow jobs are explicitly limited portability
probes; the full 2509-test suite runs only on Linux. No GUI acceptance is claimed.

Bandit reported 320 baseline pattern flags and 7 LOW flags in the separate
R3 candidate files. These are not confirmed defect counts. The latest local
pip-audit was INCOMPLETE due to PyPI DNS failure. An earlier completed scan
reported the cryptography49 advisory CVE-2026-69247, which remains NOT_FIXED.
See LOCAL_VALIDATION.json for limitations and immutable source identities.

candidates/R3/ contains six separate, statically inspected laboratory candidate
files. They are not overlaid on project/ and are not executed by this workflow.

SOURCE_MANIFEST.json binds all263 paths/content and the exact12 executable
files on POSIX. Git preserves executable-bit semantics, not full archived POSIX
permissions/ACL/ownership. Windows physical POSIX bits remain NOT_VERIFIED.

## Run the preliminary checks

After the uploaded Git tree is verified, use Actions > MOKOSH preliminary
analysis only > Run workflow on main. Findings and incomplete checks must
remain visible; a red security job can mean findings or an incomplete tool.
Inspect the raw reports rather than treating the job color as product acceptance.

history/ and draft_workflows/ preserve earlier preparation records. Their old
HOLD or no-account descriptions are historical, superseded by ANALYSIS_STATUS.json.
