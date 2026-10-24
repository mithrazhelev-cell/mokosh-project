from __future__ import annotations

import ast
import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / (
    "docs/VAULT_RECOVERY_SOURCE_INSPECTION_NORMAL_GUI_AUTHORIZATION_READINESS_AUDIT_BG.md"
)


def audit_text() -> str:
    return AUDIT_PATH.read_text(encoding="utf-8")


class NormalGUIAuthorizationReadinessAuditTests(unittest.TestCase):
    def test_01_audit_identity_and_result_are_exact(self):
        text = audit_text()
        self.assertIn("Stage 2.45 normal-GUI source-inspection authorization", text)
        self.assertIn("GO WITH BLOCKERS — audit-only, без production разрешение", text)
        self.assertIn("Дата на freeze: 2026-09-08", text)

    def test_02_baseline_commit_and_tree_are_exact(self):
        text = audit_text()
        self.assertIn("77c9432b519a8fd0c7ed7f446e39fbdc13547fb2", text)
        self.assertIn("5b60a8520b7dfbbab4054a73766f60be6fda25b5", text)

    def test_03_scope_lists_exactly_six_paths(self):
        section = audit_text().split("## 2. Exact Stage 2.45 scope", 1)[1].split(
            "## 3.", 1
        )[0]
        paths = re.findall(r"^\d+\. `([^`]+)`", section, flags=re.MULTILINE)
        self.assertEqual(
            paths,
            [
                "docs/VAULT_RECOVERY_SOURCE_INSPECTION_NORMAL_GUI_AUTHORIZATION_READINESS_AUDIT_BG.md",
                "tests/test_mokosh_vault_recovery_source_inspection_normal_gui_authorization_readiness_audit.py",
                "PROJECT_STATUS_BG.md",
                "docs/SECURITY_EVIDENCE_AND_TESTING_BG.md",
                "docs/SECURITY_STANDARDS_CROSSWALK_BG.md",
                "docs/SESSION_LOG_BG.md",
            ],
        )
        self.assertIn("точно шест paths", section)

    def test_04_scope_keeps_every_production_domain_byte_exact(self):
        text = audit_text()
        for token in (
            "всички production модули",
            "locale strings",
            "launchers",
            "crypto",
            "Vault",
            "storage",
            "Contacts",
            "network paths",
            "byte-exact",
        ):
            self.assertIn(token, text)

    def test_05_sixth_action_is_separate_locked_and_user_initiated(self):
        text = audit_text()
        self.assertIn("отделно **шесто действие**, започващо locked", text)
        self.assertIn("клик/keyboard activation на шестото действие", text)
        self.assertIn("implicit/default-positive authorization", text)

    def test_06_confirmation_is_separate_path_free_and_default_negative(self):
        text = audit_text()
        self.assertIn("отделно path-free\n   confirmation", text)
        self.assertIn("default/cancel/close/negative route", text)
        self.assertIn("PRESERVE_AND_STOP", text)

    def test_07_only_exact_positive_stage31_may_arm_stage32_boundary(self):
        text = audit_text()
        self.assertIn("само exact positive Stage 2.31 outcome", text)
        self.assertIn("Exact Stage 2.31 reference", text)
        self.assertIn("exact Stage 2.32", text)

    def test_08_stage32_uses_existing_exact_authorization_decision(self):
        text = audit_text()
        self.assertGreaterEqual(
            text.count("AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION"), 2
        )
        source = (
            ROOT / "mokosh_vault_recovery_source_inspection_execution.py"
        ).read_text(encoding="utf-8")
        self.assertIn("class RecoverySourceInspectionExecutionDecision", source)
        self.assertIn("AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION", source)

    def test_09_direct_stage29_to_stage32_route_is_forbidden(self):
        text = audit_text()
        self.assertIn("direct Stage 2.29 → Stage 2.32 route", text)
        self.assertIn("без direct\n   Stage 2.29 route", text)

    def test_10_lifecycle_states_and_terminal_routes_are_frozen(self):
        text = audit_text()
        self.assertIn("LOCKED → READY → DECIDING → COMPLETED", text)
        self.assertIn("LOCKED/READY/DECIDING → FAILED", text)
        self.assertIn("terminal success/preserve", text)

    def test_11_replay_concurrency_and_retry_fail_closed(self):
        text = audit_text()
        for token in (
            "concurrent/replayed activation",
            "не отваря втори dialog/read",
            "Няма retry върху същия prepared object",
            "replay и concurrency никога не downgrade-ват към read",
        ):
            self.assertIn(token, text)

    def test_12_predecessor_and_path_references_have_exact_clear_order(self):
        text = audit_text()
        self.assertIn("clear-ват под lock **преди**", text)
        self.assertIn("преди confirmation dialog", text)
        self.assertIn("веднага след създаване на\n  Stage 2.32 prepared execution", text)
        self.assertIn("path се clear-ва\n  преди preserve/result или преди reader call", text)

    def test_13_ordinary_and_baseexception_routes_are_distinct(self):
        text = audit_text()
        self.assertIn("Ordinary exception", text)
        self.assertIn("generic localized path-free error", text)
        self.assertIn("`BaseException` маркира terminal failure и се propagate-ва", text)

    def test_14_privacy_contract_excludes_identifiers_content_and_free_text(self):
        text = audit_text()
        for token in (
            "path, filename, directory, username, hostname",
            "recovery/vault identifier",
            "secret, nonce или ciphertext",
            "Не се въвежда свободен текст",
        ):
            self.assertIn(token, text)

    def test_15_privacy_contract_excludes_side_channels_and_persistence(self):
        text = audit_text()
        for token in (
            "logging",
            "telemetry",
            "clipboard",
            "screenshot",
            "network",
            "persistence",
            "analytics",
        ):
            self.assertIn(token, text)

    def test_16_structural_validation_is_not_authentication_or_recovery_proof(self):
        text = audit_text()
        self.assertIn("structural parsing/validation от cryptographic authentication", text)
        self.assertIn("inspection evidence от recovery proof", text)
        self.assertIn("не се представят като cryptographically authenticated", text)

    def test_17_memory_zeroization_and_global_consumption_are_not_claimed(self):
        text = audit_text()
        self.assertIn("Python memory zeroization не се твърди", text)
        self.assertIn("process-local one-shot behavior от global consumption", text)
        self.assertIn("reference clearing от доказана memory zeroization", text)

    def test_18_posix_atime_and_identity_caveats_are_explicit(self):
        text = audit_text()
        self.assertIn("filesystem-managed `atime`", text)
        self.assertIn("не твърди forensic no-change гаранция", text)
        self.assertIn("не дава future\nidentity guarantee", text)

    def test_19_review_layers_cannot_activate_automatically(self):
        text = audit_text()
        for token in (
            "Stage 2.39 review session",
            "Stage 2.40 main-GUI binding",
            "Stage 2.41 conditional review widget/window",
            "не се активира автоматично",
        ):
            self.assertIn(token, text)

    def test_20_no_recovery_secret_crypto_or_operation_authority_is_added(self):
        text = audit_text()
        self.assertIn("поиска recovery secret, decrypt, authenticate, reconcile или recover", text)
        self.assertIn("write, replace, rename, unlink, chmod, publish", text)
        self.assertIn("нито structural success са\nauthorization token", text)

    def test_21_fixture_uses_new_private_0700_directory_not_shared_downloads(self):
        text = audit_text()
        self.assertIn("runner-owned нов private directory с mode `0700`", text)
        self.assertIn("под\n  physical `~/Downloads`", text)
        self.assertIn("не директно в обичайния shared-mode Downloads", text)

    def test_22_fixture_file_is_private_regular_single_link_and_canonical(self):
        text = audit_text()
        for token in (
            "regular file",
            "current-user-owned",
            "single-link",
            "mode `0600`",
            "mokosh-vault-recovery-<32 lowercase hex>.mokr",
        ):
            self.assertIn(token, text)

    def test_23_fixture_is_structurally_valid_synthetic_and_secret_free(self):
        text = audit_text()
        self.assertIn("изцяло synthetic, non-secret", text)
        self.assertIn("не е копие на реален recovery record", text)
        self.assertIn("structurally valid record", text)
        self.assertIn("не съдържат recovery secret", text)

    def test_24_fixture_creation_validation_and_cleanup_fail_closed(self):
        text = audit_text()
        for token in (
            "creation е exclusive/no-follow",
            "identity и size се validate-ва",
            "изтрива само runner-owned exact inode",
            "отказва\n  чуждо изтриване",
            "success, failure, cancel, interrupt и `BaseException`",
        ):
            self.assertIn(token, text)

    def test_25_future_human_gate_is_self_contained_and_not_stage245(self):
        text = audit_text()
        self.assertIn("Stage 2.45 няма GUI промяна и затова няма human visual matrix", text)
        self.assertIn("собствен self-contained human matrix", text)
        self.assertIn("не зависят от chat", text)
        self.assertIn("PASS не е предварително избран", text)

    def test_26_automated_counts_are_exact(self):
        text = audit_text()
        for token in (
            "точно `32/32` methods",
            "Stage 2.31 `33/33`",
            "Stage 2.32 `44/44`",
            "boundary `48/48`",
            "storage `48/48`",
            "combined target `205/205`",
            "`2184/2184`",
            "expected failures",
            "`0` skips",
        ):
            self.assertIn(token, text)

    def test_27_integrity_rollback_and_independent_gates_are_mandatory(self):
        text = audit_text()
        for token in (
            "exact six-path allowlist",
            "no staged files",
            "rollback injection",
            "plain ACL",
            "Git diff-check/fsck",
            "unchanged bytecode",
            "independent post-apply/pre-commit gate",
        ):
            self.assertIn(token, text)

    def test_28_standards_status_and_dates_are_qualified(self):
        text = audit_text()
        self.assertIn("NIST SP 800-218 SSDF 1.1 като final", text)
        self.assertIn("Initial Public Draft от 2025-12-17", text)
        self.assertIn("WCAG2ICT 2.2 е W3C Group Note от 2025-12-11", text)
        self.assertIn("ETSI EN 301 549 V4.1.1 е публикуван през 2026-09", text)
        self.assertIn("не доказва citation в Official Journal", text)

    def test_29_cra_timeline_guidance_and_legal_gate_are_qualified(self):
        text = audit_text()
        self.assertIn("започва 2026-09-11", text)
        self.assertIn("24-hour early warning и 72-hour full notification", text)
        self.assertIn("2027-12-11", text)
        self.assertIn("2026-07-27 е non-binding", text)
        self.assertIn("qualified pre-distribution legal review", text)

    def test_30_no_conformity_certification_or_legal_claim_is_made(self):
        text = audit_text()
        for token in (
            "не е NIST endorsement",
            "accessibility evaluation",
            "WCAG/EN conformity",
            "CRA/EAA/GDPR compliance",
            "CE marking",
            "independent\nsecurity audit",
            "правно становище",
        ):
            self.assertIn(token, text)

    def test_31_critical_production_and_predecessor_files_remain_exact(self):
        expected = {
            "mokosh_gui.py": "15c8a75922aac6bef78783d99150c1c14ed9fb861c57c71d8ebb3e8f31c2cec5",
            "mokosh_vault_recovery_source_inspection_preparation_request.py": "ed03471d6196455244fb7d5f04934c21935328d4cf07be6a83d14e1608f57703",
            "mokosh_vault_recovery_source_inspection_execution.py": "11ff2ff5ca81be5f994e8ef261098fc26a8b31573eee97acbe4123d25a989500",
            "mokosh_vault_recovery_storage.py": "5f8213882a8914917f330e3a1bbd69952ecc4932cd0c68b4fb62e0646382c13c",
            "mokosh_vault_recovery_source_inspection_review_controller.py": "330a6a79451a4fc8e4d982c7468b55faa3064afc08efe1c9eafa869db2b7fda2",
            "mokosh_vault_recovery_source_inspection_main_gui_bridge.py": "a031849c1a6da82b35df803de344c081068196c8ec8816685c78b1fdadd6de1a",
            "requirements-runtime.txt": "726ba5c5e0d058a6ca5b10c8c3e59a86e04487103915b1fc5a1a2305143b0330",
            "run_mokosh_gui.sh": "a5f65af7437ac733cbaf808e94756a2f41352410a17bab65a3b90f07c672b4eb",
            "tests/test_mokosh_vault_recovery_source_inspection_preparation_request.py": "8121bce10590aa61b51e70a528679800c22f8975b62af15db1a775bccfae13ad",
            "tests/test_mokosh_vault_recovery_source_inspection_execution.py": "7a5816fa4c80cb2d6ab78f290a709d9b28903c39a78effe5afb3d57f456a13f9",
            "tests/test_mokosh_vault_recovery_source_inspection_preparation_request_main_gui_widget.py": "efd6cdf7b199ad92e2e3afa10c73572bb4c4320691609b82e70c0612b2386c1c",
            "tests/test_mokosh_vault_recovery_storage.py": "806f09f404a0217f97f2b9e5832f5eaecb12a4a4d92f03b3eb89422cb4e61957",
        }
        for name, digest in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest
                )

    def test_32_audit_is_static_and_target_count_is_exact(self):
        methods = [
            name
            for name in vars(NormalGUIAuthorizationReadinessAuditTests)
            if name.startswith("test_")
        ]
        self.assertEqual(len(methods), 32)
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imports = {
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        } | {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual(
            imports, {"__future__", "ast", "hashlib", "re", "unittest", "pathlib"}
        )
        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            called.isdisjoint(
                {
                    "open",
                    "eval",
                    "exec",
                    "compile",
                    "__import__",
                    "input",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
