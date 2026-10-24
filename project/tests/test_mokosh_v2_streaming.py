import hashlib
import inspect
import unittest
from io import BytesIO
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from mokosh_v2_complete_envelope import (
    CompleteEnvelopePolicyError,
    Ed25519EnvelopeSigning,
    RequireEd25519Envelope,
    RequireUnsignedEnvelope,
    UnsignedEnvelopeSigning,
    decrypt_complete_envelope,
)
from mokosh_v2_crypto import FrameAuthenticationError
from mokosh_v2_format import (
    MIN_CHUNK_SIZE,
    FormatLimitError,
    TruncatedDataError,
    V2FormatError,
)
from mokosh_v2_key_slots import ContactHybridSlot
from mokosh_v2_signatures import SignerFingerprintMismatchError
from mokosh_v2_slot_orchestration import (
    ContactCredential,
    KeySlotPlanBuilder,
    PasswordCredential,
    SlotCredentialMismatchError,
    SlotSelectionError,
    VaultCredential,
)
from mokosh_v2_streaming import (
    InspectedStreamEnvelope,
    PlaintextStreamPlan,
    QuarantineSinkError,
    StreamPassMismatchError,
    StreamPlanMismatchError,
    StreamSourceError,
    StreamingEnvelopeError,
    decrypt_stream_to_quarantine,
    encrypt_stream_to_quarantine,
    inspect_envelope_stream,
    scan_plaintext_stream,
)


try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as real_mlkem
except ImportError:
    real_mlkem = None


FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
DEK = bytes(range(32))
VAULT_KEY = b"V" * 32
PASSWORD = "correct horse battery staple"
SIGNER = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_SIGNER = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
CREATED_UTC = "2026-08-09T12:00:00Z"


class BoundedSource:
    def __init__(
        self,
        data,
        *,
        fragment=None,
        returned_type=bytes,
        oversize=False,
        failure=None,
    ):
        self._data = bytes(data)
        self._offset = 0
        self.fragment = fragment
        self.returned_type = returned_type
        self.oversize = oversize
        self.failure = failure
        self.requests = []

    def read(self, size):
        self.requests.append(size)
        if self.failure is not None:
            raise self.failure
        if type(size) is not int or size <= 0:
            raise AssertionError("streaming code made an unbounded read")
        amount = size + 1 if self.oversize else size
        if self.fragment is not None:
            amount = min(amount, self.fragment)
        part = self._data[self._offset : self._offset + amount]
        self._offset += len(part)
        if self.returned_type is bytes:
            return part
        if self.returned_type is bytearray:
            return bytearray(part)
        if self.returned_type is memoryview:
            return memoryview(part)
        return self.returned_type


class MemoryQuarantineSink:
    def __init__(
        self,
        *,
        partial=None,
        write_failure=None,
        commit_failure=None,
        abort_failure=None,
        interrupt_write=False,
    ):
        self._staging = bytearray()
        self._public = None
        self.partial = partial
        self.write_failure = write_failure
        self.commit_failure = commit_failure
        self.abort_failure = abort_failure
        self.interrupt_write = interrupt_write
        self.committed = False
        self.aborted = False
        self.events = []

    def write(self, data):
        self.events.append("write")
        if self.committed or self.aborted:
            raise AssertionError("write after transaction end")
        if self.interrupt_write:
            raise KeyboardInterrupt()
        if self.write_failure is not None:
            raise self.write_failure
        view = bytes(data)
        amount = len(view) if self.partial is None else min(len(view), self.partial)
        if amount:
            self._staging.extend(view[:amount])
        return amount

    def commit(self):
        self.events.append("commit")
        if self.commit_failure is not None:
            raise self.commit_failure
        self._public = bytes(self._staging)
        self.committed = True

    def abort(self):
        self.events.append("abort")
        if self.abort_failure is not None:
            raise self.abort_failure
        self._staging.clear()
        self.aborted = True

    @property
    def public_bytes(self):
        if not self.committed:
            raise RuntimeError("quarantined bytes are not public")
        return self._public


def vault_plan(*, include_password=False):
    builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
    password_slot = None
    if include_password:
        password_slot = builder.add_password(
            PASSWORD,
            time_cost=2,
            parallelism=1,
        )
    vault_slot = builder.add_vault(VAULT_KEY, 3)
    return builder.finish(), password_slot, vault_slot


def fixed_contact_slot():
    return ContactHybridSlot(
        slot_id=b"C" * 16,
        recipient_key_version=8,
        ephemeral_x25519_public_key=b"E" * 32,
        mlkem_ciphertext=b"K" * 1088,
        wrap_nonce=b"N" * 12,
        wrapped_dek=b"W" * 48,
    )


def fake_contact_plan():
    builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
    with patch(
        "mokosh_v2_slot_orchestration.create_contact_slot",
        return_value=fixed_contact_slot(),
    ):
        slot = builder.add_contact(b"X" * 32, b"M" * 1184, 8)
    return builder.finish(), slot


def stream_encrypt(
    payload,
    *,
    signed=False,
    plan=None,
    chunk_size=MIN_CHUNK_SIZE,
):
    key_plan, _, vault_slot = vault_plan() if plan is None else plan
    stream_plan = scan_plaintext_stream(
        BoundedSource(payload, fragment=701),
        chunk_size=chunk_size,
    )
    sink = MemoryQuarantineSink(partial=503)
    signing = (
        Ed25519EnvelopeSigning(SIGNER, 7)
        if signed
        else UnsignedEnvelopeSigning()
    )
    result = encrypt_stream_to_quarantine(
        key_plan=key_plan,
        plaintext_source=BoundedSource(payload, fragment=509),
        sink=sink,
        stream_plan=stream_plan,
        original_name="report.txt",
        content_type="text/plain",
        signing=signing,
        created_utc=CREATED_UTC,
    )
    return sink.public_bytes, result, vault_slot


class StreamPlanningTests(unittest.TestCase):
    def test_empty_boundary_and_multiframe_plans(self):
        cases = (
            (b"", 1),
            (b"A" * MIN_CHUNK_SIZE, 1),
            (b"B" * (MIN_CHUNK_SIZE + 1), 2),
        )
        for payload, frames in cases:
            with self.subTest(size=len(payload)):
                plan = scan_plaintext_stream(
                    BoundedSource(payload, fragment=313),
                    chunk_size=MIN_CHUNK_SIZE,
                )
                self.assertEqual(plan.original_size, len(payload))
                self.assertEqual(plan.plaintext_sha256, hashlib.sha256(payload).digest())
                self.assertEqual(plan.data_frames, frames)

    def test_scan_never_uses_unbounded_read(self):
        source = BoundedSource(b"x" * (MIN_CHUNK_SIZE + 17), fragment=97)
        scan_plaintext_stream(source, chunk_size=MIN_CHUNK_SIZE)
        self.assertTrue(source.requests)
        self.assertTrue(all(0 < size <= MIN_CHUNK_SIZE for size in source.requests))
        memory_plan = scan_plaintext_stream(
            BytesIO(b"BytesIO contract"),
            chunk_size=MIN_CHUNK_SIZE,
        )
        self.assertEqual(memory_plan.original_size, 16)

    def test_scan_enforces_caller_size_limit(self):
        with self.assertRaises(FormatLimitError):
            scan_plaintext_stream(
                BoundedSource(b"12345"),
                chunk_size=MIN_CHUNK_SIZE,
                max_plaintext_size=4,
            )

    def test_invalid_chunk_and_limit_are_rejected_before_read(self):
        for chunk, limit in (
            (1, None),
            (True, None),
            (MIN_CHUNK_SIZE, -1),
            (MIN_CHUNK_SIZE, True),
        ):
            source = BoundedSource(b"data")
            with self.subTest(chunk=chunk, limit=limit):
                with self.assertRaises(V2FormatError):
                    scan_plaintext_stream(
                        source,
                        chunk_size=chunk,
                        max_plaintext_size=limit,
                    )
                self.assertEqual(source.requests, [])

    def test_source_contract_rejects_missing_wrong_and_oversized_reads(self):
        with self.assertRaises(StreamSourceError):
            scan_plaintext_stream(object(), chunk_size=MIN_CHUNK_SIZE)
        with self.assertRaises(StreamSourceError):
            scan_plaintext_stream(
                BoundedSource(b"x", returned_type="not-bytes"),
                chunk_size=MIN_CHUNK_SIZE,
            )
        with self.assertRaises(StreamSourceError):
            scan_plaintext_stream(
                BoundedSource(b"xyz", oversize=True),
                chunk_size=MIN_CHUNK_SIZE,
                max_plaintext_size=1,
            )

    def test_source_exception_is_wrapped(self):
        with self.assertRaises(StreamSourceError):
            scan_plaintext_stream(
                BoundedSource(b"", failure=OSError("read failed")),
                chunk_size=MIN_CHUNK_SIZE,
            )

    def test_plaintext_plan_rejects_forged_fields(self):
        digest = hashlib.sha256(b"").digest()
        with self.assertRaises(StreamingEnvelopeError):
            PlaintextStreamPlan(0, b"short", 1, MIN_CHUNK_SIZE)
        with self.assertRaises(StreamingEnvelopeError):
            PlaintextStreamPlan(0, digest, 2, MIN_CHUNK_SIZE)
        with self.assertRaises(StreamingEnvelopeError):
            PlaintextStreamPlan(True, digest, 1, MIN_CHUNK_SIZE)


class StreamingEncryptionTests(unittest.TestCase):
    def test_unsigned_stream_matches_complete_decrypt_contract(self):
        payload = b"stream payload" * 7000
        envelope, result, slot = stream_encrypt(payload)
        decrypted = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
            verification=RequireUnsignedEnvelope(),
        )
        self.assertEqual(decrypted.plaintext, payload)
        self.assertEqual(result.manifest.original_size, len(payload))
        self.assertEqual(result.encoded_size, len(envelope))

    def test_signed_stream_is_verified_by_complete_reader(self):
        payload = b"signed streaming payload"
        envelope, result, slot = stream_encrypt(payload, signed=True)
        decrypted = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
            verification=RequireEd25519Envelope(SIGNER.public_key()),
        )
        self.assertEqual(decrypted.plaintext, payload)
        self.assertTrue(result.trailer.is_signed)

    def test_partial_sink_writes_are_completed(self):
        payload = b"partial write data" * 5000
        envelope, _, slot = stream_encrypt(payload)
        self.assertGreater(len(envelope), len(payload))
        result = decrypt_complete_envelope(
            envelope_bytes=envelope,
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
            verification=RequireUnsignedEnvelope(),
        )
        self.assertEqual(result.plaintext, payload)

    def test_truncated_changed_and_extra_second_passes_abort(self):
        original = b"original plaintext"
        plan, _, _ = vault_plan()
        stream_plan = scan_plaintext_stream(
            BoundedSource(original),
            chunk_size=MIN_CHUNK_SIZE,
        )
        cases = (original[:-1], b"X" * len(original), original + b"!")
        for changed in cases:
            sink = MemoryQuarantineSink()
            with self.subTest(changed=changed):
                with self.assertRaises(
                    (
                        TruncatedDataError,
                        StreamPlanMismatchError,
                        StreamingEnvelopeError,
                    )
                ):
                    encrypt_stream_to_quarantine(
                        key_plan=plan,
                        plaintext_source=BoundedSource(changed),
                        sink=sink,
                        stream_plan=stream_plan,
                        original_name="x.txt",
                        signing=UnsignedEnvelopeSigning(),
                        created_utc=CREATED_UTC,
                    )
                self.assertTrue(sink.aborted)
                self.assertFalse(sink.committed)

    def test_contact_plan_rejects_unsigned_before_output(self):
        plan, _ = fake_contact_plan()
        stream_plan = scan_plaintext_stream(
            BoundedSource(b"contact"),
            chunk_size=MIN_CHUNK_SIZE,
        )
        sink = MemoryQuarantineSink()
        with self.assertRaises(CompleteEnvelopePolicyError):
            encrypt_stream_to_quarantine(
                key_plan=plan,
                plaintext_source=BoundedSource(b"contact"),
                sink=sink,
                stream_plan=stream_plan,
                original_name="contact.txt",
                signing=UnsignedEnvelopeSigning(),
                created_utc=CREATED_UTC,
            )
        self.assertTrue(sink.aborted)

    def test_write_and_commit_failures_abort(self):
        plan, _, _ = vault_plan()
        stream_plan = scan_plaintext_stream(
            BoundedSource(b"data"),
            chunk_size=MIN_CHUNK_SIZE,
        )
        for sink in (
            MemoryQuarantineSink(write_failure=OSError("write")),
            MemoryQuarantineSink(commit_failure=OSError("commit")),
        ):
            with self.subTest(events=sink.events):
                with self.assertRaises(QuarantineSinkError):
                    encrypt_stream_to_quarantine(
                        key_plan=plan,
                        plaintext_source=BoundedSource(b"data"),
                        sink=sink,
                        stream_plan=stream_plan,
                        original_name="x.txt",
                        signing=UnsignedEnvelopeSigning(),
                        created_utc=CREATED_UTC,
                    )
                self.assertTrue(sink.aborted)

    def test_zero_progress_and_abort_failure_are_loud(self):
        plan, _, _ = vault_plan()
        stream_plan = scan_plaintext_stream(BoundedSource(b"x"), chunk_size=MIN_CHUNK_SIZE)
        sink = MemoryQuarantineSink(partial=0, abort_failure=OSError("abort"))
        with self.assertRaisesRegex(QuarantineSinkError, "abort also failed"):
            encrypt_stream_to_quarantine(
                key_plan=plan,
                plaintext_source=BoundedSource(b"x"),
                sink=sink,
                stream_plan=stream_plan,
                original_name="x",
                signing=UnsignedEnvelopeSigning(),
                created_utc=CREATED_UTC,
            )

    def test_keyboard_interrupt_aborts_transaction(self):
        plan, _, _ = vault_plan()
        stream_plan = scan_plaintext_stream(BoundedSource(b"x"), chunk_size=MIN_CHUNK_SIZE)
        sink = MemoryQuarantineSink(interrupt_write=True)
        with self.assertRaises(KeyboardInterrupt):
            encrypt_stream_to_quarantine(
                key_plan=plan,
                plaintext_source=BoundedSource(b"x"),
                sink=sink,
                stream_plan=stream_plan,
                original_name="x",
                signing=UnsignedEnvelopeSigning(),
                created_utc=CREATED_UTC,
            )
        self.assertTrue(sink.aborted)


class StreamInspectionTests(unittest.TestCase):
    def test_unsigned_and_signed_inspection(self):
        unsigned, _, _ = stream_encrypt(b"unsigned")
        checked_unsigned = inspect_envelope_stream(
            BoundedSource(unsigned, fragment=127),
            verification=RequireUnsignedEnvelope(),
        )
        self.assertIsNone(checked_unsigned.verified_signature)
        signed, _, _ = stream_encrypt(b"signed", signed=True)
        checked_signed = inspect_envelope_stream(
            BoundedSource(signed, fragment=131),
            verification=RequireEd25519Envelope(SIGNER.public_key()),
        )
        self.assertEqual(checked_signed.verified_signature.signer_key_version, 7)

    def test_wrong_policy_and_signer_are_rejected_without_slot_unwrap(self):
        signed, _, _ = stream_encrypt(b"signed", signed=True)
        with patch("mokosh_v2_streaming.unwrap_selected_slot") as unwrap:
            with self.assertRaises(CompleteEnvelopePolicyError):
                inspect_envelope_stream(
                    BoundedSource(signed),
                    verification=RequireUnsignedEnvelope(),
                )
            with self.assertRaises(SignerFingerprintMismatchError):
                inspect_envelope_stream(
                    BoundedSource(signed),
                    verification=RequireEd25519Envelope(OTHER_SIGNER.public_key()),
                )
        unwrap.assert_not_called()

    def test_tampered_truncated_and_trailing_envelopes_are_rejected(self):
        envelope, _, _ = stream_encrypt(b"inspect me")
        changed = bytearray(envelope)
        changed[len(changed) // 2] ^= 1
        cases = (bytes(changed), envelope[:-1], envelope + b"x")
        for candidate in cases:
            with self.subTest(size=len(candidate)):
                with self.assertRaises(V2FormatError):
                    inspect_envelope_stream(
                        BoundedSource(candidate, fragment=83),
                        verification=RequireUnsignedEnvelope(),
                    )

    def test_inspection_reads_are_bounded(self):
        envelope, _, _ = stream_encrypt(b"bounded" * 20000)
        source = BoundedSource(envelope, fragment=41)
        inspect_envelope_stream(source, verification=RequireUnsignedEnvelope())
        self.assertTrue(all(0 < size <= MIN_CHUNK_SIZE + 16 for size in source.requests))

    def test_contact_signed_envelope_rejects_unsigned_inspection(self):
        plan, _ = fake_contact_plan()
        stream_plan = scan_plaintext_stream(BoundedSource(b"contact"), chunk_size=MIN_CHUNK_SIZE)
        sink = MemoryQuarantineSink()
        encrypt_stream_to_quarantine(
            key_plan=plan,
            plaintext_source=BoundedSource(b"contact"),
            sink=sink,
            stream_plan=stream_plan,
            original_name="contact.txt",
            signing=Ed25519EnvelopeSigning(SIGNER, 8),
            created_utc=CREATED_UTC,
        )
        with self.assertRaises(CompleteEnvelopePolicyError):
            inspect_envelope_stream(
                BoundedSource(sink.public_bytes),
                verification=RequireUnsignedEnvelope(),
            )

    def test_inspection_cannot_be_forged_by_normal_constructor(self):
        with self.assertRaises(StreamingEnvelopeError):
            InspectedStreamEnvelope(None, b"", (), None, None, None)


class StreamingDecryptionTests(unittest.TestCase):
    def test_unsigned_roundtrip_commits_only_after_full_verification(self):
        payload = b"decryption payload" * 7000
        envelope, _, slot = stream_encrypt(payload)
        inspection = inspect_envelope_stream(
            BoundedSource(envelope),
            verification=RequireUnsignedEnvelope(),
        )
        sink = MemoryQuarantineSink(partial=307)
        with self.assertRaises(RuntimeError):
            _ = sink.public_bytes
        result = decrypt_stream_to_quarantine(
            envelope_source=BoundedSource(envelope, fragment=211),
            sink=sink,
            inspection=inspection,
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
        )
        self.assertEqual(sink.public_bytes, payload)
        self.assertEqual(result.plaintext_size, len(payload))
        self.assertEqual(result.plaintext_sha256, hashlib.sha256(payload).digest())
        self.assertEqual(sink.events[-1], "commit")

    def test_signed_roundtrip_returns_proof_not_trust(self):
        envelope, _, slot = stream_encrypt(b"signed", signed=True)
        inspection = inspect_envelope_stream(
            BoundedSource(envelope),
            verification=RequireEd25519Envelope(SIGNER.public_key()),
        )
        sink = MemoryQuarantineSink()
        result = decrypt_stream_to_quarantine(
            envelope_source=BoundedSource(envelope),
            sink=sink,
            inspection=inspection,
            selected_slot_id=slot.slot_id,
            credential=VaultCredential(VAULT_KEY),
        )
        self.assertEqual(sink.public_bytes, b"signed")
        self.assertFalse(hasattr(result.verified_signature, "trusted"))

    def test_empty_boundary_and_multiframe_roundtrips(self):
        for payload in (b"", b"A" * MIN_CHUNK_SIZE, b"B" * (MIN_CHUNK_SIZE + 1)):
            with self.subTest(size=len(payload)):
                envelope, _, slot = stream_encrypt(payload)
                inspection = inspect_envelope_stream(
                    BoundedSource(envelope),
                    verification=RequireUnsignedEnvelope(),
                )
                sink = MemoryQuarantineSink()
                decrypt_stream_to_quarantine(
                    envelope_source=BoundedSource(envelope, fragment=193),
                    sink=sink,
                    inspection=inspection,
                    selected_slot_id=slot.slot_id,
                    credential=VaultCredential(VAULT_KEY),
                )
                self.assertEqual(sink.public_bytes, payload)

    def test_wrong_credential_and_missing_slot_abort_without_fallback(self):
        plan = vault_plan(include_password=True)
        envelope, _, vault_slot = stream_encrypt(b"secret", plan=plan)
        inspection = inspect_envelope_stream(
            BoundedSource(envelope),
            verification=RequireUnsignedEnvelope(),
        )
        cases = (
            (vault_slot.slot_id, PasswordCredential(PASSWORD), SlotCredentialMismatchError),
            (b"Z" * 16, VaultCredential(VAULT_KEY), SlotSelectionError),
        )
        for slot_id, credential, error in cases:
            sink = MemoryQuarantineSink()
            with self.subTest(error=error.__name__):
                with self.assertRaises(error):
                    decrypt_stream_to_quarantine(
                        envelope_source=BoundedSource(envelope),
                        sink=sink,
                        inspection=inspection,
                        selected_slot_id=slot_id,
                        credential=credential,
                    )
                self.assertTrue(sink.aborted)

    def test_different_second_pass_prefix_is_rejected(self):
        first, _, slot = stream_encrypt(b"same")
        second, _, _ = stream_encrypt(b"same")
        inspection = inspect_envelope_stream(
            BoundedSource(first),
            verification=RequireUnsignedEnvelope(),
        )
        sink = MemoryQuarantineSink()
        with self.assertRaises(StreamPassMismatchError):
            decrypt_stream_to_quarantine(
                envelope_source=BoundedSource(second),
                sink=sink,
                inspection=inspection,
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
            )
        self.assertTrue(sink.aborted)

    def test_tampered_ciphertext_second_pass_aborts_plaintext(self):
        envelope, _, slot = stream_encrypt(b"tamper target" * 10000)
        inspection = inspect_envelope_stream(
            BoundedSource(envelope),
            verification=RequireUnsignedEnvelope(),
        )
        changed = bytearray(envelope)
        offset = len(inspection.prefix_bytes) + 20
        changed[offset] ^= 1
        sink = MemoryQuarantineSink()
        with self.assertRaises(FrameAuthenticationError):
            decrypt_stream_to_quarantine(
                envelope_source=BoundedSource(bytes(changed)),
                sink=sink,
                inspection=inspection,
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
            )
        self.assertTrue(sink.aborted)
        self.assertFalse(sink.committed)

    def test_modified_second_pass_trailer_is_rejected(self):
        envelope, _, slot = stream_encrypt(b"signed trailer", signed=True)
        inspection = inspect_envelope_stream(
            BoundedSource(envelope),
            verification=RequireEd25519Envelope(SIGNER.public_key()),
        )
        changed = bytearray(envelope)
        changed[-1] ^= 1
        sink = MemoryQuarantineSink()
        with self.assertRaises(StreamPassMismatchError):
            decrypt_stream_to_quarantine(
                envelope_source=BoundedSource(bytes(changed)),
                sink=sink,
                inspection=inspection,
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
            )
        self.assertTrue(sink.aborted)

    def test_sink_write_commit_and_interrupt_failures_abort(self):
        envelope, _, slot = stream_encrypt(b"sink failure")
        inspection = inspect_envelope_stream(
            BoundedSource(envelope),
            verification=RequireUnsignedEnvelope(),
        )
        sinks = (
            MemoryQuarantineSink(write_failure=OSError("write")),
            MemoryQuarantineSink(commit_failure=OSError("commit")),
        )
        for sink in sinks:
            with self.subTest(sink=type(sink).__name__):
                with self.assertRaises(QuarantineSinkError):
                    decrypt_stream_to_quarantine(
                        envelope_source=BoundedSource(envelope),
                        sink=sink,
                        inspection=inspection,
                        selected_slot_id=slot.slot_id,
                        credential=VaultCredential(VAULT_KEY),
                    )
                self.assertTrue(sink.aborted)
        interrupted = MemoryQuarantineSink(interrupt_write=True)
        with self.assertRaises(KeyboardInterrupt):
            decrypt_stream_to_quarantine(
                envelope_source=BoundedSource(envelope),
                sink=interrupted,
                inspection=inspection,
                selected_slot_id=slot.slot_id,
                credential=VaultCredential(VAULT_KEY),
            )
        self.assertTrue(interrupted.aborted)

    def test_invalid_inspection_is_rejected_before_sink_activity(self):
        sink = MemoryQuarantineSink()
        with self.assertRaises(StreamingEnvelopeError):
            decrypt_stream_to_quarantine(
                envelope_source=BoundedSource(b""),
                sink=sink,
                inspection=object(),
                selected_slot_id=b"S" * 16,
                credential=VaultCredential(VAULT_KEY),
            )
        self.assertEqual(sink.events, [])


@unittest.skipUnless(real_mlkem is not None, "ML-KEM requires cryptography >= 47")
class RealHybridStreamingTests(unittest.TestCase):
    def test_real_signed_contact_stream_roundtrip(self):
        x_private = x25519.X25519PrivateKey.generate()
        pq_private = real_mlkem.MLKEM768PrivateKey.generate()
        builder = KeySlotPlanBuilder(file_id=FILE_ID, dek=DEK)
        slot = builder.add_contact(
            x_private.public_key().public_bytes_raw(),
            pq_private.public_key().public_bytes_raw(),
            9,
        )
        plan = builder.finish()
        payload = b"real hybrid streaming payload" * 3000
        stream_plan = scan_plaintext_stream(
            BoundedSource(payload),
            chunk_size=MIN_CHUNK_SIZE,
        )
        encrypted = MemoryQuarantineSink()
        encrypt_stream_to_quarantine(
            key_plan=plan,
            plaintext_source=BoundedSource(payload),
            sink=encrypted,
            stream_plan=stream_plan,
            original_name="contact.bin",
            signing=Ed25519EnvelopeSigning(SIGNER, 9),
            created_utc=CREATED_UTC,
        )
        inspection = inspect_envelope_stream(
            BoundedSource(encrypted.public_bytes),
            verification=RequireEd25519Envelope(SIGNER.public_key()),
        )
        plaintext = MemoryQuarantineSink()
        decrypt_stream_to_quarantine(
            envelope_source=BoundedSource(encrypted.public_bytes),
            sink=plaintext,
            inspection=inspection,
            selected_slot_id=slot.slot_id,
            credential=ContactCredential(
                x_private.private_bytes_raw(),
                pq_private.private_bytes_raw(),
            ),
        )
        self.assertEqual(plaintext.public_bytes, payload)


class StreamingScopeTests(unittest.TestCase):
    def test_module_has_no_path_filesystem_network_gui_or_trust_operations(self):
        import mokosh_v2_streaming

        source = inspect.getsource(mokosh_v2_streaming)
        for forbidden in (
            "open(",
            "Path(",
            "os.replace",
            "os.remove",
            "socket",
            "tkinter",
            "requests",
            "trusted =",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
