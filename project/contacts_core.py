"""Fail-closed tombstone for the retired legacy contact subsystem.

The former module contained an unauthenticated, downgrade-capable contact
format and stored private identity material outside the MOKOSH Key Vault.
Import is refused before any path, file, user data, or cryptographic backend is
accessed. A replacement contact workflow is not authorized by this module.
"""

from __future__ import annotations


QUARANTINE_ID = "MOKOSH-STAGE2.45.1-LEGACY-CONTACTS"


class LegacyContactSubsystemQuarantinedError(RuntimeError):
    """Raised before any retired legacy contact capability can execute."""


raise LegacyContactSubsystemQuarantinedError(
    "MOKOSH legacy contacts_core is quarantined fail-closed "
    f"({QUARANTINE_ID}). It must not encrypt, decrypt, manage identity keys, "
    "or access contacts.json. No replacement contact workflow is authorized yet."
)
