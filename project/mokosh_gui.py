import os
import sys
import subprocess
import tkinter as tk
from enum import Enum
from threading import Lock
from tkinter import filedialog, messagebox, simpledialog
from typing import TYPE_CHECKING

from crypto_core import encrypt_file, decrypt_file
from mokosh_paths import ensure_private_data_dir
from mokosh_vault_recovery_entry_request import (
    RecoveryEntryRequestDecision,
    VaultRecoveryEntryRequestError,
    VaultRecoveryEntryRequestOutcome,
    prepare_recovery_entry_request,
)
from mokosh_vault_recovery_entry_transition import (
    RecoveryEntryTransitionDecision,
    VaultRecoveryEntryTransitionError,
    VaultRecoveryEntryTransitionOutcome,
    _validate_transition_outcome as _validate_recovery_entry_transition_outcome,
    prepare_recovery_entry_transition,
)
if TYPE_CHECKING:
    from mokosh_vault_recovery_main_gui_bridge import (
        PreparedMainGUIRecoveryReviewBinding,
    )

# Stage 0 fail-closed mode.  Encryption and modules that can destroy data or
# expose unprotected private keys remain unavailable until their redesign and
# migration tests are complete.  Legacy decryption stays available so existing
# files are not held hostage by the upgrade.
SAFETY_MODE = True


class _RecoveryReviewGUIEventState(str, Enum):
    READY = "ready"
    DISPLAYING = "displaying"
    COMPLETED = "completed"
    FAILED = "failed"


class _RecoverySourceInspectionReviewGUIEventState(str, Enum):
    READY = "ready"
    DISPLAYING = "displaying"
    COMPLETED = "completed"
    FAILED = "failed"


class _RecoveryEntryGUIEventState(str, Enum):
    READY = "ready"
    DECIDING = "deciding"
    COMPLETED = "completed"
    FAILED = "failed"


class _RecoveryEntryTransitionGUIEventState(str, Enum):
    LOCKED = "locked"
    READY = "ready"
    DECIDING = "deciding"
    COMPLETED = "completed"
    FAILED = "failed"


class _RecoverySourceSelectionGUIEventState(str, Enum):
    LOCKED = "locked"
    READY = "ready"
    SELECTING = "selecting"
    COMPLETED = "completed"
    FAILED = "failed"


class _RecoverySourceInspectionRequestGUIEventState(str, Enum):
    LOCKED = "locked"
    READY = "ready"
    DECIDING = "deciding"
    COMPLETED = "completed"
    FAILED = "failed"


class _RecoverySourceInspectionPreparationRequestGUIEventState(str, Enum):
    LOCKED = "locked"
    READY = "ready"
    DECIDING = "deciding"
    COMPLETED = "completed"
    FAILED = "failed"


_RECOVERY_REVIEW_WIDGET_TEXT = {
    "bg-BG": {
        "banner": (
            "ПОДГОТВЕН ПРЕГЛЕД ЗА ВЪЗСТАНОВЯВАНЕ: само преглед; "
            "няма да бъде извършена операция."
        ),
        "button": "Отвори подготвения преглед",
        "completed": (
            "Прегледът приключи. Не е разрешена и не е извършена "
            "операция по възстановяване."
        ),
        "failed": (
            "Прегледът не можа да бъде показан безопасно. "
            "Не е извършена операция."
        ),
    },
    "en-GB": {
        "banner": (
            "PREPARED RECOVERY REVIEW: inspection only; no operation will "
            "be performed."
        ),
        "button": "Open prepared recovery review",
        "completed": (
            "The review has ended. No recovery operation was authorised or "
            "performed."
        ),
        "failed": (
            "The review could not be displayed safely. No operation was "
            "performed."
        ),
    },
}


_RECOVERY_SOURCE_INSPECTION_REVIEW_WIDGET_TEXT = {
    "bg-BG": {
        "banner": (
            "ПОДГОТВЕН ПРЕГЛЕД НА SOURCE INSPECTION: показва само вече "
            "ограничения резултат; не разрешава и не извършва recovery операция."
        ),
        "button": "Отвори подготвения source-inspection преглед",
        "completed": (
            "Прегледът на source-inspection резултата приключи. Не е разрешена "
            "и не е извършена recovery операция."
        ),
        "failed": (
            "Прегледът на source-inspection резултата не можа да бъде показан "
            "безопасно. Не е извършена операция."
        ),
    },
    "en-GB": {
        "banner": (
            "PREPARED SOURCE-INSPECTION REVIEW: displays only the already "
            "bounded result; it neither authorises nor performs recovery."
        ),
        "button": "Open prepared source-inspection review",
        "completed": (
            "The source-inspection result review has ended. No recovery "
            "operation was authorised or performed."
        ),
        "failed": (
            "The source-inspection result review could not be displayed "
            "safely. No operation was performed."
        ),
    },
}


_RECOVERY_SOURCE_SELECTION_WIDGET_TEXT = {
    "bg-BG": {
        "banner": (
            "ИЗБОР НА RECOVERY SOURCE: недостъпен е преди двете отделни "
            "положителни стъпки. Native picker може да преглежда filesystem "
            "metadata; MOKOSH само ще запише избрания недоверен path и няма да "
            "отвори или прочете source файла."
        ),
        "button": "Избери локален recovery record...",
        "picker_title": "Избери недоверен локален recovery record",
        "selected": (
            "Недовереният path е записан само за бъдеща стъпка. Recovery source "
            "не е отворен, прочетен, проверен, разрешен или използван и не е "
            "извършена операция."
        ),
        "stopped": (
            "Спряно е безопасно без избран recovery source. Не е отворен, "
            "прочетен или променен recovery файл и не е извършена операция."
        ),
        "failed": (
            "Recovery source не можа да бъде избран безопасно. Не е отворен или "
            "прочетен recovery файл и не е извършена операция."
        ),
    },
    "en-GB": {
        "banner": (
            "RECOVERY SOURCE SELECTION: unavailable until both separate positive "
            "steps complete. The native picker may inspect filesystem metadata; "
            "MOKOSH will only record the selected untrusted path and will not open "
            "or read the source file."
        ),
        "button": "Choose local recovery record...",
        "picker_title": "Choose an untrusted local recovery record",
        "selected": (
            "The untrusted path was recorded only for a future step. The recovery "
            "source was not opened, read, validated, authorised, or used, and no "
            "operation was performed."
        ),
        "stopped": (
            "Stopped safely without a selected recovery source. No recovery file "
            "was opened, read, or changed, and no operation was performed."
        ),
        "failed": (
            "The recovery source could not be selected safely. No recovery file "
            "was opened or read, and no operation was performed."
        ),
    },
}


_RECOVERY_SOURCE_INSPECTION_REQUEST_WIDGET_TEXT = {
    "bg-BG": {
        "banner": (
            "БЪДЕЩА СИГУРНА ИНСПЕКЦИЯ: недостъпна е преди отделен избор на "
            "recovery source. Това действие записва само еднократно искане; "
            "не отваря, не чете и не разрешава достъп до избрания source."
        ),
        "button": "Заяви бъдеща сигурна инспекция...",
        "confirm": (
            "Да се запише ли искане за бъдеща сигурна инспекция на току-що "
            "избрания недоверен source?\n\nPath няма да бъде показан. Source файлът "
            "няма да бъде отворен, прочетен, проверен или разрешен и няма да "
            "бъде извършена recovery операция.\n\nИзбери Да само за искането "
            "или Не за запазване и спиране."
        ),
        "requested": (
            "Искането за бъдеща сигурна инспекция е записано. Recovery source "
            "не е отворен, прочетен, проверен, разрешен или използван и не е "
            "извършена операция."
        ),
        "stopped": (
            "Спряно е безопасно и избраният path е изхвърлен от тази стъпка. "
            "Recovery source не е отворен, прочетен или променен и не е "
            "извършена операция."
        ),
        "failed": (
            "Искането за бъдеща сигурна инспекция не можа да бъде записано "
            "безопасно. Recovery source не е отворен или прочетен и не е "
            "извършена операция."
        ),
    },
    "en-GB": {
        "banner": (
            "FUTURE SECURE INSPECTION: unavailable until a separate recovery "
            "source selection. This action records only a one-shot request; it "
            "does not open, read, or authorise access to the selected source."
        ),
        "button": "Request future secure inspection...",
        "confirm": (
            "Record a request for a future secure inspection of the just-selected "
            "untrusted source?\n\nThe path will not be displayed. The source file "
            "will not be opened, read, validated, or authorised, and no recovery "
            "operation will be performed.\n\nChoose Yes only for the request, or "
            "No to preserve and stop."
        ),
        "requested": (
            "The future secure-inspection request was recorded. The recovery "
            "source was not opened, read, validated, authorised, or used, and no "
            "operation was performed."
        ),
        "stopped": (
            "Stopped safely and discarded the selected path from this step. The "
            "recovery source was not opened, read, or changed, and no operation "
            "was performed."
        ),
        "failed": (
            "The future secure-inspection request could not be recorded safely. "
            "The recovery source was not opened or read, and no operation was "
            "performed."
        ),
    },
}


_RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_WIDGET_TEXT = {
    "bg-BG": {
        "banner": (
            "БЪДЕЩА ПОДГОТОВКА ЗА СИГУРНА ИНСПЕКЦИЯ: недостъпна е преди "
            "отделно положително искане за бъдеща инспекция. Това действие "
            "записва само еднократно намерение; не отваря, не чете, не проверява "
            "и не разрешава достъп до source. Недовереният path се пази временно "
            "само в process-local паметта и Python не позволява доказуемото му "
            "зануляване."
        ),
        "button": "Заяви бъдеща подготовка за сигурна инспекция...",
        "confirm": (
            "Да се запише ли искане за бъдеща подготовка за сигурна инспекция "
            "на току-що избрания недоверен source?\n\nPath няма да бъде показан. "
            "Той се пази временно само в process-local паметта и не може да бъде "
            "доказуемо занулен като Python текст. Source няма да бъде отворен, "
            "прочетен, stat-нат, resolve-нат, проверен или разрешен; няма да бъде "
            "подготвен review и няма да бъде извършена recovery операция.\n\n"
            "Избери Да само за искането или Не за запазване и спиране."
        ),
        "requested": (
            "Искането за бъдеща подготовка е записано. Недовереният path остава "
            "само bounded process-local metadata за бъдеща отделна стъпка; source "
            "не е отворен, прочетен, проверен, разрешен или подготвен и не е "
            "извършена recovery операция."
        ),
        "stopped": (
            "Спряно е безопасно и недовереният path е изхвърлен от тази стъпка. "
            "Source не е отворен, прочетен, проверен, разрешен или променен и не "
            "е извършена recovery операция."
        ),
        "failed": (
            "Искането за бъдеща подготовка не можа да бъде записано безопасно. "
            "Source не е отворен, прочетен или разрешен и не е извършена "
            "recovery операция."
        ),
    },
    "en-GB": {
        "banner": (
            "FUTURE SECURE-INSPECTION PREPARATION: unavailable until a separate "
            "positive future-inspection request. This action records only a "
            "one-shot intent; it does not open, read, validate, or authorise the "
            "source. The untrusted path is held temporarily only in process-local "
            "memory and Python cannot provide proven zeroisation for it."
        ),
        "button": "Request future secure-inspection preparation...",
        "confirm": (
            "Record a request for future secure-inspection preparation of the "
            "just-selected untrusted source?\n\nThe path will not be displayed. It "
            "is held temporarily only in process-local memory and cannot be "
            "proven zeroised as Python text. The source will not be opened, read, "
            "inspected with stat, resolved, validated, or authorised; no review "
            "will be "
            "prepared and no recovery operation will be performed.\n\nChoose Yes "
            "only for the request, or No to preserve and stop."
        ),
        "requested": (
            "The future-preparation request was recorded. The untrusted path "
            "remains only bounded process-local metadata for a separate future "
            "step; the source was not opened, read, validated, authorised, or "
            "prepared, and no recovery operation was performed."
        ),
        "stopped": (
            "Stopped safely and discarded the untrusted path from this step. The "
            "source was not opened, read, validated, authorised, or changed, and "
            "no recovery operation was performed."
        ),
        "failed": (
            "The future-preparation request could not be recorded safely. The "
            "source was not opened, read, or authorised, and no recovery "
            "operation was performed."
        ),
    },
}

STRINGS = {
    "en": {
        "title": "MOKOSH Agent",
        "lang_label": "Language:",
        "vault_label": "Vault folder:",
        "btn_choose_vault": "Choose vault folder...",
        "pwd_label": "Password:",
        "nick_label": "Nickname:",
        "btn_login": "LOGIN",
        "btn_encrypt_main": "Encrypt...",
        "btn_decrypt_main": "Decrypt...",
        "btn_clean_main": "Clean originals...",
        "btn_enc_file": "Encrypt file",
        "btn_enc_vault": "Encrypt vault (folder)",
        "btn_dec_file": "Decrypt file",
        "btn_dec_vault": "Decrypt vault (folder)",
        "btn_clean_one": "Clean one file",
        "btn_clean_all": "Clean all in vault",
        "info_enc_ok": "Encrypted to:\n{}",
        "info_dec_ok": "Decrypted to:\n{}",
        "info_clean_all": "Cleaned originals in vault.\nDeleted: {}",
        "info_clean_one": "Deleted:\n{}",
        "err_no_file": "No file selected.",
        "err_pwd_empty": "Please enter a password and nickname.",
        "err_vault_not_dir": "Vault folder does not exist:\n{}",
        "err_not_logged_in": "Please login first using the main window.",
        "err_enc": "Error while encrypting:\n{}",
        "err_dec": "Error while decrypting:\n{}",
        "warn_vault_enc": (
            "WARNING:\n"
            "  You are about to ENCRYPT ALL files in this folder (and subfolders).\n"
            "  It is STRONGLY recommended to make a backup first.\n\n"
            "Type \"YES\" to continue, or anything else to cancel:"
        ),
        "warn_confirm_yes": "YES",
        "warn_confirm_da": "ДА",
        "warn_cancel": "Operation cancelled.",
        "warn_clean_all": (
            "WARNING:\n"
            "  This will DELETE in this vault:\n"
            "  - all originals that have a .mok file\n"
            "  - all *_dec files\n\n"
            "Type \"YES\" to continue, or anything else to cancel:"
        ),
        "warn_clean_one_title": "Select a file whose originals to clean",
        "warn_clean_one_none": "No original or *_dec found for this file.",
        "vault_enc_done": "Vault encryption done.\nEncrypted: {} files\nErrors: {}",
        "vault_dec_done": "Vault decryption done.\nDecrypted: {} files\nErrors: {}",
        "btn_bottom_contacts": "Contacts & Sharing",
        "btn_bottom_contact_crypto": "Contact Encryption",
        "btn_bottom_master": "Sandbox",
        "safety_banner": (
            "SAFETY MAINTENANCE MODE: encryption, cleanup, contacts and "
            "Sandbox are temporarily disabled. Legacy decryption is available."
        ),
        "recovery_entry_banner": (
            "RECOVERY REVIEW REQUEST: this records only a one-time request. "
            "It does not open a Vault, file, review, or recovery operation."
        ),
        "btn_recovery_entry": "Request recovery review...",
        "recovery_entry_confirm": (
            "Record a request for a future recovery review?\n\n"
            "No Vault, file, password, review, or recovery operation will be "
            "opened or started.\n\n"
            "Choose Yes to record the request, or No to preserve and stop."
        ),
        "recovery_entry_requested": (
            "The request was recorded. No Vault, file, review, or recovery "
            "operation was opened, authorised, or performed."
        ),
        "recovery_entry_stopped": (
            "Stopped safely without a recovery-review request. No Vault, file, "
            "review, or recovery operation was opened, authorised, or performed."
        ),
        "recovery_entry_failed": (
            "The request could not be recorded safely. No Vault, file, review, "
            "or recovery operation was opened or performed."
        ),
        "recovery_transition_banner": (
            "NEXT RECOVERY STEP: unavailable until a recovery-review request "
            "is recorded. It can record only an intent for a future source-selection "
            "step; it cannot select or open a source."
        ),
        "btn_recovery_transition": "Continue recovery request...",
        "recovery_transition_confirm": (
            "Record an intent to proceed to a future source-selection step?\n\n"
            "No source, Vault, file, password, review, or recovery operation will "
            "be selected, opened, or started.\n\n"
            "Choose Yes to record only that future intent, or No to preserve and stop."
        ),
        "recovery_transition_requested": (
            "The future source-selection intent was recorded. No source, Vault, "
            "file, review, or recovery operation was selected, opened, authorised, "
            "or performed."
        ),
        "recovery_transition_stopped": (
            "Stopped safely before any future source-selection intent. No source, "
            "Vault, file, review, or recovery operation was selected, opened, "
            "authorised, or performed."
        ),
        "recovery_transition_failed": (
            "The next intent could not be recorded safely. No source, Vault, file, "
            "review, or recovery operation was selected, opened, or performed."
        ),
    },
    "bg": {
        "title": "MOKOSH Агент",
        "lang_label": "Език:",
        "vault_label": "Трезор (папка):",
        "btn_choose_vault": "Избор на трезор...",
        "pwd_label": "Парола:",
        "nick_label": "Никнейм:",
        "btn_login": "ВЛЕЗ",
        "btn_encrypt_main": "Криптиране...",
        "btn_decrypt_main": "Декриптиране...",
        "btn_clean_main": "Почистване...",
        "btn_enc_file": "Криптирай файл",
        "btn_enc_vault": "Криптирай трезор (папка)",
        "btn_dec_file": "Декриптирайте файл",
        "btn_dec_vault": "Декриптирайте трезор (папка)",
        "btn_clean_one": "Почисти един файл",
        "btn_clean_all": "Почисти всички в трезора",
        "info_enc_ok": "Файлът е криптиран в:\n{}",
        "info_dec_ok": "Файлът е декриптиран в:\n{}",
        "info_clean_all": "Почистването на трезора приключи.\nИзтрити: {}",
        "info_clean_one": "Изтрити:\n{}",
        "err_no_file": "Няма избран файл.",
        "err_pwd_empty": "Моля, въведи парола и никнейм.",
        "err_vault_not_dir": "Папката на трезора не съществува:\n{}",
        "err_not_logged_in": "Моля, първо се логни от главния прозорец.",
        "err_enc": "Грешка при криптиране:\n{}",
        "err_dec": "Грешка при декриптиране:\n{}",
        "warn_vault_enc": (
            "ВНИМАНИЕ:\n"
            "  Ще КРИПТИРАТЕ ВСИЧКИ файлове в тази папка (и под-папките).\n"
            "  СИЛНО се препоръчва първо да направите резервно копие.\n\n"
            "Напишете \"ДА\", за да продължите, или нещо друго за отказ:"
        ),
        "warn_confirm_yes": "YES",
        "warn_confirm_da": "ДА",
        "warn_cancel": "Операцията е отказана.",
        "warn_clean_all": (
            "ВНИМАНИЕ:\n"
            "  Това ще ИЗТРИЕ в този трезор:\n"
            "  - всички оригинали, за които има .mok файл\n"
            "  - всички *_dec файлове\n\n"
            "Напишете \"ДА\", за да продължите, или нещо друго за отказ:"
        ),
        "warn_clean_one_title": "Избери файл за почистване на оригинала",
        "warn_clean_one_none": "Няма оригинал или *_dec за този файл.",
        "vault_enc_done": "Криптирането на трезора приключи.\nКриптирани: {}\nГрешки: {}",
        "vault_dec_done": "Декриптирането на трезора приключи.\nДекриптирани: {}\nГрешки: {}",
        "btn_bottom_contacts": "Контакти и споделяне",
        "btn_bottom_contact_crypto": "Криптиране за контакти",
        "btn_bottom_master": "Пясъчник",
        "safety_banner": (
            "РЕЖИМ ЗА БЕЗОПАСНА ПОДДРЪЖКА: криптирането, почистването, "
            "контактите и Sandbox са временно изключени. Старото декриптиране е достъпно."
        ),
        "recovery_entry_banner": (
            "ЗАЯВКА ЗА ПРЕГЛЕД ЗА ВЪЗСТАНОВЯВАНЕ: записва се само еднократно "
            "намерение. Не се отваря трезор, файл, преглед или операция."
        ),
        "btn_recovery_entry": "Заяви преглед за възстановяване...",
        "recovery_entry_confirm": (
            "Да се запише ли заявка за бъдещ преглед за възстановяване?\n\n"
            "Няма да бъде отворен или стартиран трезор, файл, парола, преглед "
            "или операция по възстановяване.\n\n"
            "Избери Да за заявка или Не за запазване и спиране."
        ),
        "recovery_entry_requested": (
            "Заявката е записана. Не е отворен, разрешен или извършен достъп "
            "до трезор, файл, преглед или операция по възстановяване."
        ),
        "recovery_entry_stopped": (
            "Спряно е безопасно без заявка за преглед. Не е отворен, разрешен "
            "или извършен достъп до трезор, файл, преглед или операция."
        ),
        "recovery_entry_failed": (
            "Заявката не можа да бъде записана безопасно. Не е отворен трезор, "
            "файл, преглед и не е извършена операция."
        ),
        "recovery_transition_banner": (
            "СЛЕДВАЩА СТЪПКА ЗА ВЪЗСТАНОВЯВАНЕ: недостъпна е преди записана "
            "заявка за преглед. Може да запише само намерение за бъдещ избор на "
            "източник; не може да избере или отвори източник."
        ),
        "btn_recovery_transition": "Продължи заявката за възстановяване...",
        "recovery_transition_confirm": (
            "Да се запише ли намерение за преминаване към бъдеща стъпка за избор "
            "на източник?\n\n"
            "Няма да бъде избран, отворен или стартиран източник, трезор, файл, "
            "парола, преглед или операция по възстановяване.\n\n"
            "Избери Да само за това бъдещо намерение или Не за запазване и спиране."
        ),
        "recovery_transition_requested": (
            "Намерението за бъдещ избор на източник е записано. Не е избран, "
            "отворен, разрешен или използван източник, трезор, файл, преглед или "
            "операция по възстановяване."
        ),
        "recovery_transition_stopped": (
            "Спряно е безопасно преди намерение за бъдещ избор на източник. Не е "
            "избран, отворен, разрешен или използван източник, трезор, файл, "
            "преглед или операция."
        ),
        "recovery_transition_failed": (
            "Следващото намерение не можа да бъде записано безопасно. Не е избран "
            "или отворен източник, трезор, файл или преглед и не е извършена операция."
        ),
    },
}

current_lang = "en"
vault_path = os.path.expanduser("~/SafeVault")
logged_in = False


def T(key: str) -> str:
    return STRINGS.get(current_lang, STRINGS["en"]).get(key, key)


def _recovery_review_bridge_contract():
    """Load the bounded Stage 2.17 bridge only for explicit review mode."""

    from mokosh_vault_recovery_main_gui_bridge import (
        PreparedMainGUIRecoveryReviewBinding,
        RecoveryMainGUIBridgeState,
        VaultRecoveryMainGUIBridgeError,
    )

    return (
        PreparedMainGUIRecoveryReviewBinding,
        RecoveryMainGUIBridgeState,
        VaultRecoveryMainGUIBridgeError,
    )


def _recovery_source_inspection_review_bridge_contract():
    """Load the bounded Stage 2.40 bridge only for an explicit review."""

    from mokosh_vault_recovery_source_inspection_main_gui_bridge import (
        PreparedMainGUIRecoverySourceInspectionReviewBinding,
        RecoverySourceInspectionMainGUIBridgeState,
        VaultRecoverySourceInspectionMainGUIBridgeError,
    )

    return (
        PreparedMainGUIRecoverySourceInspectionReviewBinding,
        RecoverySourceInspectionMainGUIBridgeState,
        VaultRecoverySourceInspectionMainGUIBridgeError,
    )


def _recovery_source_selection_contract():
    """Load the pure Stage 2.27 contract only on the explicit third action."""

    from mokosh_vault_recovery_source_selection import (
        RecoverySourceSelectionDecision,
        VaultRecoverySourceSelectionError,
        prepare_recovery_source_selection,
    )

    return (
        RecoverySourceSelectionDecision,
        VaultRecoverySourceSelectionError,
        prepare_recovery_source_selection,
    )


def _recovery_source_selection_outcome_contract():
    """Load exact Stage 2.27 outcome validation only after source selection."""

    from mokosh_vault_recovery_source_selection import (
        RecoverySourceSelectionDecision,
        VaultRecoverySourceSelectionOutcome,
        _validate_source_selection_outcome,
    )

    return (
        RecoverySourceSelectionDecision,
        VaultRecoverySourceSelectionOutcome,
        _validate_source_selection_outcome,
    )


def _recovery_source_inspection_request_contract():
    """Load pure Stage 2.29 only on the explicit fourth action."""

    from mokosh_vault_recovery_source_inspection_request import (
        RecoverySourceInspectionRequestDecision,
        VaultRecoverySourceInspectionRequestError,
        prepare_recovery_source_inspection_request,
    )

    return (
        RecoverySourceInspectionRequestDecision,
        VaultRecoverySourceInspectionRequestError,
        prepare_recovery_source_inspection_request,
    )


def _recovery_source_inspection_request_outcome_contract():
    """Load exact Stage 2.29 validation only when arming the fifth action."""

    from mokosh_vault_recovery_source_inspection_request import (
        RecoverySourceInspectionRequestDecision,
        VaultRecoverySourceInspectionRequestOutcome,
        _validate_source_inspection_request_outcome,
    )

    return (
        RecoverySourceInspectionRequestDecision,
        VaultRecoverySourceInspectionRequestOutcome,
        _validate_source_inspection_request_outcome,
    )


def _recovery_source_inspection_preparation_request_contract():
    """Load pure Stage 2.31 only on the explicit fifth action."""

    from mokosh_vault_recovery_source_inspection_preparation_request import (
        RecoverySourceInspectionPreparationRequestDecision,
        VaultRecoverySourceInspectionPreparationRequestError,
        prepare_recovery_source_inspection_preparation_request,
    )

    return (
        RecoverySourceInspectionPreparationRequestDecision,
        VaultRecoverySourceInspectionPreparationRequestError,
        prepare_recovery_source_inspection_preparation_request,
    )


def show_prepared_recovery_review(
    parent,
    prepared_binding: "PreparedMainGUIRecoveryReviewBinding",
):
    """Inactive Stage 2.17 seam for an exact pre-bound read-only review."""

    prepared_type, _, _ = _recovery_review_bridge_contract()
    if type(prepared_binding) is not prepared_type:
        raise TypeError("prepared recovery review binding is required")
    return prepared_binding.show_once(parent)


def show_prepared_recovery_source_inspection_review(
    parent,
    prepared_binding: "PreparedMainGUIRecoverySourceInspectionReviewBinding",
):
    """Inactive Stage 2.40 seam for one exact pre-bound read-only review."""

    prepared_type, _, _ = _recovery_source_inspection_review_bridge_contract()
    if type(prepared_binding) is not prepared_type:
        raise TypeError(
            "prepared recovery source inspection review binding is required"
        )
    return prepared_binding.show_once(parent)


class _RecoveryEntryGUIEvent:
    """One-shot normal-GUI event using only the bounded Stage 2.19 request."""

    __slots__ = (
        "_parent",
        "_button",
        "_transition_event",
        "_state",
        "_lock",
    )

    def __init__(self, parent, transition_event=None) -> None:
        if (
            transition_event is not None
            and type(transition_event) is not _RecoveryEntryTransitionGUIEvent
        ):
            raise TypeError("exact recovery entry transition event is required")
        self._parent = parent
        self._button = None
        self._transition_event = transition_event
        self._state = _RecoveryEntryGUIEventState.READY
        self._lock = Lock()

    @property
    def current_state(self) -> _RecoveryEntryGUIEventState:
        return self._state

    def attach_button(self, button) -> None:
        with self._lock:
            if self._state is not _RecoveryEntryGUIEventState.READY:
                raise TypeError("recovery entry event is not fresh")
            if self._button is not None:
                raise TypeError("recovery entry button is already attached")
            self._button = button

    def __call__(self):
        with self._lock:
            if self._state is not _RecoveryEntryGUIEventState.READY:
                return None
            button = self._button
            if button is None:
                self._state = _RecoveryEntryGUIEventState.FAILED
                return None
            self._state = _RecoveryEntryGUIEventState.DECIDING

        locale_id = "bg-BG" if current_lang == "bg" else "en-GB"
        try:
            button.config(state=tk.DISABLED)
            prepared = prepare_recovery_entry_request(locale_id)
            requested = messagebox.askyesno(
                T("title"),
                T("recovery_entry_confirm"),
                parent=self._parent,
            )
            decision = (
                RecoveryEntryRequestDecision.REQUEST_RECOVERY_REVIEW
                if requested
                else RecoveryEntryRequestDecision.PRESERVE_AND_STOP
            )
            outcome = prepared.decide_once(decision)
        except VaultRecoveryEntryRequestError:
            with self._lock:
                self._state = _RecoveryEntryGUIEventState.FAILED
            messagebox.showerror(
                T("title"),
                T("recovery_entry_failed"),
                parent=self._parent,
            )
            return None
        except Exception:
            with self._lock:
                self._state = _RecoveryEntryGUIEventState.FAILED
            messagebox.showerror(
                T("title"),
                T("recovery_entry_failed"),
                parent=self._parent,
            )
            return None
        except BaseException:
            with self._lock:
                self._state = _RecoveryEntryGUIEventState.FAILED
            raise

        with self._lock:
            self._state = _RecoveryEntryGUIEventState.COMPLETED
        messagebox.showinfo(
            T("title"),
            T(
                "recovery_entry_requested"
                if outcome.review_requested
                else "recovery_entry_stopped"
            ),
            parent=self._parent,
        )
        transition_event = self._transition_event
        if outcome.review_requested and transition_event is not None:
            try:
                armed = transition_event.arm_once(outcome)
            except Exception:
                armed = False
            except BaseException:
                raise
            if not armed:
                messagebox.showerror(
                    T("title"),
                    T("recovery_transition_failed"),
                    parent=self._parent,
                )
        return outcome


class _RecoverySourceInspectionRequestGUIEvent:
    """Fourth one-shot action retaining one exact positive Stage 2.27 outcome."""

    __slots__ = (
        "_parent",
        "_banner",
        "_button",
        "_selection_outcome",
        "_preparation_request_event",
        "_locale_id",
        "_state",
        "_lock",
    )

    def __init__(self, parent, preparation_request_event=None) -> None:
        if (
            preparation_request_event is not None
            and type(preparation_request_event)
            is not _RecoverySourceInspectionPreparationRequestGUIEvent
        ):
            raise TypeError(
                "exact recovery source inspection preparation request event is required"
            )
        self._parent = parent
        self._banner = None
        self._button = None
        self._selection_outcome = None
        self._preparation_request_event = preparation_request_event
        self._locale_id = None
        self._state = _RecoverySourceInspectionRequestGUIEventState.LOCKED
        self._lock = Lock()

    @property
    def current_state(self) -> _RecoverySourceInspectionRequestGUIEventState:
        return self._state

    @property
    def retains_source_selection_outcome(self) -> bool:
        return self._selection_outcome is not None

    @property
    def bound_locale_id(self) -> str | None:
        return self._locale_id

    def attach_widgets(self, banner, button) -> None:
        with self._lock:
            if self._state is not _RecoverySourceInspectionRequestGUIEventState.LOCKED:
                raise TypeError("recovery source inspection request event is not locked")
            if self._banner is not None or self._button is not None:
                raise TypeError(
                    "recovery source inspection request widgets are already attached"
                )
            self._banner = banner
            self._button = button

    def arm_once(self, selection_outcome) -> bool:
        """Enable the request only for one fully revalidated positive selection."""

        with self._lock:
            if self._state is not _RecoverySourceInspectionRequestGUIEventState.LOCKED:
                return False
            try:
                decision_type, outcome_type, validate_outcome = (
                    _recovery_source_selection_outcome_contract()
                )
                if type(selection_outcome) is not outcome_type:
                    raise TypeError
                validate_outcome(selection_outcome)
                if (
                    selection_outcome.selection_decision
                    is not decision_type.SELECT_LOCAL_RECOVERY_RECORD
                    or selection_outcome.source_selected is not True
                ):
                    raise TypeError
            except Exception:
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
                raise TypeError(
                    "exact positive recovery source selection outcome is required"
                ) from None
            except BaseException:
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
                raise
            banner = self._banner
            button = self._button
            if banner is None or button is None:
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
                return False
            locale_id = selection_outcome.locale.value
            text = _RECOVERY_SOURCE_INSPECTION_REQUEST_WIDGET_TEXT[locale_id]
            try:
                banner.config(text=text["banner"])
                button.config(text=text["button"], state=tk.NORMAL)
            except Exception:
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
                return False
            except BaseException:
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
                raise
            self._selection_outcome = selection_outcome
            self._locale_id = locale_id
            self._state = _RecoverySourceInspectionRequestGUIEventState.READY
            return True

    def __call__(self):
        with self._lock:
            if self._state is not _RecoverySourceInspectionRequestGUIEventState.READY:
                return None
            button = self._button
            selection_outcome = self._selection_outcome
            locale_id = self._locale_id
            if (
                button is None
                or selection_outcome is None
                or locale_id not in _RECOVERY_SOURCE_INSPECTION_REQUEST_WIDGET_TEXT
            ):
                self._selection_outcome = None
                self._locale_id = None
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
                return None
            self._selection_outcome = None
            self._locale_id = None
            self._state = _RecoverySourceInspectionRequestGUIEventState.DECIDING

        text = _RECOVERY_SOURCE_INSPECTION_REQUEST_WIDGET_TEXT[locale_id]
        try:
            button.config(state=tk.DISABLED)
            decision_type, _, prepare_request = (
                _recovery_source_inspection_request_contract()
            )
            prepared = prepare_request(selection_outcome)
            requesting = messagebox.askyesno(
                text["button"],
                text["confirm"],
                parent=self._parent,
            )
            decision = (
                decision_type.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
                if requesting
                else decision_type.PRESERVE_AND_STOP
            )
            outcome = prepared.decide_once(decision)
        except Exception:
            with self._lock:
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
            messagebox.showerror(
                text["button"],
                text["failed"],
                parent=self._parent,
            )
            return None
        except BaseException:
            with self._lock:
                self._state = _RecoverySourceInspectionRequestGUIEventState.FAILED
            raise

        with self._lock:
            self._state = _RecoverySourceInspectionRequestGUIEventState.COMPLETED
        messagebox.showinfo(
            text["button"],
            text[
                "requested"
                if outcome.future_secure_source_inspection_requested
                else "stopped"
            ],
            parent=self._parent,
        )
        preparation_request_event = self._preparation_request_event
        if (
            outcome.future_secure_source_inspection_requested
            and preparation_request_event is not None
        ):
            try:
                armed = preparation_request_event.arm_once(outcome)
            except Exception:
                armed = False
            except BaseException:
                raise
            if not armed:
                messagebox.showerror(
                    text["button"],
                    _RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_WIDGET_TEXT[
                        outcome.locale.value
                    ]["failed"],
                    parent=self._parent,
                )
        return outcome


class _RecoverySourceInspectionPreparationRequestGUIEvent:
    """Fifth one-shot action retaining one exact positive Stage 2.29 outcome."""

    __slots__ = (
        "_parent",
        "_banner",
        "_button",
        "_inspection_request_outcome",
        "_locale_id",
        "_state",
        "_lock",
    )

    def __init__(self, parent) -> None:
        self._parent = parent
        self._banner = None
        self._button = None
        self._inspection_request_outcome = None
        self._locale_id = None
        self._state = (
            _RecoverySourceInspectionPreparationRequestGUIEventState.LOCKED
        )
        self._lock = Lock()

    @property
    def current_state(self) -> _RecoverySourceInspectionPreparationRequestGUIEventState:
        return self._state

    @property
    def retains_source_inspection_request_outcome(self) -> bool:
        return self._inspection_request_outcome is not None

    @property
    def bound_locale_id(self) -> str | None:
        return self._locale_id

    def attach_widgets(self, banner, button) -> None:
        with self._lock:
            if (
                self._state
                is not _RecoverySourceInspectionPreparationRequestGUIEventState.LOCKED
            ):
                raise TypeError(
                    "recovery source inspection preparation request event is not locked"
                )
            if self._banner is not None or self._button is not None:
                raise TypeError(
                    "recovery source inspection preparation request widgets are already attached"
                )
            self._banner = banner
            self._button = button

    def arm_once(self, inspection_request_outcome) -> bool:
        """Enable only for one fully revalidated positive Stage 2.29 outcome."""

        with self._lock:
            if (
                self._state
                is not _RecoverySourceInspectionPreparationRequestGUIEventState.LOCKED
            ):
                return False
            try:
                decision_type, outcome_type, validate_outcome = (
                    _recovery_source_inspection_request_outcome_contract()
                )
                if type(inspection_request_outcome) is not outcome_type:
                    raise TypeError
                validate_outcome(inspection_request_outcome)
                if (
                    inspection_request_outcome.inspection_decision
                    is not decision_type.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION
                    or inspection_request_outcome.future_secure_source_inspection_requested
                    is not True
                ):
                    raise TypeError
            except Exception:
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
                raise TypeError(
                    "exact positive recovery source inspection request outcome is required"
                ) from None
            except BaseException:
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
                raise
            banner = self._banner
            button = self._button
            if banner is None or button is None:
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
                return False
            locale_id = inspection_request_outcome.locale.value
            text = _RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_WIDGET_TEXT[
                locale_id
            ]
            try:
                banner.config(text=text["banner"])
                button.config(text=text["button"], state=tk.NORMAL)
            except Exception:
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
                return False
            except BaseException:
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
                raise
            self._inspection_request_outcome = inspection_request_outcome
            self._locale_id = locale_id
            self._state = (
                _RecoverySourceInspectionPreparationRequestGUIEventState.READY
            )
            return True

    def __call__(self):
        with self._lock:
            if (
                self._state
                is not _RecoverySourceInspectionPreparationRequestGUIEventState.READY
            ):
                return None
            button = self._button
            inspection_request_outcome = self._inspection_request_outcome
            locale_id = self._locale_id
            if (
                button is None
                or inspection_request_outcome is None
                or locale_id
                not in _RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_WIDGET_TEXT
            ):
                self._inspection_request_outcome = None
                self._locale_id = None
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
                return None
            self._inspection_request_outcome = None
            self._locale_id = None
            self._state = (
                _RecoverySourceInspectionPreparationRequestGUIEventState.DECIDING
            )

        text = _RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_WIDGET_TEXT[
            locale_id
        ]
        try:
            button.config(state=tk.DISABLED)
            decision_type, _, prepare_request = (
                _recovery_source_inspection_preparation_request_contract()
            )
            prepared = prepare_request(inspection_request_outcome)
            inspection_request_outcome = None
            requesting = messagebox.askyesno(
                text["button"],
                text["confirm"],
                parent=self._parent,
            )
            decision = (
                decision_type.REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION
                if requesting
                else decision_type.PRESERVE_AND_STOP
            )
            outcome = prepared.decide_once(decision)
        except Exception:
            with self._lock:
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
            messagebox.showerror(
                text["button"],
                text["failed"],
                parent=self._parent,
            )
            return None
        except BaseException:
            with self._lock:
                self._state = (
                    _RecoverySourceInspectionPreparationRequestGUIEventState.FAILED
                )
            raise

        with self._lock:
            self._state = (
                _RecoverySourceInspectionPreparationRequestGUIEventState.COMPLETED
            )
        messagebox.showinfo(
            text["button"],
            text[
                "requested"
                if outcome.future_secure_source_inspection_preparation_requested
                else "stopped"
            ],
            parent=self._parent,
        )
        return outcome


class _RecoverySourceSelectionGUIEvent:
    """Third one-shot action retaining only one exact Stage 2.21 outcome."""

    __slots__ = (
        "_parent",
        "_banner",
        "_button",
        "_transition_outcome",
        "_inspection_request_event",
        "_locale_id",
        "_state",
        "_lock",
    )

    def __init__(self, parent, inspection_request_event=None) -> None:
        if (
            inspection_request_event is not None
            and type(inspection_request_event)
            is not _RecoverySourceInspectionRequestGUIEvent
        ):
            raise TypeError(
                "exact recovery source inspection request event is required"
            )
        self._parent = parent
        self._banner = None
        self._button = None
        self._transition_outcome = None
        self._inspection_request_event = inspection_request_event
        self._locale_id = None
        self._state = _RecoverySourceSelectionGUIEventState.LOCKED
        self._lock = Lock()

    @property
    def current_state(self) -> _RecoverySourceSelectionGUIEventState:
        return self._state

    @property
    def retains_transition_outcome(self) -> bool:
        return self._transition_outcome is not None

    @property
    def bound_locale_id(self) -> str | None:
        return self._locale_id

    def attach_widgets(self, banner, button) -> None:
        with self._lock:
            if self._state is not _RecoverySourceSelectionGUIEventState.LOCKED:
                raise TypeError("recovery source selection event is not locked")
            if self._banner is not None or self._button is not None:
                raise TypeError("recovery source selection widgets are already attached")
            self._banner = banner
            self._button = button

    def arm_once(self, transition_outcome) -> bool:
        """Enable selection only for one fully revalidated positive transition."""

        with self._lock:
            if self._state is not _RecoverySourceSelectionGUIEventState.LOCKED:
                return False
            if type(transition_outcome) is not VaultRecoveryEntryTransitionOutcome:
                raise TypeError("exact positive recovery transition outcome is required")
            try:
                _validate_recovery_entry_transition_outcome(transition_outcome)
            except Exception:
                raise TypeError(
                    "exact positive recovery transition outcome is required"
                ) from None
            if (
                transition_outcome.transition_decision
                is not RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
                or transition_outcome.future_source_selection_requested is not True
            ):
                raise TypeError("exact positive recovery transition outcome is required")
            banner = self._banner
            button = self._button
            if banner is None or button is None:
                self._state = _RecoverySourceSelectionGUIEventState.FAILED
                return False
            locale_id = transition_outcome.locale.value
            text = _RECOVERY_SOURCE_SELECTION_WIDGET_TEXT[locale_id]
            try:
                banner.config(text=text["banner"])
                button.config(text=text["button"], state=tk.NORMAL)
            except Exception:
                self._state = _RecoverySourceSelectionGUIEventState.FAILED
                return False
            except BaseException:
                self._state = _RecoverySourceSelectionGUIEventState.FAILED
                raise
            self._transition_outcome = transition_outcome
            self._locale_id = locale_id
            self._state = _RecoverySourceSelectionGUIEventState.READY
            return True

    def __call__(self):
        with self._lock:
            if self._state is not _RecoverySourceSelectionGUIEventState.READY:
                return None
            button = self._button
            transition_outcome = self._transition_outcome
            locale_id = self._locale_id
            if (
                button is None
                or type(transition_outcome) is not VaultRecoveryEntryTransitionOutcome
                or locale_id not in _RECOVERY_SOURCE_SELECTION_WIDGET_TEXT
            ):
                self._transition_outcome = None
                self._locale_id = None
                self._state = _RecoverySourceSelectionGUIEventState.FAILED
                return None
            self._transition_outcome = None
            self._state = _RecoverySourceSelectionGUIEventState.SELECTING

        text = _RECOVERY_SOURCE_SELECTION_WIDGET_TEXT[locale_id]
        try:
            button.config(state=tk.DISABLED)
            decision_type, _, prepare_selection = (
                _recovery_source_selection_contract()
            )
            prepared = prepare_selection(transition_outcome)
            selected_path = filedialog.askopenfilename(
                title=text["picker_title"],
                parent=self._parent,
                filetypes=(
                    ("MOKOSH recovery record", "*.mokr"),
                    ("All files", "*"),
                ),
            )
            if selected_path == "":
                outcome = prepared.decide_once(
                    decision_type.PRESERVE_AND_STOP,
                    None,
                )
            else:
                outcome = prepared.decide_once(
                    decision_type.SELECT_LOCAL_RECOVERY_RECORD,
                    selected_path,
                )
        except Exception:
            with self._lock:
                self._state = _RecoverySourceSelectionGUIEventState.FAILED
            messagebox.showerror(
                text["picker_title"],
                text["failed"],
                parent=self._parent,
            )
            return None
        except BaseException:
            with self._lock:
                self._state = _RecoverySourceSelectionGUIEventState.FAILED
            raise

        with self._lock:
            self._state = _RecoverySourceSelectionGUIEventState.COMPLETED
        messagebox.showinfo(
            text["picker_title"],
            text["selected" if outcome.source_selected else "stopped"],
            parent=self._parent,
        )
        inspection_request_event = self._inspection_request_event
        if outcome.source_selected and inspection_request_event is not None:
            try:
                armed = inspection_request_event.arm_once(outcome)
            except Exception:
                armed = False
            except BaseException:
                raise
            if not armed:
                messagebox.showerror(
                    text["picker_title"],
                    _RECOVERY_SOURCE_INSPECTION_REQUEST_WIDGET_TEXT[
                        outcome.locale.value
                    ]["failed"],
                    parent=self._parent,
                )
        return outcome


class _RecoveryEntryTransitionGUIEvent:
    """Second one-shot action using only the bounded Stage 2.21 contract."""

    __slots__ = (
        "_parent",
        "_button",
        "_entry_outcome",
        "_source_selection_event",
        "_state",
        "_lock",
    )

    def __init__(self, parent, source_selection_event=None) -> None:
        if (
            source_selection_event is not None
            and type(source_selection_event) is not _RecoverySourceSelectionGUIEvent
        ):
            raise TypeError("exact recovery source selection event is required")
        self._parent = parent
        self._button = None
        self._entry_outcome = None
        self._source_selection_event = source_selection_event
        self._state = _RecoveryEntryTransitionGUIEventState.LOCKED
        self._lock = Lock()

    @property
    def current_state(self) -> _RecoveryEntryTransitionGUIEventState:
        return self._state

    @property
    def retains_entry_outcome(self) -> bool:
        return self._entry_outcome is not None

    def attach_button(self, button) -> None:
        with self._lock:
            if self._state is not _RecoveryEntryTransitionGUIEventState.LOCKED:
                raise TypeError("recovery entry transition event is not locked")
            if self._button is not None:
                raise TypeError("recovery entry transition button is already attached")
            self._button = button

    def arm_once(self, entry_outcome) -> bool:
        """Enable the separate action only for one exact positive request."""

        with self._lock:
            if self._state is not _RecoveryEntryTransitionGUIEventState.LOCKED:
                return False
            if (
                type(entry_outcome) is not VaultRecoveryEntryRequestOutcome
                or entry_outcome.review_requested is not True
            ):
                raise TypeError("exact positive recovery entry outcome is required")
            button = self._button
            if button is None:
                self._state = _RecoveryEntryTransitionGUIEventState.FAILED
                return False
            try:
                button.config(state=tk.NORMAL)
            except Exception:
                self._state = _RecoveryEntryTransitionGUIEventState.FAILED
                return False
            except BaseException:
                self._state = _RecoveryEntryTransitionGUIEventState.FAILED
                raise
            self._entry_outcome = entry_outcome
            self._state = _RecoveryEntryTransitionGUIEventState.READY
            return True

    def __call__(self):
        with self._lock:
            if self._state is not _RecoveryEntryTransitionGUIEventState.READY:
                return None
            button = self._button
            entry_outcome = self._entry_outcome
            if button is None or type(entry_outcome) is not VaultRecoveryEntryRequestOutcome:
                self._entry_outcome = None
                self._state = _RecoveryEntryTransitionGUIEventState.FAILED
                return None
            self._entry_outcome = None
            self._state = _RecoveryEntryTransitionGUIEventState.DECIDING

        try:
            button.config(state=tk.DISABLED)
            prepared = prepare_recovery_entry_transition(entry_outcome)
            text = STRINGS[
                "bg"
                if entry_outcome.locale.value == "bg-BG"
                else "en"
            ]
            proceeding = messagebox.askyesno(
                text["title"],
                text["recovery_transition_confirm"],
                parent=self._parent,
            )
            decision = (
                RecoveryEntryTransitionDecision.PROCEED_TO_FUTURE_SOURCE_SELECTION
                if proceeding
                else RecoveryEntryTransitionDecision.PRESERVE_AND_STOP
            )
            outcome = prepared.decide_once(decision)
        except VaultRecoveryEntryTransitionError:
            with self._lock:
                self._state = _RecoveryEntryTransitionGUIEventState.FAILED
            messagebox.showerror(
                T("title"),
                T("recovery_transition_failed"),
                parent=self._parent,
            )
            return None
        except Exception:
            with self._lock:
                self._state = _RecoveryEntryTransitionGUIEventState.FAILED
            messagebox.showerror(
                T("title"),
                T("recovery_transition_failed"),
                parent=self._parent,
            )
            return None
        except BaseException:
            with self._lock:
                self._state = _RecoveryEntryTransitionGUIEventState.FAILED
            raise

        with self._lock:
            self._state = _RecoveryEntryTransitionGUIEventState.COMPLETED
        messagebox.showinfo(
            text["title"],
            text[
                "recovery_transition_requested"
                if outcome.future_source_selection_requested
                else "recovery_transition_stopped"
            ],
            parent=self._parent,
        )
        source_selection_event = self._source_selection_event
        if outcome.future_source_selection_requested and source_selection_event is not None:
            try:
                armed = source_selection_event.arm_once(outcome)
            except Exception:
                armed = False
            except BaseException:
                raise
            if not armed:
                messagebox.showerror(
                    text["title"],
                    _RECOVERY_SOURCE_SELECTION_WIDGET_TEXT[outcome.locale.value][
                        "failed"
                    ],
                    parent=self._parent,
                )
        return outcome


def _wire_recovery_entry_request_widget(
    parent,
    container,
    transition_event=None,
):
    """Create the normal-startup Stage 2.20 non-secret one-shot entry."""

    event = _RecoveryEntryGUIEvent(parent, transition_event)
    banner = tk.Label(
        container,
        text=T("recovery_entry_banner"),
        font=("TkDefaultFont", 10, "bold"),
        fg="#184d47",
        bg="#d9f2ee",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=7,
    )
    banner.pack(fill="x", padx=5, pady=(0, 5))
    button = tk.Button(
        container,
        text=T("btn_recovery_entry"),
        width=32,
        font=("TkDefaultFont", 11, "bold"),
        command=event,
    )
    event.attach_button(button)
    button.pack(fill="x", padx=5, pady=(0, 7))
    return banner, button, event


def _wire_recovery_entry_transition_widget(parent, container, event):
    """Create the locked Stage 2.25 no-source transition action."""

    if type(event) is not _RecoveryEntryTransitionGUIEvent:
        raise TypeError("exact recovery entry transition event is required")
    banner = tk.Label(
        container,
        text=T("recovery_transition_banner"),
        font=("TkDefaultFont", 10, "bold"),
        fg="#184d47",
        bg="#d9f2ee",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=7,
    )
    banner.pack(fill="x", padx=5, pady=(0, 5))
    button = tk.Button(
        container,
        text=T("btn_recovery_transition"),
        width=32,
        font=("TkDefaultFont", 11, "bold"),
        command=event,
        state=tk.DISABLED,
    )
    event.attach_button(button)
    button.pack(fill="x", padx=5, pady=(0, 7))
    return banner, button, event


def _wire_recovery_source_selection_widget(parent, container, event):
    """Create the locked Stage 2.28 path-metadata selection action."""

    if type(event) is not _RecoverySourceSelectionGUIEvent:
        raise TypeError("exact recovery source selection event is required")
    locale_id = "bg-BG" if current_lang == "bg" else "en-GB"
    text = _RECOVERY_SOURCE_SELECTION_WIDGET_TEXT[locale_id]
    banner = tk.Label(
        container,
        text=text["banner"],
        font=("TkDefaultFont", 10, "bold"),
        fg="#184d47",
        bg="#d9f2ee",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=7,
    )
    banner.pack(fill="x", padx=5, pady=(0, 5))
    button = tk.Button(
        container,
        text=text["button"],
        width=32,
        font=("TkDefaultFont", 11, "bold"),
        command=event,
        state=tk.DISABLED,
    )
    event.attach_widgets(banner, button)
    button.pack(fill="x", padx=5, pady=(0, 7))
    return banner, button, event


def _wire_recovery_source_inspection_request_widget(parent, container, event):
    """Create the locked Stage 2.30 future secure-inspection request action."""

    if type(event) is not _RecoverySourceInspectionRequestGUIEvent:
        raise TypeError("exact recovery source inspection request event is required")
    locale_id = "bg-BG" if current_lang == "bg" else "en-GB"
    text = _RECOVERY_SOURCE_INSPECTION_REQUEST_WIDGET_TEXT[locale_id]
    banner = tk.Label(
        container,
        text=text["banner"],
        font=("TkDefaultFont", 10, "bold"),
        fg="#184d47",
        bg="#d9f2ee",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=7,
    )
    banner.pack(fill="x", padx=5, pady=(0, 5))
    button = tk.Button(
        container,
        text=text["button"],
        width=32,
        font=("TkDefaultFont", 11, "bold"),
        command=event,
        state=tk.DISABLED,
    )
    event.attach_widgets(banner, button)
    button.pack(fill="x", padx=5, pady=(0, 7))
    return banner, button, event


def _wire_recovery_source_inspection_preparation_request_widget(
    parent,
    container,
    event,
):
    """Create the locked Stage 2.43 preparation-request action."""

    if (
        type(event)
        is not _RecoverySourceInspectionPreparationRequestGUIEvent
    ):
        raise TypeError(
            "exact recovery source inspection preparation request event is required"
        )
    locale_id = "bg-BG" if current_lang == "bg" else "en-GB"
    text = _RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_WIDGET_TEXT[
        locale_id
    ]
    banner = tk.Label(
        container,
        text=text["banner"],
        font=("TkDefaultFont", 10, "bold"),
        fg="#184d47",
        bg="#d9f2ee",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=7,
    )
    banner.pack(fill="x", padx=5, pady=(0, 5))
    button = tk.Button(
        container,
        text=text["button"],
        width=32,
        font=("TkDefaultFont", 11, "bold"),
        command=event,
        state=tk.DISABLED,
    )
    event.attach_widgets(banner, button)
    button.pack(fill="x", padx=5, pady=(0, 7))
    return banner, button, event


class _PreparedRecoveryReviewGUIEvent:
    """One-shot Tk event retaining only the bounded Stage 2.17 binding."""

    __slots__ = (
        "_parent",
        "_binding",
        "_button",
        "_locale_id",
        "_state",
        "_lock",
    )

    def __init__(
        self,
        parent,
        prepared_binding: "PreparedMainGUIRecoveryReviewBinding",
    ) -> None:
        prepared_type, bridge_state, _ = _recovery_review_bridge_contract()
        if (
            type(prepared_binding) is not prepared_type
            or prepared_binding.current_state is not bridge_state.READY
        ):
            raise TypeError("fresh prepared recovery review binding is required")
        locale_id = prepared_binding.locale.value
        if locale_id not in _RECOVERY_REVIEW_WIDGET_TEXT:
            raise TypeError("prepared recovery review locale is unavailable")
        self._parent = parent
        self._binding: "PreparedMainGUIRecoveryReviewBinding | None" = (
            prepared_binding
        )
        self._button = None
        self._locale_id = locale_id
        self._state = _RecoveryReviewGUIEventState.READY
        self._lock = Lock()

    @property
    def current_state(self) -> _RecoveryReviewGUIEventState:
        return self._state

    @property
    def retains_binding(self) -> bool:
        return self._binding is not None

    def attach_button(self, button) -> None:
        with self._lock:
            if self._state is not _RecoveryReviewGUIEventState.READY:
                raise TypeError("recovery review event is not fresh")
            if self._button is not None:
                raise TypeError("recovery review button is already attached")
            self._button = button

    def __call__(self):
        prepared_type, _, bridge_error = _recovery_review_bridge_contract()
        with self._lock:
            if self._state is not _RecoveryReviewGUIEventState.READY:
                return None
            binding = self._binding
            button = self._button
            if (
                type(binding) is not prepared_type
                or button is None
            ):
                self._binding = None
                self._state = _RecoveryReviewGUIEventState.FAILED
                return None
            self._binding = None
            self._state = _RecoveryReviewGUIEventState.DISPLAYING

        text = _RECOVERY_REVIEW_WIDGET_TEXT[self._locale_id]
        try:
            button.config(state=tk.DISABLED)
            outcome = show_prepared_recovery_review(self._parent, binding)
        except bridge_error:
            with self._lock:
                self._state = _RecoveryReviewGUIEventState.FAILED
            messagebox.showerror("MOKOSH", text["failed"], parent=self._parent)
            return None
        except Exception:
            with self._lock:
                self._state = _RecoveryReviewGUIEventState.FAILED
            messagebox.showerror("MOKOSH", text["failed"], parent=self._parent)
            return None
        except BaseException:
            with self._lock:
                self._state = _RecoveryReviewGUIEventState.FAILED
            raise

        with self._lock:
            self._state = _RecoveryReviewGUIEventState.COMPLETED
        messagebox.showinfo("MOKOSH", text["completed"], parent=self._parent)
        return outcome


def _wire_prepared_recovery_review_widget(
    parent,
    container,
    prepared_binding: "PreparedMainGUIRecoveryReviewBinding",
):
    """Create the conditional Stage 2.18 banner and one-shot button."""

    event = _PreparedRecoveryReviewGUIEvent(parent, prepared_binding)
    text = _RECOVERY_REVIEW_WIDGET_TEXT[prepared_binding.locale.value]
    banner = tk.Label(
        container,
        text=text["banner"],
        font=("TkDefaultFont", 10, "bold"),
        fg="#184d47",
        bg="#d9f2ee",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=7,
    )
    banner.pack(fill="x", padx=5, pady=(0, 5))
    button = tk.Button(
        container,
        text=text["button"],
        width=32,
        font=("TkDefaultFont", 11, "bold"),
        command=event,
    )
    event.attach_button(button)
    button.pack(fill="x", padx=5, pady=(0, 7))
    return banner, button, event


class _PreparedRecoverySourceInspectionReviewGUIEvent:
    """One-shot Tk event retaining only the bounded Stage 2.40 binding."""

    __slots__ = (
        "_parent",
        "_binding",
        "_button",
        "_locale_id",
        "_state",
        "_lock",
    )

    def __init__(
        self,
        parent,
        prepared_binding: "PreparedMainGUIRecoverySourceInspectionReviewBinding",
    ) -> None:
        prepared_type, bridge_state, _ = (
            _recovery_source_inspection_review_bridge_contract()
        )
        if (
            type(prepared_binding) is not prepared_type
            or prepared_binding.current_state is not bridge_state.READY
        ):
            raise TypeError(
                "fresh prepared recovery source inspection review binding is required"
            )
        locale_id = prepared_binding.locale.value
        if locale_id not in _RECOVERY_SOURCE_INSPECTION_REVIEW_WIDGET_TEXT:
            raise TypeError(
                "prepared recovery source inspection review locale is unavailable"
            )
        self._parent = parent
        self._binding: (
            "PreparedMainGUIRecoverySourceInspectionReviewBinding | None"
        ) = prepared_binding
        self._button = None
        self._locale_id = locale_id
        self._state = _RecoverySourceInspectionReviewGUIEventState.READY
        self._lock = Lock()

    @property
    def current_state(self) -> _RecoverySourceInspectionReviewGUIEventState:
        return self._state

    @property
    def retains_binding(self) -> bool:
        return self._binding is not None

    def attach_button(self, button) -> None:
        with self._lock:
            if (
                self._state
                is not _RecoverySourceInspectionReviewGUIEventState.READY
            ):
                raise TypeError(
                    "recovery source inspection review event is not fresh"
                )
            if self._button is not None:
                raise TypeError(
                    "recovery source inspection review button is already attached"
                )
            self._button = button

    def __call__(self):
        prepared_type, bridge_state, bridge_error = (
            _recovery_source_inspection_review_bridge_contract()
        )
        with self._lock:
            if (
                self._state
                is not _RecoverySourceInspectionReviewGUIEventState.READY
            ):
                return None
            binding = self._binding
            button = self._button
            if type(binding) is not prepared_type or button is None:
                self._binding = None
                self._state = _RecoverySourceInspectionReviewGUIEventState.FAILED
                return None
            self._binding = None
            self._state = _RecoverySourceInspectionReviewGUIEventState.DISPLAYING

        text = _RECOVERY_SOURCE_INSPECTION_REVIEW_WIDGET_TEXT[self._locale_id]
        try:
            button.config(state=tk.DISABLED)
            outcome = show_prepared_recovery_source_inspection_review(
                self._parent,
                binding,
            )
            if (
                binding.current_state is not bridge_state.COMPLETED
                or binding.outcome is not outcome
            ):
                raise bridge_error(
                    "source inspection main-GUI event outcome is not the binding result"
                )
        except bridge_error:
            with self._lock:
                self._state = _RecoverySourceInspectionReviewGUIEventState.FAILED
            messagebox.showerror("MOKOSH", text["failed"], parent=self._parent)
            return None
        except Exception:
            with self._lock:
                self._state = _RecoverySourceInspectionReviewGUIEventState.FAILED
            messagebox.showerror("MOKOSH", text["failed"], parent=self._parent)
            return None
        except BaseException:
            with self._lock:
                self._state = _RecoverySourceInspectionReviewGUIEventState.FAILED
            raise

        with self._lock:
            self._state = _RecoverySourceInspectionReviewGUIEventState.COMPLETED
        messagebox.showinfo("MOKOSH", text["completed"], parent=self._parent)
        return outcome


def _wire_prepared_recovery_source_inspection_review_widget(
    parent,
    container,
    prepared_binding: "PreparedMainGUIRecoverySourceInspectionReviewBinding",
):
    """Create the conditional Stage 2.41 banner and one-shot button."""

    event = _PreparedRecoverySourceInspectionReviewGUIEvent(
        parent,
        prepared_binding,
    )
    text = _RECOVERY_SOURCE_INSPECTION_REVIEW_WIDGET_TEXT[
        prepared_binding.locale.value
    ]
    banner = tk.Label(
        container,
        text=text["banner"],
        font=("TkDefaultFont", 10, "bold"),
        fg="#184d47",
        bg="#d9f2ee",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=7,
    )
    banner.pack(fill="x", padx=5, pady=(0, 5))
    button = tk.Button(
        container,
        text=text["button"],
        width=38,
        font=("TkDefaultFont", 11, "bold"),
        command=event,
    )
    event.attach_button(button)
    button.pack(fill="x", padx=5, pady=(0, 7))
    return banner, button, event


def run_script(script_name: str):
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    if not os.path.exists(script_path):
        messagebox.showerror("Error", f"Script not found:\n{script_path}")
        return
    try:
        subprocess.Popen([sys.executable, script_path])
    except Exception as e:
        messagebox.showerror("Error", f"Cannot start {script_name}:\n{e}")


def ensure_auth(entry_pwd, entry_nick) -> tuple[bool, str, str]:
    pwd = entry_pwd.get()
    nick = entry_nick.get().strip()
    if not pwd or not nick:
        messagebox.showerror(T("title"), T("err_pwd_empty"))
        return False, "", ""
    return True, pwd, nick


def ensure_login(entry_pwd, entry_nick) -> tuple[bool, str, str]:
    # The historical seed store is loaded only inside the explicit technical
    # maintenance harness.  Normal profile startup never imports or reads it.
    from seed_manager import load_seed_with_creds

    ok, pwd, nick = ensure_auth(entry_pwd, entry_nick)
    if not ok:
        return False, "", ""
    if not load_seed_with_creds(pwd, nick):
        messagebox.showerror(T("title"), "Invalid password or nickname.")
        return False, "", ""
    return True, pwd, nick

def do_login(entry_pwd, entry_nick):
    global logged_in
    ok, pwd, nick = ensure_login(entry_pwd, entry_nick)
    if ok:
        logged_in = True
        messagebox.showinfo(T("title"), "Login successful!")
    # При грешка ensure_login вече показва съобщение


def choose_language(lang_var, root, widgets):
    global current_lang
    lang = lang_var.get()
    if lang in ("en", "bg"):
        current_lang = lang
    else:
        current_lang = "en"
    root.title(T("title"))
    widgets["lang_label"].config(text=T("lang_label"))
    widgets["vault_title"].config(text=T("vault_label"))
    widgets["btn_choose_vault"].config(text=T("btn_choose_vault"))
    widgets["pwd_title"].config(text=T("pwd_label"))
    widgets["nick_title"].config(text=T("nick_label"))
    widgets["btn_encrypt_main"].config(text=T("btn_encrypt_main"))
    widgets["btn_decrypt_main"].config(text=T("btn_decrypt_main"))
    widgets["btn_clean_main"].config(text=T("btn_clean_main"))
    widgets["btn_bottom_contacts"].config(text=T("btn_bottom_contacts"))
    widgets["btn_bottom_contact_crypto"].config(text=T("btn_bottom_contact_crypto"))
    widgets["btn_bottom_master"].config(text=T("btn_bottom_master"))
    widgets["safety_banner"].config(text=T("safety_banner"))
    if "recovery_entry_banner" in widgets:
        widgets["recovery_entry_banner"].config(text=T("recovery_entry_banner"))
        widgets["btn_recovery_entry"].config(text=T("btn_recovery_entry"))
    if "recovery_transition_banner" in widgets:
        widgets["recovery_transition_banner"].config(
            text=T("recovery_transition_banner")
        )
        widgets["btn_recovery_transition"].config(
            text=T("btn_recovery_transition")
        )
    if "recovery_source_selection_banner" in widgets:
        event = widgets["recovery_source_selection_event"]
        if event.bound_locale_id is None:
            locale_id = "bg-BG" if current_lang == "bg" else "en-GB"
            text = _RECOVERY_SOURCE_SELECTION_WIDGET_TEXT[locale_id]
            widgets["recovery_source_selection_banner"].config(
                text=text["banner"]
            )
            widgets["btn_recovery_source_selection"].config(
                text=text["button"]
            )
    if "recovery_source_inspection_request_banner" in widgets:
        event = widgets["recovery_source_inspection_request_event"]
        if event.bound_locale_id is None:
            locale_id = "bg-BG" if current_lang == "bg" else "en-GB"
            text = _RECOVERY_SOURCE_INSPECTION_REQUEST_WIDGET_TEXT[locale_id]
            widgets["recovery_source_inspection_request_banner"].config(
                text=text["banner"]
            )
            widgets["btn_recovery_source_inspection_request"].config(
                text=text["button"]
            )
    if "recovery_source_inspection_preparation_request_banner" in widgets:
        event = widgets["recovery_source_inspection_preparation_request_event"]
        if event.bound_locale_id is None:
            locale_id = "bg-BG" if current_lang == "bg" else "en-GB"
            text = _RECOVERY_SOURCE_INSPECTION_PREPARATION_REQUEST_WIDGET_TEXT[
                locale_id
            ]
            widgets[
                "recovery_source_inspection_preparation_request_banner"
            ].config(text=text["banner"])
            widgets[
                "btn_recovery_source_inspection_preparation_request"
            ].config(text=text["button"])


def choose_vault(lbl_vault):
    global vault_path
    path = filedialog.askdirectory(title=T("btn_choose_vault"), initialdir=vault_path)
    if path:
        vault_path = path
        lbl_vault.config(text=vault_path)


def toggle_entry_show(entry):
    if entry.cget("show") == "":
        entry.config(show="*")
    else:
        entry.config(show="")


def encrypt_single_file(entry_pwd, entry_nick):
    ok, pwd, nick = ensure_login(entry_pwd, entry_nick)

    if not ok:
        return
    file_path = filedialog.askopenfilename(
        title=T("btn_enc_file"),
        initialdir=vault_path,
        filetypes=[("All files", "*.*")]
    )
    if not file_path:
        messagebox.showerror(T("title"), T("err_no_file"))
        return
    try:
        out_path = encrypt_file(
            file_path,
            None,
            pwd,
            meta={"mode": "single", "nick": nick},
            nickname=nick
        )
        messagebox.showinfo(T("title"), T("info_enc_ok").format(out_path))
    except Exception as e:
        messagebox.showerror(T("title"), T("err_enc").format(e))


def decrypt_single_file(entry_pwd, entry_nick):
    ok, pwd, nick = ensure_login(entry_pwd, entry_nick)

    if not ok:
        return
    file_path = filedialog.askopenfilename(
        title=T("btn_dec_file"),
        initialdir=vault_path,
        filetypes=[("MOK files", "*.mok"), ("All files", "*.*")]
    )
    if not file_path:
        messagebox.showerror(T("title"), T("err_no_file"))
        return
    try:
        out_path = decrypt_file(file_path, None, pwd, nickname=nick)
        messagebox.showinfo(T("title"), T("info_dec_ok").format(out_path))
    except Exception as e:
        messagebox.showerror(T("title"), T("err_dec").format(e))


def encrypt_vault(entry_pwd, entry_nick):
    global vault_path
    ok, pwd, nick = ensure_login(entry_pwd, entry_nick)

    if not ok:
        return
    if not vault_path or not os.path.isdir(vault_path):
        messagebox.showerror(T("title"), T("err_vault_not_dir").format(vault_path))
        return

    confirm = simpledialog.askstring(T("title"), T("warn_vault_enc"))
    if confirm is None:
        return
    if not (confirm == T("warn_confirm_yes") or confirm == T("warn_confirm_da")):
        messagebox.showinfo(T("title"), T("warn_cancel"))
        return

    encrypted = 0
    errors = 0
    for root_dir, dirs, files in os.walk(vault_path):
        for name in files:
            in_path = os.path.join(root_dir, name)
            if in_path.endswith(".mok"):
                continue
            try:
                encrypt_file(in_path, None, pwd, meta={"mode": "vault", "nick": nick}, nickname=nick)
                encrypted += 1
            except Exception:
                errors += 1

    messagebox.showinfo(T("title"), T("vault_enc_done").format(encrypted, errors))


def decrypt_vault(entry_pwd, entry_nick):
    global vault_path
    ok, pwd, nick = ensure_login(entry_pwd, entry_nick)

    if not ok:
        return
    if not vault_path or not os.path.isdir(vault_path):
        messagebox.showerror(T("title"), T("err_vault_not_dir").format(vault_path))
        return

    decrypted = 0
    errors = 0
    for root_dir, dirs, files in os.walk(vault_path):
        for name in files:
            if not name.endswith(".mok"):
                continue
            in_path = os.path.join(root_dir, name)
            try:
                decrypt_file(in_path, None, pwd, nickname=nick)
                decrypted += 1
            except Exception:
                errors += 1

    messagebox.showinfo(T("title"), T("vault_dec_done").format(decrypted, errors))


def clean_all_in_vault(entry_pwd, entry_nick):
    global vault_path
    ok, _, _ = ensure_login(entry_pwd, entry_nick)

    if not ok:
        return
    if not vault_path or not os.path.isdir(vault_path):
        messagebox.showerror(T("title"), T("err_vault_not_dir").format(vault_path))
        return

    confirm = simpledialog.askstring(T("title"), T("warn_clean_all"))
    if confirm is None:
        return
    if not (confirm == T("warn_confirm_yes") or confirm == T("warn_confirm_da")):
        messagebox.showinfo(T("title"), T("warn_cancel"))
        return

    deleted = 0
    for root_dir, dirs, files in os.walk(vault_path):
        for name in files:
            full_path = os.path.join(root_dir, name)
            if name.endswith("_dec"):
                try:
                    os.remove(full_path)
                    deleted += 1
                except Exception:
                    pass
                continue
            if name.endswith(".mok"):
                continue
            mok_path = full_path + ".mok"
            if os.path.exists(mok_path):
                try:
                    os.remove(full_path)
                    deleted += 1
                except Exception:
                    pass

    messagebox.showinfo(T("title"), T("info_clean_all").format(deleted))


def clean_one_file(entry_pwd, entry_nick):
    global vault_path
    ok, _, _ = ensure_login(entry_pwd, entry_nick)

    if not ok:
        return
    if not vault_path or not os.path.isdir(vault_path):
        messagebox.showerror(T("title"), T("err_vault_not_dir").format(vault_path))
        return

    filepath = filedialog.askopenfilename(
        title=T("warn_clean_one_title"),
        initialdir=vault_path,
        filetypes=[("All files", "*.*")]
    )
    if not filepath:
        return

    name = os.path.basename(filepath)
    if name.endswith(".mok"):
        stem = filepath[:-4]
    elif name.endswith("_dec"):
        stem = filepath[:-4]
    else:
        stem = filepath

    orig_path = stem
    dec_path = stem + "_dec"
    to_delete = []

    if os.path.isfile(orig_path) and not orig_path.endswith(".mok"):
        to_delete.append(orig_path)
    if os.path.isfile(dec_path):
        to_delete.append(dec_path)

    if not to_delete:
        messagebox.showinfo(T("title"), T("warn_clean_one_none"))
        return

    deleted_names = []
    for p in to_delete:
        try:
            os.remove(p)
            deleted_names.append(os.path.basename(p))
        except Exception:
            pass

    messagebox.showinfo(T("title"), T("info_clean_one").format("\n".join(deleted_names)))


def open_encrypt_dialog(root, entry_pwd, entry_nick):
    win = tk.Toplevel(root)
    win.title(T("btn_encrypt_main"))
    win.geometry("360x200")
    win.transient(root)
    win.grab_set()

    font_btn = ("TkDefaultFont", 11, "bold")

    btn_file = tk.Button(win, text=T("btn_enc_file"), width=26, font=font_btn,
                         command=lambda: (win.destroy(), encrypt_single_file(entry_pwd, entry_nick)))
    btn_file.pack(pady=8, padx=10)

    btn_vault = tk.Button(win, text=T("btn_enc_vault"), width=26, font=font_btn,
                          command=lambda: (win.destroy(), encrypt_vault(entry_pwd, entry_nick)))
    btn_vault.pack(pady=8, padx=10)


def open_decrypt_dialog(root, entry_pwd, entry_nick):
    win = tk.Toplevel(root)
    win.title(T("btn_decrypt_main"))
    win.geometry("360x200")
    win.transient(root)
    win.grab_set()

    font_btn = ("TkDefaultFont", 11, "bold")

    btn_file = tk.Button(win, text=T("btn_dec_file"), width=26, font=font_btn,
                         command=lambda: (win.destroy(), decrypt_single_file(entry_pwd, entry_nick)))
    btn_file.pack(pady=8, padx=10)

    btn_vault = tk.Button(win, text=T("btn_dec_vault"), width=26, font=font_btn,
                          command=lambda: (win.destroy(), decrypt_vault(entry_pwd, entry_nick)))
    btn_vault.pack(pady=8, padx=10)


def open_clean_dialog(root, entry_pwd, entry_nick):
    win = tk.Toplevel(root)
    win.title(T("btn_clean_main"))
    win.geometry("380x200")
    win.transient(root)
    win.grab_set()

    font_btn = ("TkDefaultFont", 11, "bold")

    btn_one = tk.Button(win, text=T("btn_clean_one"), width=28, font=font_btn,
                        command=lambda: (win.destroy(), clean_one_file(entry_pwd, entry_nick)))
    btn_one.pack(pady=8, padx=10)

    btn_all = tk.Button(win, text=T("btn_clean_all"), width=28, font=font_btn,
                        command=lambda: (win.destroy(), clean_all_in_vault(entry_pwd, entry_nick)))
    btn_all.pack(pady=8, padx=10)


def _normal_main_scroll_units(event) -> int:
    """Normalize platform wheel events without activating a GUI control."""

    number = getattr(event, "num", None)
    if number == 4:
        return -1
    if number == 5:
        return 1
    delta = getattr(event, "delta", 0)
    if type(delta) not in (int, float) or delta == 0:
        return 0
    return -1 if delta > 0 else 1


def _reveal_normal_main_control(canvas, content, control) -> None:
    """Vertically reveal one focused normal-GUI control inside the viewport."""

    content_height = max(1, int(content.winfo_reqheight()))
    viewport_height = max(1, int(canvas.winfo_height()))
    control_top = int(control.winfo_rooty()) - int(content.winfo_rooty())
    control_bottom = control_top + max(1, int(control.winfo_height()))
    visible_top = float(canvas.canvasy(0))
    visible_bottom = visible_top + viewport_height
    target = None
    if control_top < visible_top:
        target = control_top
    elif control_bottom > visible_bottom:
        target = control_bottom - viewport_height
    if target is not None:
        maximum = max(0, content_height - viewport_height)
        canvas.yview_moveto(max(0, min(maximum, target)) / content_height)


def _create_normal_main_scroll_viewport(root):
    """Create the bounded adaptive viewport used only by normal startup."""

    body = tk.Frame(root)
    body.pack(fill="both", expand=True)
    canvas = tk.Canvas(body, highlightthickness=0, takefocus=True)
    scrollbar = tk.Scrollbar(
        body,
        orient="vertical",
        command=canvas.yview,
        takefocus=True,
    )
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    canvas.configure(yscrollcommand=scrollbar.set)
    content = tk.Frame(canvas)
    content_window = canvas.create_window((0, 0), window=content, anchor="nw")

    content.bind(
        "<Configure>",
        lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
    )
    canvas.bind(
        "<Configure>",
        lambda event: canvas.itemconfigure(content_window, width=event.width),
    )

    def scroll_wheel(event):
        units = _normal_main_scroll_units(event)
        if units:
            canvas.yview_scroll(units, "units")

    root.bind("<MouseWheel>", scroll_wheel)
    root.bind("<Button-4>", scroll_wheel)
    root.bind("<Button-5>", scroll_wheel)
    canvas.bind("<Prior>", lambda _event: canvas.yview_scroll(-1, "pages"))
    canvas.bind("<Next>", lambda _event: canvas.yview_scroll(1, "pages"))
    canvas.bind("<Home>", lambda _event: canvas.yview_moveto(0.0))
    canvas.bind("<End>", lambda _event: canvas.yview_moveto(1.0))
    return content, canvas


def _bind_normal_main_focus_reveal(root, canvas, content, controls) -> None:
    """Reveal each control after ordinary forward or reverse focus traversal."""

    for control in controls:
        control.bind(
            "<FocusIn>",
            lambda _event, item=control: root.after_idle(
                _reveal_normal_main_control,
                canvas,
                content,
                item,
            ),
            add="+",
        )


def main(
    prepared_recovery_review_binding: "PreparedMainGUIRecoveryReviewBinding | None" = None,
    *,
    prepared_recovery_source_inspection_review_binding: (
        "PreparedMainGUIRecoverySourceInspectionReviewBinding | None"
    ) = None,
):
    global current_lang, vault_path

    if (
        prepared_recovery_review_binding is not None
        and prepared_recovery_source_inspection_review_binding is not None
    ):
        raise TypeError("only one prepared recovery review binding is permitted")

    if prepared_recovery_review_binding is not None:
        prepared_type, bridge_state, _ = _recovery_review_bridge_contract()
        if (
            type(prepared_recovery_review_binding) is not prepared_type
            or prepared_recovery_review_binding.current_state
            is not bridge_state.READY
        ):
            raise TypeError("fresh prepared recovery review binding is required")
        current_lang = {
            "bg-BG": "bg",
            "en-GB": "en",
        }[prepared_recovery_review_binding.locale.value]
    elif prepared_recovery_source_inspection_review_binding is not None:
        prepared_type, bridge_state, _ = (
            _recovery_source_inspection_review_bridge_contract()
        )
        if (
            type(prepared_recovery_source_inspection_review_binding)
            is not prepared_type
            or prepared_recovery_source_inspection_review_binding.current_state
            is not bridge_state.READY
        ):
            raise TypeError(
                "fresh prepared recovery source inspection review binding is required"
            )
        current_lang = {
            "bg-BG": "bg",
            "en-GB": "en",
        }[prepared_recovery_source_inspection_review_binding.locale.value]

    conditional_recovery_review = (
        prepared_recovery_review_binding is not None
        or prepared_recovery_source_inspection_review_binding is not None
    )

    ensure_private_data_dir()
    root = tk.Tk()
    root.title(T("title"))
    root.geometry("820x560" if conditional_recovery_review else "820x720")

    content_root = root
    normal_scroll_canvas = None
    if not conditional_recovery_review:
        content_root, normal_scroll_canvas = _create_normal_main_scroll_viewport(
            root
        )

    widgets = {}

    font_label = ("TkDefaultFont", 11)
    font_btn = ("TkDefaultFont", 12, "bold")

    safety_banner = tk.Label(
        content_root,
        text=T("safety_banner"),
        font=("TkDefaultFont", 10, "bold"),
        fg="#7a3e00",
        bg="#fff3cd",
        justify="left",
        anchor="w",
        wraplength=780,
        padx=10,
        pady=8,
    )
    safety_banner.pack(fill="x", padx=10, pady=(8, 3))
    widgets["safety_banner"] = safety_banner

    if prepared_recovery_source_inspection_review_binding is not None:
        source_inspection_review_frame = tk.Frame(root)
        source_inspection_review_frame.pack(pady=(2, 8), fill="x", padx=10)
        (
            source_inspection_review_banner,
            source_inspection_review_button,
            source_inspection_review_event,
        ) = _wire_prepared_recovery_source_inspection_review_widget(
            root,
            source_inspection_review_frame,
            prepared_recovery_source_inspection_review_binding,
        )
        widgets["recovery_source_inspection_review_banner"] = (
            source_inspection_review_banner
        )
        widgets["btn_recovery_source_inspection_review"] = (
            source_inspection_review_button
        )
        widgets["recovery_source_inspection_review_event"] = (
            source_inspection_review_event
        )

    if not conditional_recovery_review:
        recovery_entry_frame = tk.Frame(content_root)
        recovery_entry_frame.pack(pady=(3, 4), fill="x", padx=10)
        recovery_source_inspection_preparation_request_event = (
            _RecoverySourceInspectionPreparationRequestGUIEvent(root)
        )
        recovery_source_inspection_request_event = (
            _RecoverySourceInspectionRequestGUIEvent(
                root,
                recovery_source_inspection_preparation_request_event,
            )
        )
        recovery_source_selection_event = _RecoverySourceSelectionGUIEvent(
            root,
            recovery_source_inspection_request_event,
        )
        recovery_transition_event = _RecoveryEntryTransitionGUIEvent(
            root,
            recovery_source_selection_event,
        )
        recovery_entry_banner, recovery_entry_button, recovery_entry_event = (
            _wire_recovery_entry_request_widget(
                root,
                recovery_entry_frame,
                recovery_transition_event,
            )
        )
        (
            recovery_transition_banner,
            recovery_transition_button,
            recovery_transition_event,
        ) = _wire_recovery_entry_transition_widget(
            root,
            recovery_entry_frame,
            recovery_transition_event,
        )
        (
            recovery_source_selection_banner,
            recovery_source_selection_button,
            recovery_source_selection_event,
        ) = _wire_recovery_source_selection_widget(
            root,
            recovery_entry_frame,
            recovery_source_selection_event,
        )
        (
            recovery_source_inspection_request_banner,
            recovery_source_inspection_request_button,
            recovery_source_inspection_request_event,
        ) = _wire_recovery_source_inspection_request_widget(
            root,
            recovery_entry_frame,
            recovery_source_inspection_request_event,
        )
        (
            recovery_source_inspection_preparation_request_banner,
            recovery_source_inspection_preparation_request_button,
            recovery_source_inspection_preparation_request_event,
        ) = _wire_recovery_source_inspection_preparation_request_widget(
            root,
            recovery_entry_frame,
            recovery_source_inspection_preparation_request_event,
        )
        widgets["recovery_entry_banner"] = recovery_entry_banner
        widgets["btn_recovery_entry"] = recovery_entry_button
        widgets["recovery_entry_event"] = recovery_entry_event
        widgets["recovery_transition_banner"] = recovery_transition_banner
        widgets["btn_recovery_transition"] = recovery_transition_button
        widgets["recovery_transition_event"] = recovery_transition_event
        widgets["recovery_source_selection_banner"] = (
            recovery_source_selection_banner
        )
        widgets["btn_recovery_source_selection"] = recovery_source_selection_button
        widgets["recovery_source_selection_event"] = recovery_source_selection_event
        widgets["recovery_source_inspection_request_banner"] = (
            recovery_source_inspection_request_banner
        )
        widgets["btn_recovery_source_inspection_request"] = (
            recovery_source_inspection_request_button
        )
        widgets["recovery_source_inspection_request_event"] = (
            recovery_source_inspection_request_event
        )
        widgets["recovery_source_inspection_preparation_request_banner"] = (
            recovery_source_inspection_preparation_request_banner
        )
        widgets["btn_recovery_source_inspection_preparation_request"] = (
            recovery_source_inspection_preparation_request_button
        )
        widgets["recovery_source_inspection_preparation_request_event"] = (
            recovery_source_inspection_preparation_request_event
        )

    # Language selection
    top_frame = tk.Frame(content_root)
    top_frame.pack(pady=5, fill="x")

    lang_label = tk.Label(top_frame, text=T("lang_label"), font=font_label)
    lang_label.pack(side="left", padx=5)
    widgets["lang_label"] = lang_label

    lang_var = tk.StringVar(value=current_lang)

    def on_lang_change():
        choose_language(lang_var, root, widgets)

    rb_en = tk.Radiobutton(top_frame, text="EN", variable=lang_var, value="en", command=on_lang_change)
    rb_en.pack(side="left")
    rb_bg = tk.Radiobutton(top_frame, text="BG", variable=lang_var, value="bg", command=on_lang_change)
    rb_bg.pack(side="left")

    # Vault display / choose
    vault_frame = tk.Frame(content_root)
    vault_frame.pack(pady=5, fill="x")

    lbl_vault_title = tk.Label(vault_frame, text=T("vault_label"), font=font_label)
    lbl_vault_title.pack(side="left", padx=5)
    widgets["vault_title"] = lbl_vault_title

    lbl_vault = tk.Label(vault_frame, text=vault_path, anchor="w", font=font_label)
    lbl_vault.pack(side="left", padx=5, fill="x", expand=True)

    btn_choose_vault = tk.Button(vault_frame, text=T("btn_choose_vault"),
                                 font=font_btn,
                                 command=lambda: choose_vault(lbl_vault))
    btn_choose_vault.pack(side="right", padx=5)
    widgets["btn_choose_vault"] = btn_choose_vault

    # Password field
    pwd_frame = tk.Frame(content_root)
    pwd_frame.pack(pady=5, fill="x")

    lbl_pwd_title = tk.Label(pwd_frame, text=T("pwd_label"), font=font_label)
    lbl_pwd_title.pack(side="left", padx=5)
    widgets["pwd_title"] = lbl_pwd_title

    entry_pwd = tk.Entry(pwd_frame, show="*", width=24, font=("TkDefaultFont", 11))
    entry_pwd.pack(side="left", padx=5)

    btn_eye_pwd = tk.Button(pwd_frame, text="👁", width=3,
                            command=lambda: toggle_entry_show(entry_pwd))
    btn_eye_pwd.pack(side="left", padx=5)



    # Nickname field
    nick_frame = tk.Frame(content_root)
    nick_frame.pack(pady=5, fill="x")

    lbl_nick_title = tk.Label(nick_frame, text=T("nick_label"), font=font_label)
    lbl_nick_title.pack(side="left", padx=5)
    widgets["nick_title"] = lbl_nick_title

    entry_nick = tk.Entry(nick_frame, show="*", width=24, font=("TkDefaultFont", 11))
    entry_nick.pack(side="left", padx=5)

    btn_eye_nick = tk.Button(nick_frame, text="👁", width=3,
                             command=lambda: toggle_entry_show(entry_nick))
    btn_eye_nick.pack(side="left", padx=5)


    btn_login = tk.Button(pwd_frame, text=T("btn_login"), width=10, font=font_btn,
                          command=lambda: do_login(entry_pwd, entry_nick))
    btn_login.pack(side="left", padx=5)

    # Nickname field


    # Main action buttons (Encrypt / Decrypt / Clean)
    main_btn_frame = tk.Frame(content_root)
    main_btn_frame.pack(pady=25, fill="x", padx=10)

    btn_encrypt_main = tk.Button(
        main_btn_frame,
        text=T("btn_encrypt_main"),
        width=18,
        font=font_btn,
        command=lambda: open_encrypt_dialog(root, entry_pwd, entry_nick),
    )
    btn_encrypt_main.pack(side="left", expand=True, fill="x", padx=5)
    widgets["btn_encrypt_main"] = btn_encrypt_main
    if SAFETY_MODE:
        btn_encrypt_main.config(state=tk.DISABLED)

    btn_decrypt_main = tk.Button(
        main_btn_frame,
        text=T("btn_decrypt_main"),
        width=18,
        font=font_btn,
        command=lambda: open_decrypt_dialog(root, entry_pwd, entry_nick),
    )
    btn_decrypt_main.pack(side="left", expand=True, fill="x", padx=5)
    widgets["btn_decrypt_main"] = btn_decrypt_main

    btn_clean_main = tk.Button(
        main_btn_frame,
        text=T("btn_clean_main"),
        width=18,
        font=font_btn,
        command=lambda: open_clean_dialog(root, entry_pwd, entry_nick),
    )
    btn_clean_main.pack(side="left", expand=True, fill="x", padx=5)
    widgets["btn_clean_main"] = btn_clean_main
    if SAFETY_MODE:
        btn_clean_main.config(state=tk.DISABLED)

    # Bottom menu buttons for other modules
    bottom_frame = tk.Frame(content_root)
    bottom_frame.pack(pady=10, fill="x", padx=10)

    btn_contacts = tk.Button(
        bottom_frame,
        text=T("btn_bottom_contacts"),
        width=18,
        font=font_btn,
        command=lambda: run_script("contacts_gui.py"),
    )
    btn_contacts.pack(side="left", expand=True, fill="x", padx=5)
    widgets["btn_bottom_contacts"] = btn_contacts
    if SAFETY_MODE:
        btn_contacts.config(state=tk.DISABLED)

    btn_contact_crypto = tk.Button(
        bottom_frame,
        text=T("btn_bottom_contact_crypto"),
        width=18,
        font=font_btn,
        command=lambda: run_script("contact_crypto_gui.py"),
    )
    btn_contact_crypto.pack(side="left", expand=True, fill="x", padx=5)
    widgets["btn_bottom_contact_crypto"] = btn_contact_crypto
    if SAFETY_MODE:
        btn_contact_crypto.config(state=tk.DISABLED)

    btn_master = tk.Button(
        bottom_frame,
        text=T("btn_bottom_master"),
        width=18,
        font=font_btn,
        command=lambda: run_script("sandbox_gui.py"),
    )
    btn_master.pack(side="left", expand=True, fill="x", padx=5)
    widgets["btn_bottom_master"] = btn_master
    if SAFETY_MODE:
        btn_master.config(state=tk.DISABLED)

    if prepared_recovery_review_binding is not None:
        review_frame = tk.Frame(root)
        review_frame.pack(pady=(2, 8), fill="x", padx=10)
        review_banner, review_button, review_event = (
            _wire_prepared_recovery_review_widget(
                root,
                review_frame,
                prepared_recovery_review_binding,
            )
        )
        widgets["recovery_review_banner"] = review_banner
        widgets["btn_recovery_review"] = review_button
        widgets["recovery_review_event"] = review_event

    if conditional_recovery_review:
        # Both bounded conditional review entries are inspection-only. All
        # unrelated main-GUI inputs/actions are disabled for either session.
        for control in (
            rb_en,
            rb_bg,
            btn_choose_vault,
            entry_pwd,
            btn_eye_pwd,
            entry_nick,
            btn_eye_nick,
            btn_login,
            btn_encrypt_main,
            btn_decrypt_main,
            btn_clean_main,
            btn_contacts,
            btn_contact_crypto,
            btn_master,
        ):
            control.config(state=tk.DISABLED)

    if normal_scroll_canvas is not None:
        _bind_normal_main_focus_reveal(
            root,
            normal_scroll_canvas,
            content_root,
            (
                rb_en,
                rb_bg,
                btn_choose_vault,
                entry_pwd,
                btn_eye_pwd,
                entry_nick,
                btn_eye_nick,
                btn_login,
                btn_encrypt_main,
                btn_decrypt_main,
                btn_clean_main,
                btn_contacts,
                btn_contact_crypto,
                btn_master,
                recovery_entry_button,
                recovery_transition_button,
                recovery_source_selection_button,
                recovery_source_inspection_request_button,
                recovery_source_inspection_preparation_request_button,
            ),
        )
        root.after_idle(
            lambda: normal_scroll_canvas.configure(
                scrollregion=normal_scroll_canvas.bbox("all")
            )
        )

    root.mainloop()


if __name__ == "__main__":
    # Keep the launcher byte-exact while separating the normal profile window
    # from the historical recovery/evidence harness.  Existing harnesses call
    # main(...) directly; ordinary script startup reaches the protected profile.
    ensure_private_data_dir()
    if sys.argv[1:] == ["--maintenance"]:
        main()
    elif sys.argv[1:]:
        raise SystemExit("unsupported MOKOSH GUI option")
    else:
        from mokosh_profile_gui import main as profile_main

        profile_main()
