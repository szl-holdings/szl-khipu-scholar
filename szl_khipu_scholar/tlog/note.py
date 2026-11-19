# SPDX-License-Identifier: Apache-2.0
"""Signed notes (c2sp.org/signed-note), Ed25519 type 0x01 only.

    <text, ends in newline>
    <blank line>
    — <key name> <base64(key id[4] || signature)>

key id  = SHA-256(name || 0x0A || 0x01 || public key)[:4]
vkey    = name + "+" + hex(key id) + "+" + base64(0x01 || public key)

The text is only trustworthy after `open_note` returns: a note is rejected
unless at least one signature from a *known* key verifies, and a signature from
a known key that fails to verify rejects the whole note. Signatures from
unknown keys are ignored, as the spec requires.

Signing needs pynacl (the same optional dependency the receipt verifier uses).
Verifying needs it too: this module adds no new cryptographic dependency.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

ALG_ED25519 = 0x01
EM_DASH = "\u2014"
MAX_SIGNATURES = 64   # the spec requires accepting at least 16


class NoteError(ValueError):
    """The note is malformed, unsigned by a known key, or fails verification."""


def b64decode_canonical(text: str) -> bytes:
    """RFC 4648 base64 with padding; non-canonical encodings are rejected."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as e:
        raise NoteError("invalid base64") from e
    if base64.b64encode(raw).decode("ascii") != text:
        raise NoteError("non-canonical base64")
    return raw


def _check_name(name: str) -> None:
    if not name or "+" in name or any(c.isspace() for c in name):
        raise NoteError("key name must be non-empty with no spaces or plus signs")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise NoteError("key name contains a control character")


def key_id(name: str, public_key: bytes, alg: int = ALG_ED25519) -> bytes:
    return hashlib.sha256(name.encode("utf-8") + b"\n" + bytes([alg]) + public_key).digest()[:4]


def _verify_ed25519(public_key: bytes, message: bytes, sig: bytes) -> bool:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
    try:
        VerifyKey(public_key).verify(message, sig)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Verifier:
    name: str
    public_key: bytes

    def __post_init__(self) -> None:
        _check_name(self.name)
        if len(self.public_key) != 32:
            raise NoteError("Ed25519 public key must be 32 bytes")

    @property
    def key_id(self) -> bytes:
        return key_id(self.name, self.public_key)

    def vkey(self) -> str:
        blob = base64.b64encode(bytes([ALG_ED25519]) + self.public_key).decode("ascii")
        return f"{self.name}+{self.key_id.hex()}+{blob}"

    @classmethod
    def from_vkey(cls, vkey: str) -> "Verifier":
        # the name has no '+', but base64 may, so split at most twice
        parts = vkey.split("+", 2)
        if len(parts) != 3:
            raise NoteError("vkey must be name+hash+base64")
        name, hex_id, blob = parts
        raw = b64decode_canonical(blob)
        if len(raw) != 33 or raw[0] != ALG_ED25519:
            raise NoteError("unsupported vkey algorithm or key length")
        v = cls(name, raw[1:])
        if len(hex_id) != 8 or hex_id != hex_id.lower() or hex_id != v.key_id.hex():
            raise NoteError("vkey key id does not match its name and key")
        return v

    def verify(self, message: bytes, sig: bytes) -> bool:
        return _verify_ed25519(self.public_key, message, sig)


class Signer:
    """An Ed25519 note signer. The 32-byte seed is supplied by the caller and is
    never written anywhere by this module."""

    def __init__(self, name: str, seed: bytes):
        from nacl.signing import SigningKey
        _check_name(name)
        if len(seed) != 32:
            raise NoteError("Ed25519 seed must be 32 bytes")
        self._sk = SigningKey(seed)
        self.verifier = Verifier(name, bytes(self._sk.verify_key))

    @classmethod
    def generate(cls, name: str) -> "Signer":
        import os
        return cls(name, os.urandom(32))

    @property
    def name(self) -> str:
        return self.verifier.name

    def sign(self, text: bytes) -> bytes:
        return self.verifier.key_id + self._sk.sign(text).signature


def _check_text(text: str) -> None:
    if not text.endswith("\n"):
        raise NoteError("note text must end in a newline")
    for c in text:
        if c != "\n" and (ord(c) < 0x20 or ord(c) == 0x7F):
            raise NoteError("note contains a control character")


def sign_note(text: str, signers: Sequence[Signer]) -> bytes:
    """Return text + blank line + one signature line per signer."""
    _check_text(text)
    if not signers:
        raise NoteError("at least one signer is required")
    data = text.encode("utf-8")
    seen = set()
    lines = []
    for s in signers:
        ident = (s.name, s.verifier.key_id)
        if ident in seen:
            raise NoteError("duplicate signer (same name and key id)")
        seen.add(ident)
        sig = base64.b64encode(s.sign(data)).decode("ascii")
        lines.append(f"{EM_DASH} {s.name} {sig}\n")
    return data + b"\n" + "".join(lines).encode("utf-8")


@dataclass(frozen=True)
class OpenedNote:
    text: str
    verified: Tuple[Verifier, ...]       # known keys whose signature verified
    unknown: Tuple[Tuple[str, bytes], ...]  # (name, key id) of ignored signatures


def open_note(msg: bytes, known: Iterable[Verifier]) -> OpenedNote:
    """Verify a signed note against pinned verifiers and return its text."""
    try:
        s = msg.decode("utf-8")
    except UnicodeDecodeError as e:
        raise NoteError("note is not valid UTF-8") from e
    cut = s.rfind("\n\n")
    if cut < 0:
        raise NoteError("no blank line before the signatures")
    text, sigblock = s[:cut + 1], s[cut + 2:]
    _check_text(text)
    if not sigblock.endswith("\n"):
        raise NoteError("signature block must end in a newline")
    if any(ord(c) < 0x20 and c != "\n" for c in sigblock):
        raise NoteError("note contains a control character")
    sig_lines = sigblock[:-1].split("\n")
    if not sigblock[:-1] or len(sig_lines) > MAX_SIGNATURES:
        raise NoteError("no signatures, or too many")
    data = text.encode("utf-8")
    pinned = {(v.name, v.key_id): v for v in known}
    verified: List[Verifier] = []
    unknown: List[Tuple[str, bytes]] = []
    seen = set()
    for line in sig_lines:
        prefix = EM_DASH + " "
        if not line.startswith(prefix):
            raise NoteError("malformed signature line")
        fields = line[len(prefix):].split(" ")
        if len(fields) != 2:
            raise NoteError("malformed signature line")
        name, b64 = fields
        _check_name(name)
        raw = b64decode_canonical(b64)
        if len(raw) < 5:
            raise NoteError("signature too short")
        kid, sig = raw[:4], raw[4:]
        if (name, kid) in seen:
            raise NoteError("duplicate signature for the same key name and id")
        seen.add((name, kid))
        v = pinned.get((name, kid))
        if v is None:
            unknown.append((name, kid))
            continue
        if not v.verify(data, sig):
            raise NoteError(f"signature from known key {name!r} does not verify")
        verified.append(v)
    if not verified:
        raise NoteError("no signature from a known key")
    return OpenedNote(text=text, verified=tuple(verified), unknown=tuple(unknown))
