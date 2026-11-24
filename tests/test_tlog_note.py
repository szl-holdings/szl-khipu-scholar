# SPDX-License-Identifier: Apache-2.0
"""Signed notes and checkpoints (c2sp.org/signed-note, c2sp.org/tlog-checkpoint).
Keys are generated at test time and never written anywhere."""
import base64

import pytest

pytest.importorskip("nacl.signing")

from szl_khipu_scholar.tlog import note as N  # noqa: E402
from szl_khipu_scholar.tlog.checkpoint import (Checkpoint, CheckpointError,  # noqa: E402
                                               open_checkpoint, sign_checkpoint)

# Published example in the signed-note spec: an independent known answer.
SPEC_VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
SPEC_NOTE = ("This is an example message.\n\n\u2014 example.com/foo "
             "Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n")
ORIGIN = "example.com/receipts"
ROOT = bytes(range(32))


def test_spec_example_note_verifies():
    v = N.Verifier.from_vkey(SPEC_VKEY)
    assert v.vkey() == SPEC_VKEY and v.key_id.hex() == "530d903a"
    opened = N.open_note(SPEC_NOTE.encode(), [v])
    assert opened.text == "This is an example message.\n"


def test_spec_example_tamper_and_wrong_key_rejected():
    v = N.Verifier.from_vkey(SPEC_VKEY)
    with pytest.raises(N.NoteError):
        N.open_note(SPEC_NOTE.replace("example message", "example massage").encode(), [v])
    other = N.Signer.generate("example.com/foo")
    with pytest.raises(N.NoteError, match="no signature from a known key"):
        N.open_note(SPEC_NOTE.encode(), [other.verifier])


def test_vkey_must_be_self_consistent():
    s = N.Signer.generate("log.example/x")
    while s.verifier.key_id.hex().isdigit():    # ~2% of key ids have no a-f: upper() would not change them
        s = N.Signer.generate("log.example/x")
    assert N.Verifier.from_vkey(s.verifier.vkey()) == s.verifier
    name, kid, blob = s.verifier.vkey().split("+", 2)
    for bad in (f"{name}+00000000+{blob}", f"{name}+{kid.upper()}+{blob}", f"{name}+{kid}",
                f"{name}+{kid}+{blob}+x", f"{name}+{kid}+" + base64.b64encode(b"\x02" + bytes(32)).decode()):
        with pytest.raises(N.NoteError):
            N.Verifier.from_vkey(bad)


def test_vkey_roundtrip_when_base64_contains_plus():
    for _ in range(2000):
        s = N.Signer.generate("plus.example/log")
        if "+" in s.verifier.vkey().split("+", 2)[2]:
            assert N.Verifier.from_vkey(s.verifier.vkey()) == s.verifier
            return
    pytest.fail("no key with '+' in its base64 found in 2000 tries")


def test_roundtrip_and_key_id_formula():
    import hashlib
    s = N.Signer.generate(ORIGIN)
    assert s.verifier.key_id == hashlib.sha256(ORIGIN.encode() + b"\n\x01" + s.verifier.public_key).digest()[:4]
    msg = N.sign_note("hello\nworld\n", [s])
    assert msg.startswith(b"hello\nworld\n\n\xe2\x80\x94 " + ORIGIN.encode() + b" ")
    assert N.open_note(msg, [s.verifier]).text == "hello\nworld\n"


def test_unknown_signatures_are_ignored_but_known_failures_reject():
    a, b = N.Signer.generate("a.example/log"), N.Signer.generate("b.example/wit")
    msg = N.sign_note("t\n", [a, b])
    opened = N.open_note(msg, [a.verifier])
    assert [v.name for v in opened.verified] == ["a.example/log"] and len(opened.unknown) == 1
    # same name, different key: ignored (and so nothing known verified)
    impostor = N.Signer.generate("a.example/log")
    with pytest.raises(N.NoteError):
        N.open_note(msg, [impostor.verifier])
    # known key, bad signature -> reject the whole note even though b verifies
    lines = msg.decode().split("\n")
    sig = bytearray(base64.b64decode(lines[-3].split(" ")[2]))
    sig[10] ^= 1
    lines[-3] = f"\u2014 a.example/log {base64.b64encode(bytes(sig)).decode()}"
    with pytest.raises(N.NoteError, match="does not verify"):
        N.open_note("\n".join(lines).encode(), [a.verifier, b.verifier])


@pytest.mark.parametrize("mutate", [
    lambda m: m.replace(b"\n\n", b"\n", 1),                          # no blank line
    lambda m: m.rstrip(b"\n"),                                       # no final newline
    lambda m: m.replace(b"\xe2\x80\x94 ", b"- "),                    # ASCII dash
    lambda m: m + b"\xe2\x80\x94 x.example/k !!!notbase64\n",        # bad base64
    lambda m: m.replace(b"t\n", b"t\x01\n", 1),                      # control char
    lambda m: m + b"\xff",                                           # invalid UTF-8
    lambda m: m.split(b"\n\n")[0] + b"\n\n",                         # no signatures
])
def test_malformed_notes_rejected(mutate):
    s = N.Signer.generate("k.example/log")
    msg = N.sign_note("t\n", [s])
    with pytest.raises(N.NoteError):
        N.open_note(mutate(msg), [s.verifier])


def test_non_canonical_base64_and_duplicates_rejected():
    s = N.Signer.generate("k.example/log")
    msg = N.sign_note("t\n", [s]).decode()
    sig = msg.rstrip("\n").split(" ")[-1]
    assert sig.endswith("=")
    # flip the unused low bits of the last base64 char before '=' padding
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = sig.rstrip("=")[-1]
    alt = alphabet[alphabet.index(last) ^ 1]
    forged = msg.replace(sig, sig.rstrip("=")[:-1] + alt + "=" * (len(sig) - len(sig.rstrip("="))))
    with pytest.raises(N.NoteError, match="non-canonical|does not verify"):
        N.open_note(forged.encode(), [s.verifier])
    line = msg.split("\n")[-2]
    with pytest.raises(N.NoteError, match="duplicate"):
        N.open_note((msg + line + "\n").encode(), [s.verifier])


def test_bad_names_and_texts_cannot_be_signed():
    for name in ("", "has space", "has+plus", "tab\tname"):
        with pytest.raises(N.NoteError):
            N.Signer.generate(name)
    s = N.Signer.generate("k.example/log")
    for text in ("no newline", "ctl\x07\n"):
        with pytest.raises(N.NoteError):
            N.sign_note(text, [s])
    with pytest.raises(N.NoteError):
        N.sign_note("t\n", [s, s])


def test_checkpoint_roundtrip_and_exact_text():
    cp = Checkpoint(ORIGIN, 20852163, ROOT)
    assert cp.text() == f"{ORIGIN}\n20852163\n{base64.b64encode(ROOT).decode()}\n"
    assert Checkpoint.parse(cp.text()) == cp
    ext = Checkpoint(ORIGIN, 0, ROOT, ("ext one", "ext two"))
    assert Checkpoint.parse(ext.text()) == ext


@pytest.mark.parametrize("text", [
    "o\n1\n",                                           # two lines
    f"o\n01\n{base64.b64encode(ROOT).decode()}\n",      # zero-prefixed size
    f"o\n-1\n{base64.b64encode(ROOT).decode()}\n",      # sign
    f"o\n1\n{base64.b64encode(ROOT[:31]).decode()}\n",  # short root
    "o\n1\nnot-base64!\n",
    f"o\n1\n{base64.b64encode(ROOT).decode()}\n\n",     # empty extension line
    f"o\n1\n{base64.b64encode(ROOT).decode()}",         # no trailing newline
    f"\n1\n{base64.b64encode(ROOT).decode()}\n",        # empty origin
    f"o\n\u0661\n{base64.b64encode(ROOT).decode()}\n",  # non-ASCII digit
])
def test_malformed_checkpoint_text_rejected(text):
    with pytest.raises(CheckpointError):
        Checkpoint.parse(text)


def test_open_checkpoint_pins_origin_and_log_key():
    log, wit = N.Signer.generate(ORIGIN), N.Signer.generate("witness.example/w")
    msg = sign_checkpoint(Checkpoint(ORIGIN, 5, ROOT), [log, wit])
    cp, opened = open_checkpoint(msg, [log.verifier, wit.verifier], origin=ORIGIN)
    assert (cp.size, cp.root) == (5, ROOT) and len(opened.verified) == 2
    with pytest.raises(CheckpointError, match="different origin"):
        open_checkpoint(msg, [log.verifier], origin="other.example/log")
    # a witness signature alone is not the log's own signature
    only_wit = sign_checkpoint(Checkpoint(ORIGIN, 5, ROOT), [wit])
    with pytest.raises(CheckpointError, match="log's own key"):
        open_checkpoint(only_wit, [wit.verifier], origin=ORIGIN)


def test_default_open_checkpoint_requires_the_origins_own_key():
    """Without `origin`, a checkpoint is still accepted only when the key named
    by its own origin line signed it. Another log's key or a witness key that
    the client also trusts is a cosigner, never the log signature."""
    a, b = N.Signer.generate("example.com/logA"), N.Signer.generate("example.com/logB")
    wit = N.Signer.generate("witness.example/w1")
    known = [a.verifier, b.verifier, wit.verifier]
    cp_a = Checkpoint("example.com/logA", 1, ROOT)
    for signers in ([b], [wit], [b, wit]):
        with pytest.raises(CheckpointError, match="log's own key"):
            open_checkpoint(sign_checkpoint(cp_a, signers), known)
    cp, opened = open_checkpoint(sign_checkpoint(cp_a, [a, wit]), known)
    assert cp == cp_a
    assert [v.name for v in opened.verified] == ["example.com/logA", "witness.example/w1"]


def test_size_zero_checkpoint_must_carry_the_empty_tree_root():
    import hashlib
    log = N.Signer.generate(ORIGIN)
    empty = hashlib.sha256(b"").digest()
    cp, _ = open_checkpoint(sign_checkpoint(Checkpoint(ORIGIN, 0, empty), [log]),
                            [log.verifier], origin=ORIGIN)
    assert (cp.size, cp.root) == (0, empty)
    with pytest.raises(CheckpointError, match="empty-tree root"):
        open_checkpoint(sign_checkpoint(Checkpoint(ORIGIN, 0, ROOT), [log]),
                        [log.verifier], origin=ORIGIN)


def test_del_is_not_a_control_character_in_signed_notes():
    """c2sp.org/signed-note: control characters are those below U+0020 (newline
    allowed); key names exclude only Unicode spaces and '+'. U+007F is neither."""
    s = N.Signer.generate("del\x7fname.example/log")
    assert N.Verifier.from_vkey(s.verifier.vkey()) == s.verifier
    msg = N.sign_note("hello\x7fworld\n", [s])
    assert N.open_note(msg, [s.verifier]).text == "hello\x7fworld\n"
    known = N.Signer.generate(ORIGIN)
    with_unknown = N.sign_note("t\n", [known, s])            # an unknown line whose name has U+007F
    opened = N.open_note(with_unknown, [known.verifier])
    assert [v.name for v in opened.verified] == [ORIGIN] and len(opened.unknown) == 1
    for bad in ("tab\x09name", "nul\x00name", "esc\x1bname"):
        with pytest.raises(N.NoteError):
            N.Signer.generate(bad)


def test_repeated_unknown_key_lines_are_ignored_by_notes_but_not_by_checkpoints():
    log, wit = N.Signer.generate(ORIGIN), N.Signer.generate("witness.example/w")
    msg = sign_checkpoint(Checkpoint(ORIGIN, 5, ROOT), [log, wit]).decode()
    wit_line = msg.rstrip("\n").split("\n")[-1] + "\n"
    doubled = (msg + wit_line).encode()
    opened = N.open_note(doubled, [log.verifier])            # signed-note: unknown keys are ignored
    assert [v.name for v in opened.verified] == [ORIGIN] and len(opened.unknown) == 2
    with pytest.raises(CheckpointError, match="same key name and id"):
        open_checkpoint(doubled, [log.verifier], origin=ORIGIN)   # tlog-checkpoint: MUST NOT repeat
    with pytest.raises(N.NoteError, match="duplicate"):
        N.open_note(doubled, [log.verifier, wit.verifier])    # a repeated known key still rejects


def test_tree_size_must_fit_in_a_uint64():
    """Go's formats/log parses the size as a uint64. A size that does not fit,
    or one too long for int() to convert, is a CheckpointError, not a crash."""
    root64 = base64.b64encode(ROOT).decode()
    assert Checkpoint.parse(f"o\n18446744073709551615\n{root64}\n").size == 2**64 - 1
    for size in ("18446744073709551616", "9" * 21, "1" + "0" * 5000):
        with pytest.raises(CheckpointError, match="uint64"):
            Checkpoint.parse(f"o\n{size}\n{root64}\n")
    with pytest.raises(CheckpointError, match="uint64"):
        Checkpoint("o", 2**64, ROOT)
    log = N.Signer.generate(ORIGIN)
    huge = N.sign_note(f"{ORIGIN}\n1{'0' * 5000}\n{root64}\n", [log])
    with pytest.raises(CheckpointError, match="uint64"):
        open_checkpoint(huge, [log.verifier], origin=ORIGIN)


def test_signature_line_limit():
    """The spec asks verifiers to accept at least 16 signatures and to apply a
    limit: MAX_SIGNATURES lines are accepted, one more is refused."""
    log = N.Signer.generate(ORIGIN)
    others = [N.Signer.generate(f"w{i}.example/wit") for i in range(N.MAX_SIGNATURES)]
    for count in (16, N.MAX_SIGNATURES):
        msg = N.sign_note("t\n", [log] + others[:count - 1])
        assert len(N.open_note(msg, [log.verifier]).unknown) == count - 1
    with pytest.raises(N.NoteError, match="too many"):
        N.open_note(N.sign_note("t\n", [log] + others), [log.verifier])
