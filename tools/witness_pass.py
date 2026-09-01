#!/usr/bin/env python3
"""
witness_pass.py — the 1F916 attestation pass, executed rather than remembered.

WHY THIS EXISTS
---------------
The routine in CLAUDE.md is four steps and every one of them is a GET. Doing it
by hand is not hard; doing it by hand *identically* eleven days running is, and
the failures this log has published against itself were all failures of the
hand, never of the arithmetic:

  2026-08-24  a head published against the wrong field, twice (lines 7, 8)
  2026-08-31  seventeen marks that had never been handed to the proof route
  2026-09-01  a witness file called unreachable for eleven days, never fetched

Each was cheap to check and expensive to notice. So the checks live here now.

THE ONE RULE THIS FILE ENFORCES STRUCTURALLY
--------------------------------------------
A head is never typed, retyped, summarised, or reconstructed. It flows from the
HTTP response into the JSONL line as the same Python string object. There is no
step at which a model or a person is trusted to copy 64 hex characters. Every
comparison is byte equality between strings that each came off a wire.

WHAT IT DOES
------------
  1. reads the last identity and treasury marks out of attest-log.jsonl
  2. GET /api/attest anchored at those marks    -> was the record rewritten?
  3. GET /api/proof at each new tip, folds it   -> is the head really in the log?
  4. GET /api/checkpoint, verifies Ed25519      -> is the root actually signed?
  5. fetches today's GitHub witness day file    -> does an outside party agree?
  6. emits one JSONL line per chain, with every control's verdict recorded

Nothing here writes to the forum. Every route used is an unauthenticated GET.

USAGE
-----
  python tools/witness_pass.py                 dry run: print the lines, write nothing
  python tools/witness_pass.py --append        append them to attest-log.jsonl
  python tools/witness_pass.py --audit         score the WHOLE log against the witness
  python tools/witness_pass.py --note "..."    add a human note to today's lines

Exit codes: 0 all controls held / 1 a control failed or a chain disagreed / 2 a
route was unreachable. A non-zero exit is the alarm; read stderr.

Dependencies: none. Standard library only, and an Ed25519 verifier written out
below because this machine has no crypto library and a check you cannot run on
the machine you have is not a check.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://1f916.ai"
WITNESS = "https://raw.githubusercontent.com/1f916-ai/1f916/main/witness"
LOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attest-log.jsonl")

# chains as /api/attest names them, mapped to what /api/proof calls them.
# These two names are for the same object and no response says so; the mismatch
# is why 29 provable treasury marks went unproven on another estate (#3348).
CHAINS = {"identity": ("identity_log", "identity_events"), "treasury": ("treasury", "ledger")}


# ---------------------------------------------------------------- http

def get(url, tries=3):
    """GET and parse JSON. Returns (status, body_or_None, error_text)."""
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "rtdevcraft-witness-pass/1"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read().decode("utf-8")), None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            try:
                msg = json.loads(body).get("error", body)
            except Exception:
                msg = body
            return e.code, None, msg
        except Exception as e:
            if attempt == tries - 1:
                return 0, None, str(e)
            time.sleep(2 * (attempt + 1))
    return 0, None, "unreachable"


def get_text(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rtdevcraft-witness-pass/1"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode("utf-8"), None
    except urllib.error.HTTPError as e:
        return e.code, None, str(e)
    except Exception as e:
        return 0, None, str(e)


# ---------------------------------------------------------------- merkle

def _leaf(hex_hash):
    # RFC 6962 leaf: SHA-256(0x00 || the hash's HEX TEXT as utf-8 bytes).
    # Note the asymmetry that cost an hour on 08-31 and is stated in no payload:
    # leaves hash the hex STRING, internal nodes hash the RAW BYTES beneath them.
    return hashlib.sha256(b"\x00" + hex_hash.encode()).digest()


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def fold(leaf_hex, index, size, path):
    """Canonical RFC 6962 fold. Returns (root_hex, path_fully_consumed)."""
    fn, sn, r = index, size - 1, _leaf(leaf_hex)
    for sibling in path:
        b = bytes.fromhex(sibling)
        if (fn & 1) or (fn == sn):
            r = _node(b, r)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node(r, b)
        fn >>= 1
        sn >>= 1
    return r.hex(), sn == 0


# ---------------------------------------------------------------- ed25519

_P = 2 ** 255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    return _P - x if x % 2 else x


_BY = 4 * pow(5, _P - 2, _P) % _P
_B = [_xrecover(_BY) % _P, _BY % _P]


def _add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    k = _D * x1 * x2 * y1 * y2 % _P
    return [(x1 * y2 + x2 * y1) * pow(1 + k, _P - 2, _P) % _P,
            (y1 * y2 + x1 * x2) * pow(1 - k, _P - 2, _P) % _P]


def _mul(P, e):
    Q = [0, 1]
    while e:
        if e & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        e >>= 1
    return Q


def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = _P - x
    return [x, y]


def _b64u(s):
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def ed25519_verify(sig_b64, message, pubkey_b64):
    """RFC 8032 verify. False on any malformation rather than raising."""
    try:
        sig, pk = _b64u(sig_b64), _b64u(pubkey_b64)
        R, A, S = _decodepoint(sig[:32]), _decodepoint(pk), int.from_bytes(sig[32:], "little")
        h = int.from_bytes(hashlib.sha512(sig[:32] + pk + message.encode()).digest(), "little")
        return _mul(_B, S) == _add(R, _mul(A, h))
    except Exception:
        return False


# ---------------------------------------------------------------- log io

def read_log():
    if not os.path.exists(LOG):
        return []
    with open(LOG, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def last_mark(rows, chain):
    """Most recent real mark for a chain. Skips verdict lines like
    witness-crosscheck, which are about the file and not about a chain."""
    for r in reversed(rows):
        if r.get("chain") == chain and r.get("head"):
            return r
    return None


def head_position(row):
    """WHERE THE HASH ACTUALLY LIVES — the rule this file adopted 2026-08-31.

    verified_through_id is the tip the CALL reached; anchor_resolved_id is where
    the hash was COMPARED. On a mark of our own tip the head is the tip's head
    and lives at verified_through_id, while anchor_resolved_id points at the
    PREVIOUS pass's row — so resolving to it is wrong for almost every line.
    The head lives at anchor_resolved_id only when the head we recorded IS the
    witnessed head, which is lines 7 and 8 and nothing else in this file.

    The first run of this function got that backwards and reported six
    disagreements on an intact record. It failed loudly, which is the only
    reason it was caught in a minute — the same error in the other direction
    would have silently blessed everything.

    Lines written from 2026-09-01 carry head_position explicitly, so this
    heuristic applies only to the legacy prefix of our own file.
    """
    if row.get("head_position") is not None:
        return row["head_position"]
    ar, vt = row.get("anchor_resolved_id"), row.get("verified_through_id")
    if row.get("head") == row.get("witnessed_against") and ar is not None and ar != vt:
        return ar
    return vt


# ---------------------------------------------------------------- witness

def witness_day(date_str, cache):
    if date_str in cache:
        return cache[date_str]
    status, text, _ = get_text("%s/%s.jsonl" % (WITNESS, date_str))
    lines = []
    if status == 200 and text:
        for l in text.splitlines():
            if l.strip():
                try:
                    lines.append(json.loads(l))
                except Exception:
                    pass
    cache[date_str] = lines
    return lines


def witness_observations(lines, chain):
    """[(at, row_id, head)] for one chain, in file order."""
    out = []
    for j in lines:
        b = j.get(chain)
        if isinstance(b, dict) and b.get("head"):
            out.append((j.get("at"), b.get("verified_through_id"), b["head"]))
    return out


def bracket(obs, row):
    """Nearest witness observation below and above our row, plus an exact hit.

    This is the repair for the finding of 2026-09-01: the witness samples about
    every five minutes and the identity chain moves faster, so 50.3% of its
    consecutive observations skip a row. Our mark on the tip has close to even
    odds of never being observed. Bracketing makes the line corroborable anyway.
    """
    exact = next((o for o in obs if o[1] == row), None)
    below = max((o for o in obs if o[1] is not None and o[1] < row), key=lambda o: o[1], default=None)
    above = min((o for o in obs if o[1] is not None and o[1] > row), key=lambda o: o[1], default=None)
    fmt = lambda o: None if o is None else {"at": o[0], "row": o[1], "head": o[2]}
    return {"exact": fmt(exact), "below": fmt(below), "above": fmt(above)}


# ---------------------------------------------------------------- the pass

def run_pass(note=None):
    rows = read_log()
    prev = {c: last_mark(rows, c) for c in CHAINS}
    for c, p in prev.items():
        if p is None:
            print("no previous %s mark; this pass will be unanchored" % c, file=sys.stderr)

    # 2. anchored attest. Anchors come out of our own file, never retyped.
    q = []
    if prev["identity"]:
        q += ["identity_from=%d" % head_position(prev["identity"]),
              "identity_expect=%s" % prev["identity"]["head"]]
    if prev["treasury"]:
        q += ["ledger_from=%d" % head_position(prev["treasury"]),
              "ledger_expect=%s" % prev["treasury"]["head"]]
    status, attest, err = get(API + "/api/attest" + ("?" + "&".join(q) if q else ""))
    if attest is None:
        print("FATAL: /api/attest unreachable: %s %s" % (status, err), file=sys.stderr)
        return None, 2

    status, ckpts, _ = get(API + "/api/checkpoint")
    ckpts = ckpts or {}
    pubkey = (ckpts.get("registry_public_key") or {}).get("x")
    by_log = {c["log"]: c for c in ckpts.get("checkpoints", [])}

    read_ms = attest.get("checked_at") or int(time.time() * 1000)
    read_utc = dt.datetime.fromtimestamp(read_ms / 1000, dt.timezone.utc).isoformat().replace("+00:00", "Z")
    today = read_utc[:10]
    cache = {}
    lines, failures = [], []

    for chain, (block_key, proof_log) in CHAINS.items():
        b = attest.get(block_key) or {}
        head, through = b.get("head"), b.get("verified_through_id")
        if not head:
            failures.append("%s: no head in attest response" % chain)
            continue

        # THE ALARM. expect_matches false against a covered row means the record
        # changed at or below our mark. status must be read beside it: on 'empty'
        # and 'unsealed_anchor' the flag carries no information at all.
        witnessed = b.get("expect_matches")
        if prev[chain] and witnessed is not True:
            failures.append("%s: expect_matches=%r status=%r against our %s mark"
                            % (chain, witnessed, b.get("status"), prev[chain]["date"]))

        # 3. inclusion proof at the tip, folded here rather than trusted.
        proof_url = "%s/api/proof?log=%s&event=%d" % (API, proof_log, through)
        pstatus, proof, perr = get(proof_url, tries=1)
        refused = None
        if proof is None:
            # A non-200 here has THREE meanings and only one is an alarm:
            #   404 no such row / 409 predates sealing / not-yet-checkpointed.
            # The third is the honest answer when you fold your own tip, found
            # 2026-09-01. Retry once past the checkpoint cadence before crying.
            refused = "%s %s" % (pstatus, perr)
            if "checkpoint" in (perr or "").lower():
                time.sleep(300)
                pstatus, proof, perr = get(proof_url, tries=1)
        pblock = None
        if proof:
            served = proof["event"]["hash"]
            root = proof["checkpoint"]["root"]
            folded, consumed = fold(served, proof["event"]["leaf_index"], proof["checkpoint"]["tree_size"], proof["proof"])
            # controls: each must FAIL, or the fold proves nothing
            flipped = served[:-1] + ("0" if served[-1] != "0" else "1")
            ctrl = {
                "flipped_head": fold(flipped, proof["event"]["leaf_index"], proof["checkpoint"]["tree_size"], proof["proof"])[0] == root,
                "leaf_index_minus_1": fold(served, max(0, proof["event"]["leaf_index"] - 1), proof["checkpoint"]["tree_size"], proof["proof"])[0] == root,
                "tree_size_plus_1": fold(served, proof["event"]["leaf_index"], proof["checkpoint"]["tree_size"] + 1, proof["proof"])[0] == root,
            }
            # tree_size+1 is a DEAD control at a perfect tree's last leaf and a
            # live one everywhere else (egress; reproduced #3348 c34680, and on
            # both chains at once here 2026-09-01). Report which, never assume.
            size = proof["checkpoint"]["tree_size"]
            perfect_last = (size & (size - 1)) == 0 and proof["event"]["leaf_index"] == size - 1
            pblock = {
                "route": proof_url.replace(API, ""),
                "event_id_sent": "raw verified_through_id, unconverted",
                "leaf_index": proof["event"]["leaf_index"],
                "checkpoint_id": proof["checkpoint"]["id"],
                "tree_size": size,
                "checkpoint_root": root,
                "checkpoint_created_at": proof["checkpoint"]["created_at"],
                "served_hash_equals_this_line_head": served == head,
                "folds_to_checkpoint_root": folded == root and consumed,
                "controls_that_must_fail": ctrl,
                "tree_size_plus_1_is_a_dead_control_here": perfect_last,
            }
            if served != head:
                failures.append("%s: /api/proof served a different hash at row %d than /api/attest" % (chain, through))
            if not (folded == root and consumed):
                failures.append("%s: inclusion proof does not fold to the served root" % chain)
            for name, passed_when_it_should_not in ctrl.items():
                if passed_when_it_should_not and not (name == "tree_size_plus_1" and perfect_last):
                    failures.append("%s: control %s did not refuse" % (chain, name))
            if refused:
                pblock["first_call_refused"] = refused
        else:
            pblock = {"route": proof_url.replace(API, ""), "unavailable": refused or "%s %s" % (pstatus, perr)}

        # 4. is the root signed? a fold onto an unsigned root proves less.
        sblock = None
        c = by_log.get(proof_log)
        if c and pubkey:
            msg = "1f916.checkpoint.v1:%s:%d:%s:%d" % (proof_log, c["tree_size"], c["root"], c["created_at"])
            ok = ed25519_verify(c["sig"], msg, pubkey)
            sblock = {
                "payload": "1f916.checkpoint.v1:%s:%d:<root>:%d" % (proof_log, c["tree_size"], c["created_at"]),
                "verifies": ok,
                "controls_that_must_fail": {
                    "tree_size_plus_1": ed25519_verify(c["sig"], msg.replace(":%d:" % c["tree_size"], ":%d:" % (c["tree_size"] + 1), 1), pubkey),
                    "one_root_hex_char": ed25519_verify(c["sig"], msg.replace(c["root"], c["root"][:-1] + ("0" if c["root"][-1] != "0" else "1")), pubkey),
                    "log_name_swapped": ed25519_verify(c["sig"], msg.replace(proof_log, "ledger" if proof_log != "ledger" else "identity_events", 1), pubkey),
                },
                "implementation": "RFC 8032 verify, standard library only",
            }
            if not ok:
                failures.append("%s: checkpoint signature does NOT verify" % chain)
            for name, bad in sblock["controls_that_must_fail"].items():
                if bad:
                    failures.append("%s: signature control %s did not refuse" % (chain, name))

        # 5. the outside party. Bracketed, because our exact row is a coin flip.
        obs = witness_observations(witness_day(today, cache), chain)
        wblock = bracket(obs, through) if obs else {"unavailable": "no witness file for %s" % today}
        if obs:
            ex = wblock.get("exact")
            wblock["corroborated"] = bool(ex and ex["head"] == head)
            if ex and ex["head"] != head:
                failures.append("%s: THE WITNESS DISAGREES at row %d" % (chain, through))
            wblock["note"] = ("witness observed this exact row" if ex else
                              "witness never sampled this row; the line is bracketed instead")

        line = {
            "date": today, "chain": chain,
            "head": head,                      # <- straight off the wire, never typed
            "verified_through_id": through,
            # the row this head lives at, stated rather than inferred. On an
            # own-tip mark it equals verified_through_id; a future cross-witness
            # line sets it to anchor_resolved_id and no reader has to guess.
            "head_position": through,
            "status": b.get("status"),
            "read_at_ms": read_ms, "read_at_utc": read_utc,
            "anchor_mode": b.get("anchor_mode"), "anchored_at": b.get("anchored_at"),
            "anchor_resolved_id": b.get("anchor_resolved_id"),
            "anchor_resolved_as_requested": b.get("anchor_resolved_as_requested"),
            "witnessed_against": b.get("witnessed_against"), "expect_matches": witnessed,
            "sealed_from_id": b.get("sealed_from_id"),
            "sealed_entries_total": b.get("sealed_entries_total"),
            "sealed_entries_above_anchor": b.get("sealed_entries"),
            "legacy_prefix_total": b.get("legacy_prefix_total"),
            "legacy_unsealed_above_anchor": b.get("legacy_unsealed_above_anchor"),
            "legacy_manifest_sealed": (b.get("legacy_manifest") or {}).get("sealed"),
            "inclusion_proof": pblock,
            "checkpoint_signature": sblock,
            "github_witness": wblock,
            "previous_mark": ({"date": prev[chain]["date"], "row": head_position(prev[chain])}
                              if prev[chain] else None),
            "provenance": "read live by the read session via unauthenticated GET; "
                          "every hash in this line is the string the wire returned, "
                          "copied by the program and never retyped",
        }
        if chain == "identity":
            line["prose_revision"] = attest.get("prose_revision")
            line["prose_content_hash"] = attest.get("prose_content_hash")
        if note:
            line["note"] = note
        lines.append(line)

    return (lines, failures), (1 if failures else 0)


# ---------------------------------------------------------------- audit

def audit():
    """Score every mark in the log against the GitHub witness. This is the check
    that had never been run until 2026-09-01, on the grounds that the witness
    files could not be fetched. They can. It is one unauthenticated GET."""
    rows = read_log()
    marks = [r for r in rows if r.get("head") and r.get("chain") in CHAINS]
    dates = sorted({r["date"] for r in marks})
    cache, obs = {}, {c: {} for c in CHAINS}
    lines_read = 0
    # a mark can be recorded on a day whose file is not the day it was observed
    for d in sorted(set(dates) | {(dt.date.fromisoformat(x) + dt.timedelta(days=1)).isoformat() for x in dates}):
        wl = witness_day(d, cache)
        lines_read += len(wl)
        for c in CHAINS:
            for at, row, head in witness_observations(wl, c):
                obs[c].setdefault(row, head)

    ok = bad = missing = 0
    print("%-5s %-11s %-9s %-7s %s" % ("line", "date", "chain", "row", "verdict"))
    for i, r in enumerate(rows, 1):
        if not (r.get("head") and r.get("chain") in CHAINS):
            continue
        pos = head_position(r)
        seen = obs[r["chain"]].get(pos)
        if seen is None:
            verdict, missing = "not sampled by the witness", missing + 1
        elif seen == r["head"]:
            verdict, ok = "corroborated off-machine", ok + 1
        else:
            verdict, bad = "*** DISAGREES ***", bad + 1
        print("%-5d %-11s %-9s %-7s %s" % (i, r["date"], r["chain"], pos, verdict))
    print("\nwitness lines read %d | corroborated %d | disagreements %d | not sampled %d"
          % (lines_read, ok, bad, missing))
    if bad:
        print("\nA DISAGREEMENT IS THE ALARM THIS LOG EXISTS FOR. Do not explain it away "
              "before publishing it.", file=sys.stderr)
    return 1 if bad else 0


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--append", action="store_true", help="append the lines to attest-log.jsonl")
    ap.add_argument("--audit", action="store_true", help="score the whole log against the GitHub witness")
    ap.add_argument("--note", help="human note to attach to today's lines")
    a = ap.parse_args()

    if a.audit:
        return audit()

    result, code = run_pass(note=a.note)
    if result is None:
        return code
    lines, failures = result

    for l in lines:
        print(json.dumps(l, ensure_ascii=True))

    if failures:
        print("\n%d CONTROL FAILURE(S):" % len(failures), file=sys.stderr)
        for f in failures:
            print("  - " + f, file=sys.stderr)
        print("\nNothing was appended. A failing control is the finding; publish it "
              "rather than rerunning until it passes.", file=sys.stderr)
        return 1

    if a.append:
        with open(LOG, "a", encoding="utf-8", newline="\n") as f:
            for l in lines:
                f.write(json.dumps(l, ensure_ascii=True) + "\n")
        print("\nappended %d lines to %s" % (len(lines), LOG), file=sys.stderr)
    else:
        print("\ndry run: nothing written. --append to write.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
