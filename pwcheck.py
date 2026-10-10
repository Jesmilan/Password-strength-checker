#!/usr/bin/env python3
"""
pwcheck.py - password strength checker.

Scores a password by estimated entropy (with penalties for common patterns)
and checks it against the HaveIBeenPwned "Pwned Passwords" breach corpus.

The breach check uses HIBP's k-anonymity range API: only the first 5 hex
characters of the password's SHA-1 hash leave your machine. The matching
suffix is compared locally, so neither the password nor its full hash is
ever sent anywhere.

Standard library only (no pip install needed). Python 3.8+.
"""

import argparse
import getpass
import hashlib
import json
import math
import re
import string
import sys
import urllib.error
import urllib.request
from collections import Counter

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "pwcheck-learning-tool"

# Small built-in list so the tool still catches the worst offenders offline.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "1234567", "1234567890",
    "letmein", "welcome", "monkey", "dragon", "football", "iloveyou",
    "admin", "login", "princess", "sunshine", "master", "shadow",
    "qwerty123", "passw0rd", "trustno1", "baseball", "superman", "000000",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


# --------------------------------------------------------------------------
# Entropy
# --------------------------------------------------------------------------

def charset_size(pw):
    """Size of the character pool the password draws from."""
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c in string.digits for c in pw):
        pool += 10
    if any(c in string.punctuation for c in pw):
        pool += len(string.punctuation)  # 32
    if any(c == " " for c in pw):
        pool += 1
    if any(ord(c) > 127 for c in pw):
        pool += 100  # rough allowance for non-ASCII
    return pool


def charset_entropy(pw):
    """Upper bound: length * log2(pool size), assuming random characters."""
    pool = charset_size(pw)
    return len(pw) * math.log2(pool) if pool else 0.0


def shannon_entropy(pw):
    """Bits per character based on actual character frequency."""
    if not pw:
        return 0.0
    counts = Counter(pw)
    n = len(pw)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _has_sequence(s, min_len=4):
    """abcd, 1234, dcba, 4321 and keyboard walks like qwer/asdf."""
    low = s.lower()
    for i in range(len(low) - min_len + 1):
        chunk = low[i:i + min_len]
        diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(min_len - 1)}
        if diffs in ({1}, {-1}):
            return True
        for row in KEYBOARD_ROWS:
            if chunk in row or chunk[::-1] in row:
                return True
    return False


def find_weaknesses(pw):
    """Return a list of (description, bits_penalty) for detected patterns."""
    issues = []
    low = pw.lower()
    leet = low.translate(str.maketrans("@0134$5!7", "aoleassit"))

    if low in COMMON_PASSWORDS or leet in COMMON_PASSWORDS:
        issues.append(("is a very common password", 1000))
    if len(pw) < 8:
        issues.append(("shorter than 8 characters", 10))
    if re.search(r"(.)\1{2,}", pw):
        issues.append(("repeated characters (e.g. 'aaa')", 10))
    if _has_sequence(pw):
        issues.append(("sequential or keyboard pattern (e.g. 'abcd', '1234', 'qwer')", 15))
    if re.search(r"(19|20)\d{2}", pw):
        issues.append(("looks like it contains a year", 8))
    if re.fullmatch(r"[A-Za-z]+\d{1,4}[!@#$%^&*.?]?", pw):
        issues.append(("predictable 'Word123!' shape", 15))
    if pw.isdigit():
        issues.append(("digits only", 10))
    elif pw.isalpha():
        issues.append(("letters only", 5))
    if len(set(pw)) <= len(pw) / 3:
        issues.append(("few unique characters", 10))
    return issues


def rate(bits):
    if bits < 28:
        return "very weak"
    if bits < 36:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 80:
        return "strong"
    return "very strong"


def crack_time(bits, guesses_per_sec=1e10):
    """Rough average time to brute-force at 10 billion guesses/sec (offline GPU)."""
    seconds = (2 ** bits) / 2 / guesses_per_sec
    for unit, size in (("years", 31_557_600), ("days", 86_400),
                       ("hours", 3_600), ("minutes", 60)):
        if seconds >= size:
            value = seconds / size
            if unit == "years" and value > 1e6:
                return "millions of years+"
            return f"{value:,.0f} {unit}"
    return "instantly" if seconds < 1 else f"{seconds:.0f} seconds"


# --------------------------------------------------------------------------
# HaveIBeenPwned (k-anonymity)
# --------------------------------------------------------------------------

def sha1_hex(pw):
    return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()


def parse_range_response(body, suffix):
    """Find our suffix in a 'SUFFIX:COUNT' per-line response. Padding rows have count 0."""
    for line in body.splitlines():
        if ":" not in line:
            continue
        candidate, count = line.strip().split(":", 1)
        if candidate.upper() == suffix:
            return int(count)
    return 0


def hibp_breach_count(pw, timeout=10):
    """
    Return the number of times the password appears in HIBP's breach corpus.
    Returns None if the API could not be reached.
    """
    digest = sha1_hex(pw)
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        HIBP_RANGE_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    return parse_range_response(body, suffix)


def wordlist_contains(pw, path):
    """Offline fallback: look for the password in a local list (e.g. rockyou.txt)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return any(line.rstrip("\r\n") == pw for line in fh)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def analyze(pw, use_hibp=True, wordlist=None):
    raw_bits = charset_entropy(pw)
    weaknesses = find_weaknesses(pw)
    penalty = sum(p for _, p in weaknesses)
    effective = max(0.0, raw_bits - penalty)

    breach_count = hibp_breach_count(pw) if use_hibp else None
    in_wordlist = wordlist_contains(pw, wordlist) if wordlist else None

    if breach_count:
        effective = 0.0  # a leaked password is in every attacker's wordlist
    if in_wordlist:
        effective = 0.0

    return {
        "length": len(pw),
        "charset_size": charset_size(pw),
        "charset_entropy_bits": round(raw_bits, 1),
        "shannon_bits_per_char": round(shannon_entropy(pw), 2),
        "weaknesses": [w for w, _ in weaknesses],
        "effective_entropy_bits": round(effective, 1),
        "rating": rate(effective),
        "est_crack_time_offline": crack_time(effective),
        "hibp_checked": use_hibp,
        "hibp_reachable": (breach_count is not None) if use_hibp else None,
        "hibp_breach_count": breach_count,
        "wordlist_match": in_wordlist,
    }


def print_report(r):
    print(f"Length:              {r['length']}")
    print(f"Character pool:      {r['charset_size']}")
    print(f"Raw entropy:         {r['charset_entropy_bits']} bits")
    print(f"Shannon entropy:     {r['shannon_bits_per_char']} bits/char")
    print(f"Effective entropy:   {r['effective_entropy_bits']} bits")
    print(f"Rating:              {r['rating'].upper()}")
    print(f"Est. crack time:     {r['est_crack_time_offline']} (offline, 10B guesses/s)")

    if r["hibp_checked"]:
        if not r["hibp_reachable"]:
            print("HIBP breach check:   UNAVAILABLE (could not reach api.pwnedpasswords.com)")
        elif r["hibp_breach_count"]:
            print(f"HIBP breach check:   PWNED, seen {r['hibp_breach_count']:,} times in breaches")
        else:
            print("HIBP breach check:   not found in known breaches")
    else:
        print("HIBP breach check:   skipped (--offline)")

    if r["wordlist_match"] is not None:
        print(f"Local wordlist:      {'FOUND' if r['wordlist_match'] else 'not found'}")

    if r["weaknesses"]:
        print("Weaknesses:")
        for w in r["weaknesses"]:
            print(f"  - {w}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Password strength + breach checker")
    ap.add_argument("password", nargs="?",
                    help="password to check (omit to be prompted; avoids shell history)")
    ap.add_argument("--stdin", action="store_true",
                    help="read one password per line from stdin")
    ap.add_argument("--offline", action="store_true",
                    help="skip the HaveIBeenPwned lookup")
    ap.add_argument("--wordlist", metavar="FILE",
                    help="also check against a local wordlist (e.g. rockyou.txt)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args(argv)

    if args.stdin:
        passwords = [l.rstrip("\r\n") for l in sys.stdin if l.strip()]
    elif args.password is not None:
        passwords = [args.password]
    else:
        passwords = [getpass.getpass("Password: ")]

    results = [analyze(p, use_hibp=not args.offline, wordlist=args.wordlist)
               for p in passwords]

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
    else:
        for i, r in enumerate(results):
            if len(results) > 1:
                print(f"\n=== password #{i + 1} ===")
            print_report(r)

    # Exit 1 if any password is weak or pwned, handy for scripts.
    bad = any(r["hibp_breach_count"] or r["rating"] in ("very weak", "weak")
              for r in results)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
