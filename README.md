# pwcheck: password strength + breach checker

Standard library only, Python 3.8+.

## Usage

```bash
python3 pwcheck.py                      # prompts (hidden input, stays out of shell history)
python3 pwcheck.py 'Summer2024!'        # quick check
python3 pwcheck.py --offline 'hunter2'  # skip the HIBP lookup
python3 pwcheck.py --wordlist rockyou.txt   # also check a local leak list
cat list.txt | python3 pwcheck.py --stdin --json
```

Exit code is 1 if any password is weak or found in a breach.

## How it scores

- **Raw entropy** = length × log2(character pool size)
- **Penalties** for common passwords (incl. leetspeak), repeats, sequences/keyboard walks, years, `Word123!` shape, single char class
- **Effective entropy** = raw − penalties; forced to 0 if found in HIBP or the wordlist
- Ratings: <28 very weak, <36 weak, <60 fair, <80 strong, 80+ very strong
- Crack time assumes an offline attack at 10 billion guesses/sec

## HaveIBeenPwned privacy (k-anonymity)

1. SHA-1 the password locally
2. Send only the first 5 hex chars to `https://api.pwnedpasswords.com/range/<prefix>`
3. Match the remaining 35 chars against the returned list locally
4. `Add-Padding: true` header hides the real response size

If the API can't be reached, the report says `UNAVAILABLE` and the entropy check still runs.

## Tests

```bash
python3 -m unittest test_pwcheck.py
```
