# Demo 01 - Basic queue + crack + audit

A red-team engagement recovers four password hashes from a dumped database.
We queue them in CRACKQ, run them against a small wordlist with rule mangling,
and confirm the run is recorded in the tamper-evident audit log.

## Files

- `hashes.txt` - four hashes (mixed md5/sha1/sha256). Three are crackable with
  the demo wordlist + rules; one is not, to show an `exhausted` outcome.
- `wordlist.txt` - a tiny candidate dictionary.

The known plaintexts behind the crackable hashes:

- md5("Password123")    = 42f749ade7f9e195bf475f37a44cafcb
- sha1("hunter2")       = f3bbbd66a63d4bf1747940578ec3d0103530e21d
- sha256("letmein!")    = the sha256 of `letmein` + the `!` append rule

## Run it

```
python -m crackq --format table run \
    --hashfile demos/01-basic/hashes.txt \
    --wordlist demos/01-basic/wordlist.txt \
    --owner analyst1
```

Then verify the audit chain:

```
python -m crackq --format json audit --verify
```

Expected: three jobs reach state `cracked`, one reaches `exhausted`, and the
audit verification reports `"verified": true`.

## Why it matters

The audit log is hash-chained: every record embeds the SHA-256 of the prior
record, so any edit, deletion, or reordering of who-ran-what is detectable.
That is the difference between "someone cracked these" and an accountable,
multi-user cracking service.
