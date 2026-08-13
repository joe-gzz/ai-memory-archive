# Status of this repository

Last updated: 2026-08-13.

This file answers the one question `README.md` cannot: what this particular
copy holds today. Right now the answer is **no evidence at all**, and saying so
plainly is the reason this file exists.

## What is here

- `verify.mjs` — the independent verifier. Byte for byte the program the
  publisher runs, with no dependencies and no imports from the application.
- `README.md` — its specification: how to run it, what a passing run proves,
  and, at considerably greater length, what it does not.
- `keys/public-keys.json` — the key ring. It is **empty**. See below.
- `.gitattributes` — the rule that keeps every published byte identical on
  every platform. Everything here is hashed, signed, or read as a
  specification, so Git must never rewrite a line ending in any of it.

## What is not here, and why

**No campaign.** No manifest, no leaf set, no payload, no timestamp token. This
repository was created before the first real capture campaign, so that the
verifier and its specification can be read — and argued with — while nothing
yet depends on them.

A corpus does exist on the publisher's machine. It is fabricated and its dates
are backdated: it exists to exercise the code. Publishing it here would hand a
third party — this host's commit history — a false chronology to attest to, and
that is the exact opposite of what this repository is for. None of it will be
pushed here, ever.

**No production signing key.** The key ring is published and empty rather than
simply absent, because "no key has been published yet" is a fact worth stating
out loud, and because a missing key ring is indistinguishable from a forgotten
one.

The only signing key that exists today is a development key whose id begins
with `dev-`. The verifier refuses such keys outright (`README.md`, step 4 of
"What the verifier actually does"): a signature made with one is
arithmetically valid and evidentially worthless. Publishing it here as though
it were a production key would be precisely the kind of unearned reassurance
this project exists to remove.

## What running the verifier says today

From a clone of this repository, with Node.js 20 or newer and nothing else —
no `npm install`, no network, no account:

    node verify.mjs

Today that prints `Campaigns    : 0`, notes that the key ring loaded zero keys,
prints in full what a successful run would and would not prove, and ends with:

    Result: NOTHING VERIFIED — no campaign directory under <path>.

It exits with status `2`, which means "nothing was verified at all". That is
the correct answer today, and it is worth running once before there is any
evidence here: it is the shape of the report you will be reading later, with
the interesting part still empty.

## How the production signing key will be published

Written down in advance, so that it can be held against the publisher later.

1. The Ed25519 key pair is generated away from this repository. The private
   half is stored encrypted in the publisher's password manager and nowhere
   else: not in a database, not in this repository, not in any file of the
   application's working tree. It reaches the signing process through an
   environment variable.
2. The public half is published here, in `keys/public-keys.json`, in the same
   commit as the first campaign it signed — not before. A key published ahead
   of anything it signs is a claim with nothing behind it.
3. That commit message will state the key's id and the SHA-256 fingerprint of
   its published public bytes, so that the fingerprint's first appearance is
   itself dated by this host's commit history, independently of anything the
   publisher signs.
4. A key that is retired or compromised stays in the ring, with its revocation
   recorded there. Signatures it made before that date remain verifiable:
   revocation means "stop signing with this key", not "everything it ever
   signed is false". `README.md` explains how the verifier treats a revoked
   key, and why that is reported as a limit rather than a failure.

Checking a fingerprint against this repository alone proves nothing — it would
be the publisher vouching for the publisher. If the identity of the key matters
to you, record its fingerprint from a source that is not under the publisher's
control, on a date you chose yourself.

## Two things this repository is not

The application that produces this stream is not published at this time. The
verifier needs none of it: it reimplements canonicalization, hashing, the
Merkle construction and signature checking from scratch, deliberately, so that
two independent implementations have to agree before anything is claimed.
`README.md` explains why that duplication must not be factored out.

And nothing signs `verify.mjs` — not here, not anywhere. A verifier handed to
you by the party it is meant to check is worth exactly as much as your reading
of it. It was written to be read.
