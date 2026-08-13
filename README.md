# Verifying this archive yourself

This archive is meant to be checked by people who have no reason to trust the
people who published it. That is why `verify.mjs` sits next to the data: you
should not have to take our word for anything, and you should not have to run
our application to find out.

## What this is

A stream of files recording what a fixed set of AI systems answered to a fixed
set of questions, asked again and again over years. Each answer is captured
together with the exchange that produced it, and hashed; the hashes of one
campaign are folded into a Merkle tree; the tree's root, the number of records
and the link to the previous campaign are signed together and, when an
authority answers, timestamped. The point of the whole apparatus is to be able
to show what changed between one capture and the next without asking anyone to
believe the publisher.

The stream is published as a Git repository, so that every clone is a mirror
and the host's commit history is one more witness of when each campaign
appeared. The directory you are reading is that stream: `verify.mjs` sits at
its root, next to the campaigns it checks.

If this copy came from that repository, the `STATUS.md` file next to this one
is the publisher's dated statement of what the repository holds — including
whether it holds any campaign at all yet, and which signing keys have been
published.

## Running it

You need Node.js 20 or newer. Nothing else — no `npm install`, no network
access, no account.

```sh
node verify.mjs
```

Run from inside the archive directory, the verifier checks every campaign it
finds next to itself. You can also point it somewhere else:

```sh
node verify.mjs /path/to/archive
```

Three flags exist. `--help` (or `-h`) prints the usage block and exits without
verifying anything. `--allow-dev-keys` downgrades the refusal of a development
signing key to a warning, and a published archive must never need it.
`--scan-budget=<n>` raises or lowers how many directories the search for
misplaced campaign material may open (default 50 000). Lowering it never hides
anything quietly — whatever is left unsearched is named as a limit — and raising
it is the answer when that limit appears on a very large working copy.

Exit codes: `0` means no integrity failure was found, `1` means at least one
check failed, `2` means nothing was verified at all (missing directory, no
campaign, bad arguments). A `2` still prints the full report, because the case
where nothing could be checked is the case where knowing *what was skipped*
matters most. Note which case `2` most often is: a repository that carries this
program and its documentation but holds no campaign yet exits `2` on a perfectly
healthy run. The program ran to the end; there was simply nothing to verify.

The final line is one of four:

- `NOTHING VERIFIED` — no campaign directory was found under the root. Not a
  judgement on anything: the run found nothing to judge, and the report above it
  names what it did find.
- `FAILED` — at least one proof does not hold.
- `VERIFIED WITH LIMITS` — no check failed, but the run states things it is
  **not** entitled to conclude. Read them; they are the interesting part.
- `VERIFIED — no discrepancy found.` — nothing this program checks came out
  wrong. Note what that sentence does **not** say: not "every check passed",
  which would invite you to hear "every check that matters". This program never
  decodes a timestamp token, so a clean run leaves the archive's central claim
  — its dates — entirely unexamined. The line points you at the "what it does
  NOT prove" section for that reason.

Warnings and limits both prevent the unqualified `VERIFIED` line. A summary
claiming a clean run a few lines under a warning would contradict the body of
its own report.

## The rule this program is built on

> **Every byte of the archive is either covered by a signature, or named in the
> report.**

Operationally: everything living at a level the archive format defines — the
root, a campaign directory, `payloads/`, `tsr/`, `keys/` — is named
individually. A directory the format does not define is named as a whole and
searched, at any depth, for campaign material; listing every file inside a
cloned `.git` would bury the report, while leaving a campaign hidden inside one
would be a hole. The search covers *every* directory at the root, campaign
directories included: the one blind spot it used to have had the shape of the
archive's own layout.

Very little of an archive is actually signed: the canonical bytes of each
manifest, and — through the Merkle root the manifest carries — the bytes of
each payload file. Everything else is unsigned: the key ring, the timestamp
tokens, the per-leaf metadata in `merkle.json`, and this program itself.

Unsigned does not mean harmless. A file dropped next to genuine evidence
borrows its credibility. So the verifier walks the whole tree and, for every
entry, either verifies it or names it. If you run it and something you expected
to see is not mentioned anywhere in the output, that is a bug worth reporting.

The rule has no exception for a run that already failed. A campaign whose
manifest is rejected still gets the contents of its `payloads/` and `tsr/`
listed, because the reader whose archive was rejected is exactly the reader who
needs to know what is in it.

Three consequences worth stating, because each of them is a place where the
rule was once broken:

- **No path this program opens ever traverses a link, and every link is named.**
  A symbolic link or a Windows junction is neither a file nor a directory.
  Following one would let an archive point at bytes it does not contain, or back
  at one of its own parents, so nothing behind a link is read, listed, hashed or
  verified — not by the search for misplaced campaigns, and not by any of the
  readers. A directory whose `manifest.json` is a link is therefore **not** a
  campaign, and is reported as campaign material with no manifest; a `keys/`
  that is a link means no key ring was read at all, and every signature fails
  for want of a key. Naming a link without refusing to read through it was a
  real bug here: the same run printed both a failure about the link and a
  passing signature check over bytes from outside the archive.
- **A search that was cut short says so, and names what it did not finish.** The
  scan budget is global, and the root is walked in alphabetical order, so a
  large `.assets-cache/` can exhaust it before `docs/` is reached. When that
  happens the summary for each unfinished directory reads *not searched to the
  end* rather than *no manifest.json anywhere inside* — which would be a false
  statement dressed as a reassuring one.
- **Everything printed is escaped, at the one place where printing happens.**
  File names, campaign ids, key ids, unknown field names and sidecar values all
  end up inside report lines. Control characters in any of them are printed as
  an escape such as `\u000a`, so an archive cannot write its own report lines —
  which, before this was fixed, it could, verdict line included. Bidirectional
  formatting characters are escaped too: `U+202E` forges no line, but it
  reverses the visible order of the rest of the line it appears in, in every
  terminal (Trojan Source, CVE-2021-42574). Line **length** is deliberately not
  capped: the lines that grow are the ones that *name* things — the inventory,
  the list of stray manifests — and truncating those would break the rule above.

## What is in the archive

```
archive/
  verify.mjs                     this program
  README.md                      this file
  keys/public-keys.json          every public signing key, past and present
  <campaign-id>/
    manifest.json                the signed statement about one campaign
    merkle.json                  one entry per record: archive id, payload hash, capture date
    payloads/<archive-id>.json   the exact bytes that were hashed, for published records
    tsr/<authority>.tsr          timestamp tokens, as returned by the authority
    tsr/<authority>.json         the authority's certificate chain, and when we asked
```

Every record of a campaign has a leaf in `merkle.json`, published or not —
otherwise the count in the manifest would silently exclude whatever was held
back. Only some of those leaves have a payload file.

A campaign directory may hold those four entries and nothing else, each of the
type shown above; anything extra, or an entry of the wrong type, is a failure.
`keys/` may hold `public-keys.json` and nothing else, for the same reason. The
archive root may hold anything (it is a published Git repository — `.git/`,
`LICENSE`, `docs/` are perfectly ordinary), and whatever is there gets listed
rather than judged — but it is also searched, so a campaign parked under
`docs/2026-07-01/` or `.cache/` is found and reported instead of vanishing.

A directory is treated as a campaign because it contains a `manifest.json`,
never because of its name.

**If you get `FAILED` because of a file you recognise.** A campaign directory
is strict, and it is strict about everything: a `.DS_Store` left by opening the
folder in the macOS Finder, a `Thumbs.db`, an editor's swap file will each be
reported as an unexpected entry and will each make the run fail. That is not the
verifier telling you the archive was tampered with — it is telling you the
directory no longer holds only what was signed, and it has no way to tell your
file manager's droppings from a smuggled one. There is deliberately no list of
blessed names here: a list of names an attacker can read is a list of names an
attacker can use. Check the entry, delete it, run again on a clean copy.

## What the verifier actually does

1. **Rebuilds the signed bytes of `manifest.json`** from the file's own fields,
   using RFC 8785 (JSON Canonicalization Scheme), and checks that they hash to
   the `manifestHash` the file claims. The claimed hash is compared, never
   trusted as an input.
2. **Checks the Ed25519 signature** over those bytes, using the key the
   manifest names itself — not "the current key". A key retired in 2031 does
   not invalidate anything signed in 2026.
3. **Reads what the key ring says about that key.** If it records the key as
   revoked, or the manifest's own creation date falls outside the key's
   validity window, that is reported as a limit (see below).
4. **Refuses development keys.** Any key whose id starts with `dev-` signs a
   fabricated corpus used to exercise the code. Such a signature is
   arithmetically valid and evidentially worthless, so the verifier fails on it
   rather than printing a reassuring "OK".
5. **Refuses a manifest whose signed `campaignId` is not its directory name.**
   The folder name is the only thing tying a manifest to a set of payloads;
   without this check, moving an authentic manifest into another campaign's
   folder would break no signature.
6. **Recomputes the Merkle root** from the leaves in `merkle.json` and compares
   it to the root inside the signed manifest. The number of leaves must equal
   the `snapshotCount` the signature covers — the tree size is taken from the
   signed manifest, never from `merkle.json`, because an input cannot
   authenticate itself.
7. **Hashes every payload file** and checks it against the leaf recorded in the
   tree. Anything else in `payloads/` is rejected: a file whose name matches no
   leaf, a file that is not `<archive-id>.json`, a subdirectory. All of it would
   be content that nothing covers, and treating it as a warning would mean that
   renaming a payload quietly removes it from verification.
8. **Cross-checks the records it can**, and **counts the ones it cannot**.
9. **Warns about any JSON field it does not recognise**, naming each one, in
   `manifest.json`, `merkle.json`, the timestamp sidecars and the key ring. A
   warning rather than a failure, so that an older copy of this program does
   not reject a newer archive — but never silence, because an unsigned field
   inside a signed file reads as authenticated to anyone who does not know
   which fields the signature covers. This matters most in the key ring: a
   revocation marker written under a name this program predates would otherwise
   have no effect on any verdict, silently.
10. **Checks that the manifests form a single chain**: a fork, two manifests
    both claiming to open the chain, or a successor created before its own
    predecessor are failures. A missing predecessor is a limit.
11. **Enumerates `tsr/` without decoding anything.**

The Merkle construction follows RFC 6962: leaves are hashed as
`SHA-256(0x00 ‖ bytes)`, internal nodes as `SHA-256(0x01 ‖ left ‖ right)`,
leaves are sorted before the tree is built, and an odd node is promoted
unchanged rather than duplicated — duplicating it is CVE-2012-2459, which makes
`{A,B,C}` and `{A,B,C,C}` produce the same root.

The archive carries the full leaf set, so no per-record inclusion proof is
needed. Recomputing the whole root proves more than an inclusion path would,
and it removes an entire class of question: there is no proof to forge, no
sibling list whose length can be inflated, no promotion marker to place at a
free position.

## What it does not prove

Stating this precisely matters more than the checks themselves. An overstated
guarantee is a worse defect than a missing one.

- **It does not prove that an AI provider produced this text.** Nothing in the
  archive comes from the provider. The archive attests what was recorded and
  that the recording has not changed since; it cannot attest that the recording
  was faithful in the first place.
- **It does not prove who holds the signing key.** `keys/public-keys.json`
  ships with the archive, so it is the publisher vouching for the publisher. It
  establishes internal consistency, not identity. To go further you need the
  key fingerprint from an independent source.
- **It does not prove when anything was written.** See below.
- **It does not prove that this copy is complete.** Nothing inside an archive
  can attest to what was removed from it before you received it. Two cases are
  reported as limits rather than failures because they are genuinely
  indistinguishable from an incomplete copy: a manifest naming a predecessor
  that is not present, and a hidden directory that was skipped. They are still
  stated on every run, because making a whole campaign disappear is the
  cheapest move available to anyone who wants history changed.
- **It does not prove that this program is the one the publisher wrote.**
  `verify.mjs` travels inside the archive and nothing signs it. Read it, or
  fetch it from a source you already trust. This is not a formality: a verifier
  distributed by the party it is meant to check is only as good as your reading
  of it, which is why it is written to be read.

### Timestamps: named, never graded

This verifier lists which token files are present and stops there. It does not
decode them — extracting a `genTime`, checking the authority's signature and
validating its certificate chain is a job of its own, and a half-written
decoder would invite exactly the confidence it has not earned.

Because nothing is decoded, **no state of `tsr/` carries a severity**: tokens
present, a claimed timestamp with no token, and no timestamp at all are all
reported as plain notes that name every file involved. A file named
`whatever.tsr` containing the words "not a token" is, to this program,
indistinguishable from a real one, so no arrangement of files in that directory
can change the class of the outcome in either direction — fabricating a token
buys nothing, deleting one costs nothing.

That this program does not decode tokens is a property of **the program**,
identical on every run, so it is stated once, in the section above, rather than
repeated per campaign. (An earlier version made every timestamp state a limit;
on a twelve-campaign archive that printed twelve identical paragraphs under an
instruction to read them, which is how a reader learns to skip the block where
the revoked key and the missing predecessor also live.)

Content that does not belong in `tsr/` at all is a different matter and remains
a failure: a stray file, a subdirectory, a sidecar describing a token this
archive does not hold.

If you decode the tokens yourself, compare the `messageImprint` inside the
token to the manifest's `manifestHash`, **never** to the Merkle root. The
manifest hash covers the root, the record count and the link to the previous
manifest at once, which is why it is what gets timestamped. Comparing against
the root would make a perfectly valid token look forged.

### A revoked or out-of-window signing key

If the key ring marks the signing key as revoked, or the manifest's signed
`createdAt` falls outside the key's `validFrom`/`validUntil` window, the run
reports a limit — not a failure.

Not a failure, because revocation means "stop signing with this key", not
"everything it ever signed is false". Retroactively invalidating a key would
destroy the archive the day a key is rotated, which is the opposite of the
goal. But not silence either: the sharper statement is that **this verifier
cannot place a signature in time**. The only date available is inside the
signed bytes, which whoever holds the key controls. Nothing here distinguishes
a manifest signed before a revocation from one forged after it. Only a decoded
timestamp token could, and this version does not decode them.

The validity window is compared against the manifest's own `createdAt`, never
against your system clock. A verdict that changes because a certificate expired
overnight is a verdict nobody can cite.

### Records whose identity and date are not authenticated

This is the most important limit, and the one most likely to be misread.

The Merkle root is built from the payload **hashes** alone. `merkle.json` also
carries, next to each leaf, that record's `archiveId` and `capturedAt` — and
the root does not cover those two fields. They are authenticated only when this
copy also holds the record's signed bytes and those bytes repeat the same two
values. That happens for archive format 2 payloads present in the copy; the
verifier cross-checks them and says so.

For every other record — a format-1 payload, which hashes only the HTTP capture
and therefore names nothing, or any record whose payload file is not in this
copy — the two fields are free. Swapping the `archiveId` of two such leaves, or
rewriting their `capturedAt`, leaves the Merkle root valid and every signature
intact.

So the verifier counts `snapshotCount` minus the number of records it actually
cross-checked, and reports the difference on every run. It proves those hashes
belong to the campaign, and it refuses to conclude which record any of them is,
or when it was captured.

The **count** is printed per campaign, because it differs and because a count
that is not what the publisher expects is the whole point. The **reasoning** is
printed once, for the whole archive, under `archive root`.

A campaign escapes this limit only when every record it holds is published *and*
in archive format 2 — then the run prints `all N record(s) are tied to signed
bytes` and nothing is left unauthenticated. That does happen, and the
publisher's own corpus is an example of it. But a payload file is only ever
written for a published record, so any campaign that held a record back, or that
predates archive format 2, reports the limit; expect it on most archives, and on
a large one expect it once per campaign. The reasoning is said once for that
reason: near-identical paragraphs repeated a dozen times under an instruction to
read them is how a reader learns to skip the block where the revoked key and the
missing predecessor also live.

Note the phrasing it uses for records with no payload file: **absent from this
copy**, not "unpublished". The archive does not authenticate which records were
published, so a deliberately withheld record and a deleted file look the same
from here.

## Why this program duplicates code

`verify.mjs` reimplements canonicalization, hashing, the Merkle tree and
signature checking by hand, even though the project already has all four. That
duplication is the point, not an oversight. A verifier that imported the
project's own modules would only establish that our code agrees with our code.
Two independent implementations that agree are evidence; if they ever disagree,
one of them is wrong, and that is exactly what we want to find out.

For the same reason it has no dependencies: it must run from a folder copied
onto a USB stick, years from now, with nothing installed.

The reasoning behind each subtle decision lives in the comments of
`verify.mjs`, not here, so that the two texts cannot drift apart. Read it: it is
the specification you need to write your own.

If you find a disagreement between this program and the archive, or between
this program and your own reimplementation, that is a finding worth reporting.
