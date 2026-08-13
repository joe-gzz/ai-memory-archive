#!/usr/bin/env node
/**
 * Independent verifier for the `archive/` file stream.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * THIS FILE DELIBERATELY DUPLICATES PROJECT CODE. DO NOT "FACTOR IT OUT".
 * ─────────────────────────────────────────────────────────────────────────
 *
 * It reimplements RFC 8785 (JCS), prefixed hashing, RFC 6962 Merkle tree
 * construction and Ed25519 verification by hand. Those are exactly the
 * computations found in `src/lib/integrity/{jcs,hash,merkle,signing}.ts`, and
 * that is the point: a verifier that imported `src/lib/` would establish
 * nothing beyond "our code agrees with our code". If the two implementations
 * ever diverge, one of them is wrong, and finding that out is precisely what
 * this file exists for. Any future review that replaces this duplication with
 * an import removes the only thing that makes the verification independent.
 *
 * The same reasoning forces **zero dependencies**. Node built-ins only
 * (`node:crypto`, `node:fs`, `node:path`). This file must run from a folder
 * copied onto a USB stick, with no `npm install`, no network, and none of the
 * rest of the repository.
 *
 * This whole directory is written in English, comments included, against the
 * project's usual convention of French comments. The exception is recorded in
 * `CLAUDE.md` with its reason: this program exists so that an unknown third
 * party can read it and reimplement it, and its specification lives in these
 * comments. Four subtleties decide whether a reimplementation is correct —
 * lowercase hex making the default sort equivalent to a byte sort, promotion
 * instead of duplication in odd levels, tree size taken from the signed
 * manifest, and the `kind` tag rather than a text match for the one flag that
 * changes a severity. None of them survive a move into the README, and two
 * texts saying the same thing would drift.
 *
 * ── The rule this program is built on ─────────────────────────────────────
 *
 *   EVERY BYTE OF THE ARCHIVE IS EITHER COVERED BY A SIGNATURE, OR NAMED IN
 *   THE REPORT.
 *
 * Very little of an archive is actually signed: the canonical bytes of each
 * manifest, and — through the Merkle root the manifest carries — the bytes of
 * each payload file. Everything else is unsigned: the key ring, the timestamp
 * tokens, the leaf metadata in `merkle.json`, this program itself. Unsigned
 * does not mean harmless. A file dropped next to genuine evidence borrows its
 * credibility, so the only defensible treatment is to enumerate the archive
 * exhaustively and say, for every entry, which of the two categories it falls
 * in. An entry that is neither verified nor mentioned is an entry the reader
 * will assume was checked.
 *
 * That rule replaced five separate patches. Earlier versions enforced it
 * inside `payloads/` only, and every place it was not enforced turned out to
 * be exploitable in the same way: a fabricated `tsr/*.tsr` bought the
 * strongest verdict, a fabricated `answers.html` sat unmentioned in a campaign
 * folder, unknown JSON fields passed in silence. Same defect, five addresses.
 *
 * ── The other design decision that shapes everything below ────────────────
 *
 * This verifier **recomputes the whole Merkle root** from the complete leaf
 * set in `merkle.json`. It never consumes an inclusion proof. That is not a
 * shortcut: it steps out of an entire malleability family. There is no proof
 * to forge, no sibling list whose length can be inflated, no promotion marker
 * to insert at a free position — the questions that cost `src/lib/integrity/
 * merkle.ts` three review rounds simply do not arise here, because nothing in
 * the archive is a proof that this program has to trust.
 *
 * ── Severity, and the one thing a verifier must never do ──────────────────
 *
 * `LIMIT` marks a check that passed while proving **less** than a hurried
 * reader would assume. It is a first-class output, not a footnote. Two rules
 * govern it, learned the hard way:
 *
 *   1. Close the invariant, not the vector. Count what was actually proven and
 *      report the remainder; never enumerate the ways it could be missing.
 *   2. A severity that fires on every legitimate run teaches the reader to
 *      ignore it — and it is the same severity the chain checks depend on. So
 *      an ordinary `.git` directory, or a leftover from an interrupted write,
 *      must not raise one. Classification is by **content**, never by a list
 *      of blessed names.
 */

import { createHash, createPublicKey, verify as verifyEd25519Bytes } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Format constants — the project's values, rewritten here
// ---------------------------------------------------------------------------

/** The only manifest format version this verifier knows how to read. */
const SUPPORTED_MANIFEST_FORMAT_VERSION = 1;

/** Record payload format versions this verifier knows how to read. */
const FORMAT_RAW_CAPTURE = 1;
const FORMAT_SELF_CONTAINED = 2;

/** Exact shape of a prefixed hash: `sha256:` then 64 lowercase hex digits. */
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

/** Prefix marking a development signing key (`src/lib/integrity/signing.ts`). */
const DEVELOPMENT_KEY_ID_PREFIX = "dev-";

/** Length of an Ed25519 signature, in bytes (RFC 8032). */
const SIGNATURE_BYTES = 64;

/** Manifest fields that enter the signed bytes, and only those. */
const SIGNED_MANIFEST_FIELDS = [
  "campaignId",
  "createdAt",
  "keyId",
  "merkleRoot",
  "previousManifestHash",
  "snapshotCount",
];

/** Every field a `manifest.json` may hold: the signed ones plus four unsigned. */
const KNOWN_MANIFEST_FIELDS = new Set([
  ...SIGNED_MANIFEST_FIELDS,
  "manifestFormatVersion",
  "isDevelopment",
  "manifestHash",
  "signature",
  "timestampedAt",
]);

const KNOWN_MERKLE_FIELDS = new Set(["campaignId", "leaves"]);
const KNOWN_LEAF_FIELDS = new Set(["archiveId", "payloadHash", "capturedAt"]);
const KNOWN_SIDECAR_FIELDS = new Set(["requestedAt", "certificateChainPem"]);

/**
 * The key ring had no known-field set at all, which meant `revoked`,
 * `status: "COMPROMISED"` or `trustedBy` passed in total silence — in the one
 * file that decides which key is worth trusting. That is the same defect as
 * dropping `revokedAt`, one file further along: a revocation marker written
 * under a name this verifier predates would simply not exist for it.
 */
const KNOWN_KEYRING_FIELDS = new Set(["keys"]);
const KNOWN_KEY_FIELDS = new Set([
  "keyId",
  "algorithm",
  "publicKey",
  "validFrom",
  "validUntil",
  "revokedAt",
  "note",
]);

/** The only entry `keys/` may hold. */
const KNOWN_KEYS_DIR_ENTRIES = new Set(["public-keys.json"]);

/** The only entries a campaign directory may hold. */
const KNOWN_CAMPAIGN_ENTRIES = new Map([
  ["manifest.json", "file"],
  ["merkle.json", "file"],
  ["payloads", "directory"],
  ["tsr", "directory"],
]);

/**
 * Entries at the archive root that are the tooling rather than the evidence.
 * They are still listed in the unsigned inventory: nothing signs them either.
 */
const TOOLING_ENTRIES = new Set(["verify.mjs", "README.md"]);

// ---------------------------------------------------------------------------
// RFC 8785 (JCS) — independent reimplementation
// ---------------------------------------------------------------------------

/**
 * Serializes a value produced by `JSON.parse` into canonical RFC 8785 JSON:
 * object keys sorted by UTF-16 code unit at every depth, numbers formatted by
 * ECMAScript's `Number::toString`, minimal string escaping.
 *
 * `Array.prototype.sort()` with no comparator **is** the UTF-16 code unit sort
 * the standard requires, and `String(n)` **is** `Number::toString`. Do not
 * replace the first with `localeCompare`, nor the second with any "readable"
 * number formatting: either change silently produces different bytes, hence a
 * different hash, hence a different verdict.
 */
function canonicalize(value) {
  if (value === null) {
    return "null";
  }
  const type = typeof value;
  if (type === "boolean") {
    return value ? "true" : "false";
  }
  if (type === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("no canonical JSON form for NaN or Infinity");
    }
    return String(value);
  }
  if (type === "string") {
    // Conformant since ES2019: minimal escaping, control characters as
    // lowercase `\u00xx` — exactly what RFC 8785 requires.
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (type === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new Error(`no canonical JSON form for a value of type ${type}`);
}

// ---------------------------------------------------------------------------
// Hashing and Merkle tree (RFC 6962) — independent reimplementation
// ---------------------------------------------------------------------------

/** `sha256:<64 lowercase hex>` over the UTF-8 bytes of a canonical string. */
function sha256PrefixedOfString(canonical) {
  return `sha256:${createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex")}`;
}

/** `sha256:<64 lowercase hex>` over bytes already read from disk. */
function sha256PrefixedOfBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/** The 32 raw bytes denoted by the 64 hex digits of a prefixed hash. */
function digestBytesOf(prefixedHash) {
  return Buffer.from(prefixedHash.slice("sha256:".length), "hex");
}

/**
 * Leaf: `SHA-256(0x00 ‖ bytes)`. Internal node:
 * `SHA-256(0x01 ‖ left ‖ right)`. Both domain tags come from RFC 6962
 * (Certificate Transparency). Without them, an internal node built from two
 * legitimate leaves could pass for a leaf of another tree, because both would
 * live in the same space of 32-byte values. The tags apply to the **bytes** of
 * the digest, never to the characters of its hexadecimal spelling.
 */
function hashLeaf(prefixedHash) {
  const digest = createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x00]), digestBytesOf(prefixedHash)]))
    .digest("hex");
  return `sha256:${digest}`;
}

function combineChildren(left, right) {
  const digest = createHash("sha256")
    .update(Buffer.concat([Buffer.from([0x01]), digestBytesOf(left), digestBytesOf(right)]))
    .digest("hex");
  return `sha256:${digest}`;
}

/**
 * Root of the tree built over a set of prefixed hashes.
 *
 * Two rules that are not implementation details:
 *
 * 1. Leaves are **sorted** before the tree is built, so the root does not
 *    depend on the order of the file. The default lexicographic sort coincides
 *    with a byte sort only because the hex is lowercase: in ASCII, digits
 *    (0x30-0x39) precede uppercase `A`-`F` (0x41-0x46), which precede
 *    lowercase `a`-`f` (0x61-0x66). A reimplementation that tolerated
 *    uppercase would get a different order, hence a different root.
 * 2. An odd-sized level **promotes** its last node unchanged rather than
 *    duplicating it. Duplication is CVE-2012-2459 (Bitcoin): it makes
 *    `{A,B,C}` and `{A,B,C,C}` produce the same root.
 */
function merkleRootOf(prefixedLeaves) {
  let level = [...prefixedLeaves].sort().map((leaf) => hashLeaf(leaf));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? combineChildren(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

// ---------------------------------------------------------------------------
// Ed25519 signature — independent reimplementation
// ---------------------------------------------------------------------------

/**
 * Verifies an Ed25519 signature (base64) over the UTF-8 bytes of a canonical
 * string, using a base64 SPKI DER public key.
 *
 * Returns `{ok, reason}` instead of throwing: corrupted input must produce a
 * verdict, not a stack trace. A verifier that crashes has concluded nothing.
 */
function verifySignature(canonicalBytes, signatureB64, publicKeyB64) {
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
  } catch {
    return { ok: false, reason: "the recorded public key is not a base64 SPKI DER key" };
  }
  if (key.asymmetricKeyType !== "ed25519") {
    return { ok: false, reason: `the recorded public key is ${String(key.asymmetricKeyType)}, not Ed25519` };
  }
  const signature = Buffer.from(signatureB64, "base64");
  if (signature.length !== SIGNATURE_BYTES) {
    return { ok: false, reason: `signature is ${signature.length} bytes, ${SIGNATURE_BYTES} expected` };
  }
  if (!verifyEd25519Bytes(null, Buffer.from(canonicalBytes, "utf8"), key, signature)) {
    return { ok: false, reason: "signature does not match the canonical bytes" };
  }
  return { ok: true, reason: null };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/**
 * Five levels:
 *
 * - `FAIL`  : a proof does not hold. Non-zero exit code.
 * - `LIMIT` : the proof holds but establishes less than assumed.
 * - `WARN`  : an inconsistency in data that nothing authenticates.
 * - `PASS`  : a check that was actually performed and succeeded.
 * - `NOTE`  : a stated fact, carrying no verdict. This is where the unsigned
 *             inventory lives: naming a file is not an accusation.
 *
 * `LIMIT` and `WARN` both suppress the unqualified success line. A summary
 * that printed "every check passed" four lines under a warning would
 * contradict the body of its own report.
 */
class Report {
  constructor() {
    this.lines = [];
    this.counts = { PASS: 0, FAIL: 0, LIMIT: 0, WARN: 0, NOTE: 0 };
  }

  /**
   * `kind` names the nature of a line when a command-line flag has to change
   * its severity. A name, never a match on the message text: someone would
   * eventually reword the message, and the flag would stop applying with
   * nothing to say so.
   */
  add(level, scope, message, kind = null) {
    this.counts[level] += 1;
    this.lines.push({ level, scope, message, kind });
  }

  pass(scope, message) {
    this.add("PASS", scope, message);
  }
  fail(scope, message, kind = null) {
    this.add("FAIL", scope, message, kind);
  }
  limit(scope, message) {
    this.add("LIMIT", scope, message);
  }
  warn(scope, message) {
    this.add("WARN", scope, message);
  }
  note(scope, message) {
    this.add("NOTE", scope, message);
  }
}

/**
 * The single place anything reaches the terminal, and therefore the single
 * place escaping can be guaranteed rather than remembered.
 *
 * It takes ONE line. Multi-line text must be printed one line at a time — see
 * `printUsage` — because a newline inside `line` is exactly what this escapes.
 */
function print(line) {
  process.stdout.write(`${forReport(line)}\n`);
}

/** Prints a multi-line block, one line at a time, so `print` can escape. */
function printBlock(text) {
  for (const line of text.split("\n")) {
    print(line);
  }
}

/**
 * Escapes the control characters of a string that came out of the archive,
 * before it is printed.
 *
 * The report is a line-oriented text format, and almost every line embeds
 * something the archive controls: a file name, a `campaignId`, a `keyId`, an
 * unknown JSON field name, a sidecar's `requestedAt`. None of it was escaped,
 * so an archive could **write its own report lines**. Measured: an otherwise
 * healthy archive whose `tsr/<authority>.json` carries a `requestedAt` with
 * embedded newlines printed two fabricated `PASS` lines about a campaign that
 * does not exist, followed by a fabricated `Result: VERIFIED — no discrepancy
 * found.` — while the real run was still in progress. Anyone reading the output,
 * and every script that greps it for a verdict, is defeated by that. File names
 * are the same vector wherever POSIX allows a newline in one, which is
 * everywhere, and the archive is published as a Git repository that gets cloned
 * on POSIX.
 *
 * Escaping is applied by `print` itself, so it cannot be forgotten. It was
 * applied at three chosen call sites first, and three OTHER `print` calls in
 * this same file were then found unescaped — the archive root echoed back on a
 * missing directory, the same root inside the NOTHING VERIFIED verdict, and a
 * crash stack. The justification for a single choke point had itself been
 * forgotten three times in the file that wrote it down, which settles where the
 * choke point belongs.
 *
 * The escaped set is control characters plus the bidirectional formatting
 * characters (U+202A..U+202E, U+2066..U+2069, U+200E/F, U+061C). Those forge no
 * line, but U+202E reverses the visible order of the rest of its line in every
 * terminal — Trojan Source, CVE-2021-42574 — so a file name carrying one makes
 * a reader read something other than what is written.
 *
 * What is deliberately NOT bounded is length. Truncating would break the axiom
 * for the lines that NAME things — the inventory, the list of stray manifests —
 * and those are the ones that grow. The scalars that name nothing (`keyId`, a
 * sidecar's `requestedAt`, an unknown field name) could be capped without
 * touching the axiom, and they are the only unbounded ones: a path component is
 * capped at 255 bytes by the operating system. Measured, a 200 kB field yields
 * one 200 kB line and the verdict line stays unique and last, so this is noise,
 * never a false conclusion.
 */
function forReport(value) {
  return String(value).replace(
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g,
    (character) => `\\u${character.codePointAt(0).toString(16).padStart(4, "0")}`,
  );
}

// ---------------------------------------------------------------------------
// File reading
// ---------------------------------------------------------------------------

/**
 * The one sentence this layer exists to make true:
 *
 *   NO PATH THIS PROGRAM OPENS EVER TRAVERSES A LINK.
 *
 * Naming a link is not refusing it, and that distinction cost a whole review
 * round. An earlier version described links correctly in the report and then
 * read straight through them, because `readFile`, `readdir` and `stat` all
 * resolve. The same run printed `FAIL … is a symbolic link or junction where
 * the archive format defines a file` **and** `PASS … Ed25519 signature valid`
 * over bytes that were not in the archive. Worse, a `keys/` junction was the
 * one case with no failure at all: the file that decides which key is trusted
 * was read from outside the archive while the report said "not followed", and
 * the run exited 0.
 *
 * So every read goes through `inspectUnder`, which walks the components of a
 * path one at a time with `lstat` — never `stat` — and stops at the first
 * component that is a link. `scanForManifests` is the single exception and it
 * is safe for a structural reason, stated at its definition: it only ever
 * descends into entries a `Dirent` classified as real directories.
 */
const LINK_REFUSAL = "a symbolic link or junction, which this verifier never follows";

/**
 * Walks `parts` under `base` component by component with `lstat`.
 *
 * Returns the kind of the last component — `"file"`, `"directory"`, `"other"`,
 * `"missing"` — or `"link"` as soon as any component is one, or an error code.
 * `at` names the component that stopped the walk, so a caller can say which.
 */
async function inspectUnder(base, parts) {
  let current = base;
  for (const [index, part] of parts.entries()) {
    current = path.join(current, part);
    const at = parts.slice(0, index + 1).join("/");
    let info;
    try {
      info = await lstat(current);
    } catch (cause) {
      if (cause.code === "ENOENT" || cause.code === "ENOTDIR") {
        return { kind: "missing", at };
      }
      return { kind: cause.code ?? "EUNKNOWN", at };
    }
    if (info.isSymbolicLink()) {
      return { kind: "link", at };
    }
    if (index < parts.length - 1) {
      if (!info.isDirectory()) {
        // A non-directory in the middle of the path: the rest cannot exist.
        return { kind: "missing", at };
      }
      continue;
    }
    return { kind: info.isDirectory() ? "directory" : info.isFile() ? "file" : "other", at };
  }
  return { kind: "directory", at: "" };
}

/**
 * Reads a JSON file at `parts` under `base`, refusing to traverse a link.
 * Returns `{ok:true, value}` or `{ok:false, reason}`.
 */
async function readJson(base, parts) {
  const found = await inspectUnder(base, parts);
  if (found.kind === "link") {
    return {
      ok: false,
      reason:
        `cannot be read: "${found.at}" is ${LINK_REFUSAL}. Whatever it points at is not part of this ` +
        "archive, so nothing here was read and nothing here is covered",
    };
  }
  if (found.kind === "directory") {
    return { ok: false, reason: "cannot be read: it is a directory, not a file" };
  }
  if (found.kind === "other") {
    return { ok: false, reason: `cannot be read: "${found.at}" is neither a file nor a directory` };
  }
  if (found.kind === "missing") {
    return { ok: false, reason: "cannot be read (ENOENT)" };
  }
  if (found.kind !== "file") {
    return { ok: false, reason: `cannot be read (${found.kind})` };
  }
  let text;
  try {
    text = await readFile(path.join(base, ...parts), "utf8");
  } catch (cause) {
    return { ok: false, reason: `cannot be read (${cause.code ?? cause.message})` };
  }
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (cause) {
    return { ok: false, reason: `is not valid JSON (${cause.message})` };
  }
}

/**
 * Directory entries, as `{entries, missing, error}`.
 *
 * Never throws. An earlier version rethrew anything that was not `ENOENT` or
 * `ENOTDIR`, so a single unreadable entry — a locked `.git` object, a junction,
 * a permission-restricted `docs/` — turned a perfectly valid archive into a
 * stack trace and exit 2. That is the `.git` false positive again, one layer
 * down: the reader is told the archive could not be checked when the truth is
 * that one directory could not be opened. Callers inventory the entry and
 * raise a limit that names it.
 */
async function readDirEntriesOfKnownDirectory(dir) {
  try {
    return { entries: await readdir(dir, { withFileTypes: true }), missing: false, error: null };
  } catch (cause) {
    if (cause.code === "ENOENT" || cause.code === "ENOTDIR") {
      return { entries: null, missing: true, error: null };
    }
    return { entries: null, missing: false, error: cause.code ?? cause.message };
  }
}

/**
 * Directory entries at `parts` under `base`, refusing to traverse a link.
 * Same `{entries, missing, error}` shape, and the same promise never to throw.
 */
async function readDirEntries(base, parts) {
  const found = await inspectUnder(base, parts);
  if (found.kind === "link") {
    return { entries: null, missing: false, error: `"${found.at}" is ${LINK_REFUSAL}` };
  }
  if (found.kind === "missing" || found.kind === "file" || found.kind === "other") {
    // Absent, or present as something that is not a directory: the caller's
    // "missing" branch is the right one, and the type mismatch is reported
    // separately by whoever enumerated the parent.
    return { entries: null, missing: true, error: null };
  }
  if (found.kind !== "directory") {
    return { entries: null, missing: false, error: found.kind };
  }
  return readDirEntriesOfKnownDirectory(path.join(base, ...parts));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function byName(a, b) {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

/**
 * What a directory entry is, decided from the entry itself and **never** from
 * `stat()`.
 *
 * `stat()` follows links, and following a link is the one traversal this
 * program must refuse: a link inside an archive can point anywhere on the
 * machine that happens to hold the copy, or back at one of its own parents, so
 * following it would either hash bytes that are not in the archive or walk in
 * circles. Refusing to follow is only half the rule though, and the missing
 * half was a hole: `entry.isDirectory()` is FALSE for a junction and for a
 * symbolic link, so any classification written as "a directory, otherwise a
 * plain file" drops them on the floor. A chain tip moved out of the tree and
 * replaced by a junction (`mklink /J`, no administrator rights required; a
 * symlink that `git clone` restores as-is on POSIX) then vanished from the
 * report completely, while the inventory printed the positive claim "no
 * manifest.json anywhere inside" about the very directory holding it — and the
 * run ended on the strongest verdict available. Never followed, always named.
 */
async function classifyEntry(dir, entry) {
  if (entry.isDirectory()) {
    return { kind: "directory", description: "a directory" };
  }
  if (entry.isFile()) {
    return { kind: "file", description: "a file" };
  }
  if (entry.isSymbolicLink()) {
    return { kind: "link", description: "a symbolic link or junction" };
  }
  if (entry.isFIFO()) {
    return { kind: "other", description: "a FIFO" };
  }
  if (entry.isSocket()) {
    return { kind: "other", description: "a socket" };
  }
  if (entry.isBlockDevice()) {
    return { kind: "other", description: "a block device" };
  }
  if (entry.isCharacterDevice()) {
    return { kind: "other", description: "a character device" };
  }
  // `UV_DIRENT_UNKNOWN`: `readdir` fills the type from `d_type`, which several
  // NFS and FUSE mounts leave empty — every predicate above then answers false.
  // Treating that as "not followable" refused EVERY entry of a healthy archive
  // and ended the run on NOTHING VERIFIED, a total refusal in exactly the
  // portable deployment this program is written for. `lstat` is the fallback,
  // and it is `lstat` and never `stat`: the question is what the entry IS, not
  // what it points at.
  try {
    const info = await lstat(path.join(dir, entry.name));
    if (info.isSymbolicLink()) {
      return { kind: "link", description: "a symbolic link or junction" };
    }
    if (info.isDirectory()) {
      return { kind: "directory", description: "a directory" };
    }
    if (info.isFile()) {
      return { kind: "file", description: "a file" };
    }
    return { kind: "other", description: "neither a file nor a directory" };
  } catch (cause) {
    return { kind: "other", description: `an entry lstat could not describe (${cause.code ?? "EUNKNOWN"})` };
  }
}

/**
 * Reports any field this verifier does not know about, naming each one.
 *
 * A warning rather than a failure, deliberately: an archive written by a newer
 * version of the project may legitimately carry fields this copy predates, and
 * refusing them would make old verifiers reject valid future archives. But
 * silence is not an option either — an unsigned field sitting inside a signed
 * file reads as authenticated to anyone who does not know which fields the
 * signature covers.
 */
function reportUnknownFields(report, scope, object, known, what) {
  const unknown = Object.keys(object).filter((key) => !known.has(key)).sort();
  if (unknown.length === 0) {
    return;
  }
  const reinstated = unknown.filter((key) => key === "merkleRoot" || key === "snapshotCount");
  report.warn(
    scope,
    `${what} carries ${unknown.length} field(s) this verifier does not know and NOTHING authenticates: ` +
      `${unknown.join(", ")}. They were ignored.` +
      (reinstated.length > 0
        ? ` Note that ${reinstated.join(" and ")} were deliberately removed from this file by the archive ` +
          "writer, precisely so that no reader could take an unauthenticated copy of them for the signed " +
          "one: the authenticated values live in manifest.json."
        : ""),
  );
}

// ---------------------------------------------------------------------------
// keys/public-keys.json
// ---------------------------------------------------------------------------

/**
 * Loads the key ring as a `Map` from `keyId` to its full record.
 *
 * This file is **not** an authority: it is distributed with the archive, so by
 * the same party as the archive. It lets you observe that a signature answers
 * to the key a manifest names; it does not establish that the key belongs to
 * anyone.
 *
 * `validFrom`, `validUntil`, `revokedAt` and `note` are kept, not dropped. An
 * earlier version read only the algorithm and the key material, so a manifest
 * signed by a key the ring itself marked `revoked` — with a note reading
 * "COMPROMISED" — collected the strongest verdict. The objection that the ring
 * is unauthenticated does not hold: `timestampedAt` is unauthenticated too and
 * is already read to raise a limit. Unauthenticated evidence cannot condemn,
 * but it can and must prevent a claim of full verification.
 */
async function loadPublicKeys(root, report) {
  const parsed = await readJson(root, ["keys", "public-keys.json"]);
  if (!parsed.ok) {
    report.fail("keys/public-keys.json", parsed.reason);
    return new Map();
  }
  const entries = isPlainObject(parsed.value) && Array.isArray(parsed.value.keys) ? parsed.value.keys : null;
  if (entries === null) {
    report.fail("keys/public-keys.json", 'does not hold a "keys" array');
    return new Map();
  }

  reportUnknownFields(report, "keys/public-keys.json", parsed.value, KNOWN_KEYRING_FIELDS, "the key ring");

  const keys = new Map();
  const unknownKeyFields = new Set();
  for (const entry of entries) {
    if (!isPlainObject(entry) || typeof entry.keyId !== "string" || typeof entry.publicKey !== "string") {
      report.warn("keys/public-keys.json", "an entry has no keyId/publicKey pair and was ignored");
      continue;
    }
    for (const field of Object.keys(entry)) {
      if (!KNOWN_KEY_FIELDS.has(field)) {
        unknownKeyFields.add(field);
      }
    }
    if (keys.has(entry.keyId)) {
      report.fail("keys/public-keys.json", `key "${entry.keyId}" is listed twice with no way to tell which one signed`);
      continue;
    }
    keys.set(entry.keyId, {
      algorithm: entry.algorithm,
      publicKey: entry.publicKey,
      validFrom: typeof entry.validFrom === "string" ? entry.validFrom : null,
      validUntil: typeof entry.validUntil === "string" ? entry.validUntil : null,
      revokedAt: typeof entry.revokedAt === "string" ? entry.revokedAt : null,
      note: typeof entry.note === "string" ? entry.note : null,
    });
  }
  if (unknownKeyFields.size > 0) {
    report.warn(
      "keys/public-keys.json",
      `key entries carry field(s) this verifier does not know: ${[...unknownKeyFields].sort().join(", ")}. ` +
        "They were ignored. This is the file that decides which key is trusted, so a revocation or status " +
        "marker written under a name this verifier predates would have no effect on any verdict below.",
    );
  }
  report.note("keys/public-keys.json", `${keys.size} public key(s) loaded`);
  return keys;
}

/**
 * Names everything in `keys/` that is not the key ring itself.
 *
 * `keys/` used to be the one directory whose contents were never enumerated:
 * `entry.name === "keys"` was tested before anything else and the walk moved
 * on, so `keys/answers.html` produced a report byte-for-byte identical to a
 * healthy archive's — and a mid-chain campaign renamed `keys/2026-07-01/`
 * became indistinguishable from a deleted one, while sitting there readable.
 * A name test at the root, which is exactly the construction this program
 * claims not to use.
 */
async function reportUnexpectedKeyRingEntries(root, report) {
  const { entries, error } = await readDirEntries(root, ["keys"]);
  if (error !== null) {
    report.limit("keys/", `could not be read (${error}): its contents were neither verified nor listed`);
    return;
  }
  for (const entry of entries === null ? [] : [...entries].sort(byName)) {
    const { kind } = await classifyEntry(path.join(root, "keys"), entry);
    if (kind === "file" && KNOWN_KEYS_DIR_ENTRIES.has(entry.name)) {
      continue;
    }
    report.fail(
      `keys/${entry.name}`,
      "unexpected entry: keys/ holds public-keys.json and nothing else. Nothing in this archive covers it, " +
        "and a directory here is a place a campaign can be hidden in plain sight",
    );
  }
}

/**
 * States what the key ring says about the key that signed this manifest.
 *
 * Every case is a limit, never a failure, and the reason is a rule of the
 * project: revocation says "stop signing with this one", not "everything it
 * ever signed is false". Retroactively invalidating a key would destroy the
 * archive the day a key is rotated, which is the opposite of the goal.
 *
 * What can be said is sharper, and it is worth saying: this verifier cannot
 * place the signature in time. `createdAt` is inside the signed bytes, so a
 * holder of a leaked key can write any date there. Only a timestamp token
 * could settle whether a manifest was signed before or after a revocation, and
 * this verifier does not decode them.
 *
 * The validity window is compared against the manifest's own signed
 * `createdAt`, never against the current clock. A verifier whose verdict
 * changes because a certificate expired overnight is a verifier nobody can
 * cite.
 */
function reportKeyStatus(scope, keyId, key, createdAt, report) {
  if (key.revokedAt !== null) {
    report.limit(
      scope,
      `the key ring says key "${keyId}" was REVOKED at ${key.revokedAt}` +
        (key.note === null ? "" : ` (note: ${JSON.stringify(key.note)})`) +
        ". The signature is arithmetically valid, but this verifier cannot place it in time: the only date " +
        "available is inside the signed bytes, which a holder of the key controls. Nothing here distinguishes " +
        "a manifest signed before the revocation from one forged after it.",
    );
  }

  const signedAt = Date.parse(createdAt);
  if (Number.isNaN(signedAt)) {
    return;
  }
  const from = key.validFrom === null ? Number.NaN : Date.parse(key.validFrom);
  const until = key.validUntil === null ? Number.NaN : Date.parse(key.validUntil);
  if (!Number.isNaN(from) && signedAt < from) {
    report.limit(
      scope,
      `the manifest claims to be created at ${createdAt}, before key "${keyId}" became valid ` +
        `(${key.validFrom}). One of the two statements is false, and neither is authenticated by anything ` +
        "outside this archive.",
    );
  }
  if (!Number.isNaN(until) && signedAt > until) {
    report.limit(
      scope,
      `the manifest claims to be created at ${createdAt}, after key "${keyId}" stopped being valid ` +
        `(${key.validUntil}). One of the two statements is false, and neither is authenticated by anything ` +
        "outside this archive.",
    );
  }
}

// ---------------------------------------------------------------------------
// manifest.json
// ---------------------------------------------------------------------------

/**
 * Verifies `manifest.json` and returns what its signature **authenticates**,
 * or `null` if nothing can be.
 *
 * The order matters: rebuild the canonical bytes from the file's own fields,
 * recompute the hash, then verify the signature over those bytes. The
 * `manifestHash` written in the file is never trusted as an input — it is only
 * ever compared against.
 */
async function verifyManifest(root, campaignId, keys, report) {
  const scope = `${campaignId}/manifest.json`;
  const parsed = await readJson(root, [campaignId, "manifest.json"]);
  if (!parsed.ok) {
    report.fail(scope, parsed.reason);
    return null;
  }
  const manifest = parsed.value;
  if (!isPlainObject(manifest)) {
    report.fail(scope, "is not a JSON object");
    return null;
  }

  if (manifest.manifestFormatVersion !== SUPPORTED_MANIFEST_FORMAT_VERSION) {
    report.fail(
      scope,
      `manifestFormatVersion is ${JSON.stringify(manifest.manifestFormatVersion)}; ` +
        `this verifier only knows version ${SUPPORTED_MANIFEST_FORMAT_VERSION} and refuses to guess`,
    );
    return null;
  }

  // Shape of the signed fields. A missing field, or one of another type, would
  // produce canonical bytes that are not the bytes that were signed.
  const shapeErrors = [];
  for (const field of SIGNED_MANIFEST_FIELDS) {
    if (!Object.hasOwn(manifest, field)) {
      shapeErrors.push(`"${field}" is missing`);
    }
  }
  if (typeof manifest.campaignId !== "string") shapeErrors.push('"campaignId" is not a string');
  if (typeof manifest.createdAt !== "string" || Number.isNaN(Date.parse(manifest.createdAt))) {
    // A creation date that cannot be read would silently switch off the chain
    // ordering check further down — the defect class this file keeps closing.
    shapeErrors.push('"createdAt" is not a readable instant');
  }
  if (typeof manifest.keyId !== "string") shapeErrors.push('"keyId" is not a string');
  if (typeof manifest.merkleRoot !== "string" || !HASH_PATTERN.test(manifest.merkleRoot)) {
    shapeErrors.push('"merkleRoot" is not a sha256:<64 lowercase hex> hash');
  }
  if (manifest.previousManifestHash !== null && !HASH_PATTERN.test(String(manifest.previousManifestHash))) {
    shapeErrors.push('"previousManifestHash" is neither null nor a sha256:<64 lowercase hex> hash');
  }
  if (!Number.isSafeInteger(manifest.snapshotCount) || manifest.snapshotCount < 1) {
    shapeErrors.push('"snapshotCount" is not a safe integer of at least 1');
  }
  if (typeof manifest.manifestHash !== "string" || !HASH_PATTERN.test(manifest.manifestHash)) {
    shapeErrors.push('"manifestHash" is not a sha256:<64 lowercase hex> hash');
  }
  if (typeof manifest.signature !== "string") shapeErrors.push('"signature" is not a string');
  if (shapeErrors.length > 0) {
    report.fail(scope, `malformed manifest: ${shapeErrors.join("; ")}`);
    return null;
  }

  reportUnknownFields(report, scope, manifest, KNOWN_MANIFEST_FIELDS, "manifest.json");

  // The directory name is the only thing tying a manifest to a set of
  // payloads; `campaignId` sits in the signed bytes precisely so that moving a
  // manifest from one folder to another shows.
  if (manifest.campaignId !== campaignId) {
    report.fail(
      scope,
      `signed campaignId "${manifest.campaignId}" does not match the directory name "${campaignId}": ` +
        "this manifest belongs to another campaign",
    );
    return null;
  }

  let canonicalBytes;
  try {
    canonicalBytes = canonicalize({
      manifestFormatVersion: SUPPORTED_MANIFEST_FORMAT_VERSION,
      campaignId: manifest.campaignId,
      createdAt: manifest.createdAt,
      keyId: manifest.keyId,
      merkleRoot: manifest.merkleRoot,
      previousManifestHash: manifest.previousManifestHash,
      snapshotCount: manifest.snapshotCount,
    });
  } catch (cause) {
    report.fail(scope, `canonical bytes cannot be rebuilt: ${cause.message}`);
    return null;
  }

  const recomputedHash = sha256PrefixedOfString(canonicalBytes);
  if (recomputedHash !== manifest.manifestHash) {
    report.fail(
      scope,
      `rebuilt canonical bytes hash to ${recomputedHash} but the file claims ${manifest.manifestHash}`,
    );
    return null;
  }
  report.pass(scope, "canonical bytes rebuilt from the file itself; manifestHash matches");

  const key = keys.get(manifest.keyId);
  if (key === undefined) {
    report.fail(
      scope,
      `no public key "${manifest.keyId}" in keys/public-keys.json: the signature cannot be checked, ` +
        "which is not the same thing as a bad signature",
    );
    return null;
  }
  if (key.algorithm !== "ed25519") {
    report.fail(scope, `key "${manifest.keyId}" is registered as ${String(key.algorithm)}; only ed25519 is verifiable here`);
    return null;
  }

  const verdict = verifySignature(canonicalBytes, manifest.signature, key.publicKey);
  if (!verdict.ok) {
    report.fail(scope, `Ed25519 signature rejected: ${verdict.reason}`);
    return null;
  }
  report.pass(scope, `Ed25519 signature valid under key "${manifest.keyId}"`);
  reportKeyStatus(scope, manifest.keyId, key, manifest.createdAt, report);

  // `isDevelopment` is NOT in the signed bytes: it is recomputed from the
  // `keyId`, which is. The file's field is compared only to point out that it
  // lies, never to decide anything.
  const isDevelopmentKey = manifest.keyId.startsWith(DEVELOPMENT_KEY_ID_PREFIX);
  if (typeof manifest.isDevelopment === "boolean" && manifest.isDevelopment !== isDevelopmentKey) {
    report.warn(
      scope,
      `the unsigned "isDevelopment" field says ${manifest.isDevelopment} while key "${manifest.keyId}" says ` +
        `${isDevelopmentKey}; only the key id is authenticated`,
    );
  }

  return {
    campaignId: manifest.campaignId,
    createdAt: manifest.createdAt,
    keyId: manifest.keyId,
    isDevelopmentKey,
    merkleRoot: manifest.merkleRoot,
    previousManifestHash: manifest.previousManifestHash,
    snapshotCount: manifest.snapshotCount,
    manifestHash: manifest.manifestHash,
    timestampedAt: manifest.timestampedAt ?? null,
  };
}

// ---------------------------------------------------------------------------
// merkle.json
// ---------------------------------------------------------------------------

/**
 * Verifies `merkle.json` against the **already authenticated** manifest, and
 * returns the `archiveId` -> leaf table, or `null`.
 *
 * The tree size comes from `manifest.snapshotCount`, never from `merkle.json`:
 * an input cannot authenticate itself. That is also why `merkle.json`
 * deliberately carries neither the root nor the count, and why seeing either
 * of them reappear here raises a warning.
 *
 * `capturedAt` is **required** on every leaf, and its absence is a failure
 * rather than a skipped check. A control that an omission switches off is the
 * same defect class as the gap the control exists to close.
 */
async function verifyMerkleFile(root, authenticated, report) {
  const scope = `${authenticated.campaignId}/merkle.json`;
  const parsed = await readJson(root, [authenticated.campaignId, "merkle.json"]);
  if (!parsed.ok) {
    report.fail(scope, parsed.reason);
    return null;
  }
  const file = parsed.value;
  if (!isPlainObject(file) || !Array.isArray(file.leaves)) {
    report.fail(scope, 'does not hold a "leaves" array');
    return null;
  }
  if (file.campaignId !== authenticated.campaignId) {
    report.fail(scope, `campaignId "${String(file.campaignId)}" does not match the signed manifest`);
    return null;
  }
  reportUnknownFields(report, scope, file, KNOWN_MERKLE_FIELDS, "merkle.json");

  const byArchiveId = new Map();
  const hashes = [];
  const seenHashes = new Set();
  const unknownLeafFields = new Set();
  for (const [index, leaf] of file.leaves.entries()) {
    if (!isPlainObject(leaf) || typeof leaf.archiveId !== "string" || typeof leaf.payloadHash !== "string") {
      report.fail(scope, `leaf #${index} has no archiveId/payloadHash pair`);
      return null;
    }
    if (typeof leaf.capturedAt !== "string") {
      report.fail(
        scope,
        `leaf #${index} ("${leaf.archiveId}") has no capturedAt string; a leaf without one would silently ` +
          "switch off the cross-check that compares it against the signed bytes",
      );
      return null;
    }
    if (!HASH_PATTERN.test(leaf.payloadHash)) {
      report.fail(scope, `leaf #${index} ("${leaf.archiveId}") has a payloadHash that is not sha256:<64 lowercase hex>`);
      return null;
    }
    if (byArchiveId.has(leaf.archiveId)) {
      report.fail(scope, `archiveId "${leaf.archiveId}" appears twice`);
      return null;
    }
    if (seenHashes.has(leaf.payloadHash)) {
      report.fail(scope, `payloadHash ${leaf.payloadHash} appears twice, which makes the tree ambiguous`);
      return null;
    }
    for (const key of Object.keys(leaf)) {
      if (!KNOWN_LEAF_FIELDS.has(key)) {
        unknownLeafFields.add(key);
      }
    }
    seenHashes.add(leaf.payloadHash);
    byArchiveId.set(leaf.archiveId, { payloadHash: leaf.payloadHash, capturedAt: leaf.capturedAt });
    hashes.push(leaf.payloadHash);
  }
  if (unknownLeafFields.size > 0) {
    // Aggregated across leaves: one line per unknown name, not per occurrence.
    report.warn(
      scope,
      `leaves carry field(s) this verifier does not know and NOTHING authenticates: ` +
        `${[...unknownLeafFields].sort().join(", ")}. They were ignored.`,
    );
  }

  if (hashes.length !== authenticated.snapshotCount) {
    report.fail(
      scope,
      `holds ${hashes.length} leaf/leaves while the signed manifest attests ${authenticated.snapshotCount}`,
    );
    return null;
  }
  report.pass(scope, `${hashes.length} leaf/leaves, matching the signed snapshotCount`);

  const recomputedRoot = merkleRootOf(hashes);
  if (recomputedRoot !== authenticated.merkleRoot) {
    report.fail(
      scope,
      `recomputed Merkle root ${recomputedRoot} does not match the signed root ${authenticated.merkleRoot}`,
    );
    return null;
  }
  report.pass(scope, "recomputed Merkle root matches the signed merkleRoot");

  return byArchiveId;
}

// ---------------------------------------------------------------------------
// payloads/
// ---------------------------------------------------------------------------

/**
 * Verifies every payload file against the leaf that the tree — hence the
 * signature — covers, and reports how many records could **not** be tied to
 * signed bytes.
 *
 * Not every leaf has a file: the archive carries the hash of every record in
 * the campaign but the **content** of only some of them. A file with no
 * matching leaf, on the other hand, is content nothing covers, and so is any
 * other entry in this directory: a stray `.txt`, a `.json.bak`, a
 * subdirectory. Treating them as warnings would mean that renaming a payload
 * quietly removes it from verification, which is a rename away from deleting
 * evidence.
 *
 * Successes are **aggregated** into one line per campaign; failures stay named
 * file by file. A campaign holds dozens of payloads, and one green line each
 * would bury the only line that matters on the day one of them fails.
 */
async function verifyPayloads(root, authenticated, leaves, report) {
  const campaignId = authenticated.campaignId;
  const summaryScope = `${campaignId}/payloads/`;
  const payloadsDir = path.join(root, campaignId, "payloads");
  const { entries, error } = await readDirEntries(root, [campaignId, "payloads"]);
  if (error !== null) {
    report.limit(summaryScope, `could not be read (${error}): no payload file in this campaign was verified`);
  }
  if (entries === null) {
    return { covered: 0, crossChecked: 0, rawCaptureFormat: 0, filePresent: 0 };
  }

  let covered = 0;
  let crossChecked = 0;
  let rawCaptureFormat = 0;
  let filePresent = 0;

  for (const entry of [...entries].sort(byName)) {
    const scope = `${campaignId}/payloads/${entry.name}`;
    const { kind } = await classifyEntry(payloadsDir, entry);
    if (kind === "directory") {
      report.fail(scope, "unexpected directory: nothing in the signed tree covers a directory here");
      continue;
    }
    if (kind !== "file" || !entry.name.endsWith(".json")) {
      report.fail(
        scope,
        "unexpected entry: only <archiveId>.json payload files belong here, and nothing in the signed tree " +
          "covers this one",
      );
      continue;
    }
    const archiveId = entry.name.slice(0, -".json".length);

    const leaf = leaves.get(archiveId);
    if (leaf === undefined) {
      report.fail(scope, "no leaf in merkle.json carries this archiveId: nothing in the signed tree covers this file");
      continue;
    }
    // Counted before the hash is checked, and separately from `covered`: the
    // sentence this header calls the most important in the document used to
    // say "no payload file in this copy" about a file that was right there and
    // simply did not hash to its leaf.
    filePresent += 1;

    // The last unguarded read in the file layer, and it cost the whole report:
    // a payload the operating system refused (a deny ACE, a file larger than a
    // Buffer, a file removed between reading the directory and reading it)
    // produced a stack trace and exit 2, throwing away every line collected so
    // far — including, in the archive it was measured on, the limit naming a
    // hidden campaign. Word for word the defect `printReport` says it fixed.
    // A limit rather than a failure, consistent with every other read this
    // program cannot perform: not being able to check something is not the same
    // as having checked it and found it wrong. `filePresent` is incremented
    // above, before this point, so the file is never described as absent.
    let bytes;
    try {
      bytes = await readFile(path.join(payloadsDir, entry.name));
    } catch (cause) {
      report.limit(
        scope,
        `could not be read (${cause.code ?? cause.message}), so its bytes were never compared to the leaf ` +
          "the signed tree records for them: this file is present and unverified",
      );
      continue;
    }
    const computedHash = sha256PrefixedOfBytes(bytes);
    if (computedHash !== leaf.payloadHash) {
      report.fail(scope, `bytes hash to ${computedHash} but the signed tree records ${leaf.payloadHash}`);
      continue;
    }
    covered += 1;

    // From here the bytes are proven. What remains is knowing WHAT THEY ARE:
    // a format-2 payload names itself, a format-1 payload does not.
    let parsedPayload;
    try {
      parsedPayload = JSON.parse(bytes.toString("utf8"));
    } catch (cause) {
      report.fail(scope, `bytes match the signed tree but are not valid JSON (${cause.message})`);
      continue;
    }
    if (!isPlainObject(parsedPayload)) {
      report.fail(scope, "bytes match the signed tree but are not a JSON object");
      continue;
    }

    const formatVersion = Object.hasOwn(parsedPayload, "archiveFormatVersion")
      ? parsedPayload.archiveFormatVersion
      : FORMAT_RAW_CAPTURE;

    if (formatVersion === FORMAT_SELF_CONTAINED) {
      if (parsedPayload.archiveId !== archiveId) {
        report.fail(
          scope,
          `the payload names itself "${String(parsedPayload.archiveId)}" but the file is named "${archiveId}": ` +
            "the record identity in the signed bytes contradicts the filename",
        );
        continue;
      }
      // Malleability check: proven bytes must ALREADY be the canonical form of
      // what they contain. Otherwise two different spellings of the same
      // content could coexist, only one of which is in the tree.
      let recanonicalized;
      try {
        recanonicalized = canonicalize(parsedPayload);
      } catch (cause) {
        report.fail(scope, `payload cannot be re-canonicalized: ${cause.message}`);
        continue;
      }
      if (recanonicalized !== bytes.toString("utf8")) {
        report.fail(scope, "payload bytes are not in RFC 8785 canonical form");
        continue;
      }
      // `merkle.json` repeats the capture date next to the leaf, where nothing
      // authenticates it. In format 2 the date is ALSO in the signed bytes, so
      // it gets cross-checked rather than left as a free copy sitting beside a
      // proven one.
      const signedCapturedAt = isPlainObject(parsedPayload.capture) ? parsedPayload.capture.capturedAt : undefined;
      if (signedCapturedAt !== leaf.capturedAt) {
        report.fail(
          scope,
          `merkle.json records capturedAt ${JSON.stringify(leaf.capturedAt)} for this record while the signed ` +
            `bytes say ${JSON.stringify(signedCapturedAt)}`,
        );
        continue;
      }
      crossChecked += 1;
      continue;
    }

    if (formatVersion === FORMAT_RAW_CAPTURE) {
      rawCaptureFormat += 1;
      continue;
    }

    report.fail(scope, `archiveFormatVersion ${JSON.stringify(formatVersion)} is unknown to this verifier`);
  }

  if (covered > 0) {
    report.pass(
      summaryScope,
      `${covered} payload file(s) hash to the leaf the signed tree records for them`,
    );
  }
  if (crossChecked > 0) {
    report.pass(
      summaryScope,
      `${crossChecked} of them are in archive format 2 and name their own archiveId and capture date inside ` +
        "the signed bytes; both match the filename and the leaf metadata in merkle.json",
    );
  }
  return { covered, crossChecked, rawCaptureFormat, filePresent };
}

/**
 * States, per campaign, how many records could not be tied to signed bytes.
 *
 * This is the invariant, and the reason it is computed here rather than inside
 * the loop above: a record's identity and capture date are authenticated **if
 * and only if** this copy holds signed bytes that repeat them. Whether they
 * are missing because the record is in archive format 1, because its payload
 * was never published, or because someone deleted the file, is irrelevant to
 * what can be concluded. Counting `snapshotCount - crossChecked` reports all
 * three at once and cannot be defeated by a case nobody thought of.
 */
function reportUnlinkedRecords(authenticated, tally, report) {
  const scope = `${authenticated.campaignId}/`;
  const unlinked = authenticated.snapshotCount - tally.crossChecked;
  if (unlinked <= 0) {
    report.pass(
      scope,
      `all ${authenticated.snapshotCount} record(s) are tied to signed bytes that repeat their archiveId and ` +
        "capture date: nothing in this campaign rests on unauthenticated leaf metadata",
    );
    return 0;
  }

  const withoutBytes = authenticated.snapshotCount - tally.filePresent;
  const reasons = [];
  if (tally.rawCaptureFormat > 0) {
    reasons.push(
      `${tally.rawCaptureFormat} in archive format 1, which hashes only the HTTP capture and therefore carries ` +
        "neither an archiveId nor a capture date inside the signed bytes",
    );
  }
  if (withoutBytes > 0) {
    reasons.push(
      `${withoutBytes} with no payload file in this copy — the archive does NOT authenticate which records were ` +
        "published, so this verifier cannot tell a deliberately withheld record from a deleted file",
    );
  }
  // Everything the two named reasons do not account for. Without this the
  // sentence could end on an empty pair of brackets, in the single most
  // important line of a document written for strangers.
  const otherwise = unlinked - tally.rawCaptureFormat - withoutBytes;
  if (otherwise > 0) {
    // "failed a check" was too narrow once an unreadable payload became a
    // limit rather than a crash: the file is present, nothing was proven wrong
    // about it, and nothing was proven right either.
    reasons.push(`${otherwise} whose payload file is present but was not cross-checked, for a reason reported above`);
  }

  report.limit(
    scope,
    `${unlinked} of ${authenticated.snapshotCount} record(s) have an archiveId and a capture date that only ` +
      `appear as leaf metadata in merkle.json: ${reasons.join("; ")}. What that allows and forbids you to ` +
      'conclude is stated once, under "archive root", below.',
  );
  return unlinked;
}

/**
 * States, **once for the whole archive**, what an unlinked record means.
 *
 * The explanation used to be repeated inside every per-campaign limit, and the
 * ceiling this file fought to make reachable turned out to be unreachable for
 * the real corpus anyway: `archive-writer.ts` only writes a payload file for a
 * *published* record, so every campaign will always carry this limit. Measured
 * on twelve campaigns: twelve near-identical paragraphs of roughly 700
 * characters each. That is the same failure mode as the twelve identical
 * timestamp paragraphs — a block long enough that a reader learns to skip it,
 * and it is the block where the revoked key and the missing predecessor live.
 *
 * The counts stay per campaign, because they differ and because a campaign
 * whose count is not what its publisher expects is the whole point. Only the
 * reasoning, which is identical by construction, is said once.
 */
function reportUnlinkedRecordsExplanation(campaignCount, report) {
  report.limit(
    "archive root",
    `${campaignCount} campaign(s) above report record(s) whose archiveId and capture date are not tied to ` +
      "signed bytes. The Merkle root is built from payloadHash alone, so for those records the two fields are " +
      "free: swapping the archiveIds of two such leaves, or rewriting their capturedAt, leaves the root valid " +
      "and every signature intact. This verifier proves those hashes belong to the campaign and REFUSES to " +
      "conclude which record any of them is, or when it was captured. Expect this on any published archive — a " +
      "payload file exists only for a published record — but expecting it is not the same as it being empty: " +
      "read the per-campaign counts, and note that a record can also land here because its payload file failed " +
      "a check, which is reported separately above.",
  );
}

// ---------------------------------------------------------------------------
// tsr/
// ---------------------------------------------------------------------------

/**
 * Enumerates the timestamp directory, naming every file in it. **Decodes
 * nothing, and therefore grades nothing.**
 *
 * Extracting a `genTime`, checking the authority's signature and validating
 * its certificate chain is a job of its own, and it is not done here. A
 * half-written decoder would invite exactly the confidence it has not earned.
 *
 * **Every state of this directory is a NOTE, and that took two corrections to
 * get right.** The first version lifted the verdict when a token was present,
 * which meant fabricating a file named `whatever.tsr` containing the words
 * "not a token" bought the strongest available result, while deleting a real
 * token was penalised. The fix was to make every state a limit — and that
 * broke something else: on a healthy twelve-campaign archive it printed twelve
 * identical limit paragraphs, under a summary inviting the reader to read
 * them. A reader who skips that block skips the revoked key, the hidden
 * directory and the missing predecessor that live in it. That is the `.git`
 * false positive one level up.
 *
 * The resolution is to separate two different statements. "This program does
 * not decode timestamp tokens" is a property of **the program**, identical on
 * every run, and it belongs in the permanent "what this does NOT prove" block,
 * where it is stated once. What belongs **here** is only the fact of which
 * files exist, which is why these are notes: naming satisfies the rule this
 * file is built on, and carrying no severity keeps the incentive flat — no
 * arrangement of files in this directory can change the class of the result,
 * in either direction.
 *
 * Content that does not belong here at all is a different matter and stays a
 * failure: a stray `.txt`, a subdirectory, a sidecar describing a token this
 * archive does not hold. That is the uncovered-content rule, not a judgement
 * about timestamps.
 *
 * A point that has already led people to the wrong conclusion: the imprint
 * sealed in a token is the **manifest**'s (`manifestHash`), never the Merkle
 * root. The manifest carries the root AND the leaf count; timestamping the
 * root alone would leave the count outside what the authority attests.
 * Verified in `src/lib/campaign/close.ts`, which calls the authority with
 * `manifest.manifestHash` stripped of its `sha256:` prefix.
 */
async function inspectTimestamps(root, authenticated, report) {
  const campaignId = authenticated.campaignId;
  const scope = `${campaignId}/tsr/`;
  const tsrDir = path.join(root, campaignId, "tsr");
  const { entries, error } = await readDirEntries(root, [campaignId, "tsr"]);
  if (error !== null) {
    report.limit(scope, `could not be read (${error}): its contents were neither verified nor listed`);
    return;
  }

  const tokens = new Set();
  const sidecars = new Set();
  for (const entry of entries === null ? [] : [...entries].sort(byName)) {
    const entryScope = `${campaignId}/tsr/${entry.name}`;
    const { kind, description } = await classifyEntry(tsrDir, entry);
    if (kind !== "file") {
      report.fail(
        entryScope,
        `unexpected entry — it is ${description}: only <authority>.tsr tokens and their .json sidecars ` +
          "belong here",
      );
      continue;
    }
    if (entry.name.endsWith(".tsr")) {
      tokens.add(entry.name.slice(0, -".tsr".length));
      continue;
    }
    if (entry.name.endsWith(".json")) {
      sidecars.add(entry.name.slice(0, -".json".length));
      continue;
    }
    report.fail(
      entryScope,
      "unexpected entry: only <authority>.tsr tokens and their .json sidecars belong here, and nothing " +
        "in this archive covers this file",
    );
  }

  for (const authority of [...sidecars].sort()) {
    const sidecarScope = `${campaignId}/tsr/${authority}.json`;
    if (!tokens.has(authority)) {
      report.fail(
        sidecarScope,
        "certificate chain sidecar with no matching .tsr token: it describes a token this archive does not hold",
      );
      continue;
    }
    // The sidecar was never read at all before, and then only reported when it
    // was empty — so a "chain" reading `TOTALLY NOT A CERTIFICATE` appeared
    // nowhere in the output. An unnamed file is exactly what the rule forbids,
    // whether or not its contents look plausible. It is described, not judged:
    // this program does not validate certificates either.
    const parsed = await readJson(root, [campaignId, "tsr", `${authority}.json`]);
    if (!parsed.ok || !isPlainObject(parsed.value)) {
      report.fail(sidecarScope, parsed.ok ? "is not a JSON object" : parsed.reason);
      continue;
    }
    reportUnknownFields(report, sidecarScope, parsed.value, KNOWN_SIDECAR_FIELDS, "the sidecar");
    const chain = parsed.value.certificateChainPem;
    const requestedAt = typeof parsed.value.requestedAt === "string" ? parsed.value.requestedAt : "(absent)";
    const described =
      typeof chain !== "string" || chain.trim() === ""
        ? "carries NO certificate chain"
        : chain.includes("-----BEGIN CERTIFICATE-----")
          ? `carries ${chain.length} characters beginning with a PEM certificate header`
          : `carries ${chain.length} characters that do NOT contain a PEM certificate header`;
    report.note(
      sidecarScope,
      `requestedAt ${requestedAt} (our own clock, not the authority's); the certificate chain field ` +
        `${described}. Neither is decoded or validated here.`,
    );
  }

  // Files are listed by their FULL relative path, never by base name. A base
  // name inside a scoped line reads fine to a human and defeats any check that
  // looks for the path the rest of the report uses — including this program's
  // own test that every byte is either covered or named.
  const orphanTokens = [...tokens].filter((authority) => !sidecars.has(authority)).sort();
  if (orphanTokens.length > 0) {
    report.note(
      scope,
      `token(s) ${orphanTokens.map((a) => `${scope}${a}.tsr`).join(", ")} have no .json sidecar, so this copy holds no ` +
        "certificate chain for them: whoever verifies them later will have to obtain the authority's " +
        "certificates from elsewhere, and may not be able to once they expire",
    );
  }

  if (tokens.size > 0) {
    report.note(
      scope,
      `${tokens.size} timestamp token(s) present: ${[...tokens].sort().map((a) => `${scope}${a}.tsr`).join(", ")}. ` +
        "Their bytes are not read, so their presence establishes nothing here. Whoever decodes them must " +
        `compare the messageImprint to manifestHash ${authenticated.manifestHash}, never to the Merkle root.`,
    );
    return;
  }

  // `timestampedAt` is not in the signed bytes: it is an operational index,
  // not a proof. It is read only to notice that the folder does not support
  // what the file claims.
  if (authenticated.timestampedAt !== null) {
    report.note(
      scope,
      'no token file in this copy, while the unsigned "timestampedAt" field claims this manifest was ' +
        "timestamped. Nothing here supports that claim, and nothing here contradicts it either.",
    );
    return;
  }
  report.note(scope, "no token file, and the manifest claims no timestamp");
}

// ---------------------------------------------------------------------------
// Per-campaign orchestration
// ---------------------------------------------------------------------------

/**
 * Names everything in a campaign directory that is not one of the four entries
 * the archive format defines.
 *
 * Same reasoning as inside `payloads/`, one level up, and the gap that made it
 * necessary: a fabricated `answers.html` dropped next to genuine files was
 * never mentioned, so the run ended on a clean verdict for a folder holding
 * content nobody had checked. A failure rather than a warning, consistent with
 * the treatment of unknown files in `payloads/` — and consistent, too, with
 * refusing an unknown `manifestFormatVersion`. Content this verifier cannot
 * account for is refused; a genuinely new format announces itself by bumping
 * the version, which is refused just as loudly.
 */
async function reportUnexpectedCampaignEntries(root, campaignId, report) {
  const dir = path.join(root, campaignId);
  const { entries, error } = await readDirEntries(root, [campaignId]);
  if (error !== null) {
    report.fail(`${campaignId}/`, `could not be read (${error}): nothing in this campaign could be checked`);
    return;
  }
  for (const entry of entries === null ? [] : [...entries].sort(byName)) {
    const expectedKind = KNOWN_CAMPAIGN_ENTRIES.get(entry.name);
    if (expectedKind === undefined) {
      report.fail(
        `${campaignId}/${entry.name}`,
        "unexpected entry in a campaign directory: nothing in this archive covers it, and a file sitting next " +
          "to genuine evidence borrows its credibility",
      );
      continue;
    }
    // The name was checked but never the type, and only the two directory
    // entries were exposed by it: an ordinary 900-byte text file named `tsr`
    // was accepted, `readDirEntries` then swallowed its ENOTDIR, and the run
    // reported "no token file is present in this copy" — false — while those
    // 900 bytes went unnamed. `manifest.json` and `merkle.json` were already
    // safe by accident, because reading a directory as a file fails loudly.
    // A link is neither, and "is a other where the archive format defines a
    // directory" is what the earlier spelling produced for one.
    const { kind, description } = await classifyEntry(dir, entry);
    if (kind !== expectedKind) {
      report.fail(
        `${campaignId}/${entry.name}`,
        `is ${description} where the archive format defines a ${expectedKind}. Its bytes are covered by ` +
          "nothing, and read as that format its contents would silently look absent",
      );
    }
  }
}

/**
 * Names what sits inside `payloads/` and `tsr/` when the campaign was rejected
 * before either directory was reached.
 *
 * A rejected manifest used to end the campaign on the spot, so
 * `campaign/payloads/smuggled.exe` was named nowhere at all. The exit code is 1
 * and nobody is led to accept the archive, which is why this is the smallest of
 * the gaps — but the rule this program is built on does not read "every byte is
 * covered or named, unless an earlier check failed". A reader whose archive was
 * rejected is exactly the reader who needs to know what is in it.
 *
 * Aggregated into one line per directory, and a limit rather than a failure:
 * the failure has already been reported, and repeating it per file would bury
 * it. Nothing here was checked against anything, and the line says so.
 */
async function reportUnverifiedCampaignContents(root, campaignId, report) {
  for (const name of ["payloads", "tsr"]) {
    const scope = `${campaignId}/${name}/`;
    const { entries, error } = await readDirEntries(root, [campaignId, name]);
    if (error !== null) {
      report.limit(scope, `could not be read (${error}): its contents were neither verified nor listed`);
      continue;
    }
    if (entries === null || entries.length === 0) {
      continue;
    }
    const named = [];
    for (const entry of [...entries].sort(byName)) {
      const { kind } = await classifyEntry(path.join(root, campaignId, name), entry);
      named.push(`${scope}${entry.name}${kind === "directory" ? "/" : ""}`);
    }
    report.limit(
      scope,
      `holds ${named.length} entr${named.length === 1 ? "y" : "ies"} that this run never checked against ` +
        `anything, because the campaign was rejected above: ${named.join(", ")}`,
    );
  }
}

async function verifyCampaign(root, campaignId, keys, report) {
  await reportUnexpectedCampaignEntries(root, campaignId, report);

  const authenticated = await verifyManifest(root, campaignId, keys, report);
  if (authenticated === null) {
    await reportUnverifiedCampaignContents(root, campaignId, report);
    return { authenticated: null, unlinked: 0 };
  }

  if (authenticated.isDevelopmentKey) {
    report.fail(
      `${campaignId}/manifest.json`,
      `signing key "${authenticated.keyId}" is a DEVELOPMENT key (its id starts with ` +
        `"${DEVELOPMENT_KEY_ID_PREFIX}"). Its signature is arithmetically valid and proves NOTHING: development ` +
        "keys sign a fabricated corpus. Treating it as evidence would be worse than having no signature at all. " +
        "Pass --allow-dev-keys only to exercise this verifier itself, never to assess a real archive.",
      "development-key",
    );
  }

  const leaves = await verifyMerkleFile(root, authenticated, report);
  if (leaves === null) {
    await reportUnverifiedCampaignContents(root, campaignId, report);
    return { authenticated, unlinked: 0 };
  }
  const tally = await verifyPayloads(root, authenticated, leaves, report);
  const unlinked = reportUnlinkedRecords(authenticated, tally, report);
  await inspectTimestamps(root, authenticated, report);
  return { authenticated, unlinked };
}

// ---------------------------------------------------------------------------
// The chain between manifests
// ---------------------------------------------------------------------------

/**
 * Checks that the manifests present form **one chain**, and says what it
 * cannot check.
 *
 * Each manifest names its predecessor by hash, inside its own signed bytes.
 * That makes four questions answerable offline, and one not:
 *
 * - A **fork** — two manifests naming the same predecessor — is a failure. A
 *   chain verifier that accepts a fork is not verifying a chain: a fork is how
 *   one branch of history gets replaced by another while every individual
 *   signature stays valid.
 * - **Two manifests both claiming to open the chain** (`previousManifestHash`
 *   null, which is inside the signed bytes) is a fork at the root.
 * - **A successor created before its predecessor** is a failure. Both
 *   `createdAt` values are inside signed bytes, so the contradiction is
 *   authenticated on both sides and readable offline. The chain is the only
 *   ordering evidence this archive has that does not depend on decoding a
 *   timestamp token; a chain that contradicts itself orders nothing.
 * - A **missing predecessor** cannot be resolved: an incomplete copy and a
 *   removed link look identical from here. That justifies not failing. It does
 *   not justify a note. Making a whole campaign disappear is the cheapest move
 *   available to a censor, and it is exactly where the strongest reassurance
 *   used to be printed — so it is a limit.
 */
function verifyChain(manifests, report) {
  const byHash = new Map();
  for (const manifest of manifests) {
    const existing = byHash.get(manifest.manifestHash);
    if (existing !== undefined) {
      // Not reachable with manifests that passed the checks above, and stated
      // rather than left to look like a live control: `campaignId` is inside
      // the signed bytes and must equal the directory name, and two directory
      // names in one parent are necessarily distinct — so two manifests cannot
      // share signed bytes. Kept for the same reason as the cycle check below.
      report.fail(
        `${manifest.campaignId}/manifest.json`,
        `has the same manifestHash as campaign ${existing.campaignId}: two campaigns cannot share signed bytes`,
      );
      continue;
    }
    byHash.set(manifest.manifestHash, manifest);
  }

  const roots = manifests.filter((manifest) => manifest.previousManifestHash === null);
  if (roots.length > 1) {
    report.fail(
      "chain",
      `${roots.length} manifests claim to open the chain (${roots.map((m) => m.campaignId).sort().join(", ")}); ` +
        "each claim is inside signed bytes, so these are several chains, not one",
    );
  }

  const children = new Map();
  for (const manifest of manifests) {
    if (manifest.previousManifestHash === null) {
      continue;
    }
    const siblings = children.get(manifest.previousManifestHash) ?? [];
    siblings.push(manifest.campaignId);
    children.set(manifest.previousManifestHash, siblings);
  }
  for (const [previousHash, siblings] of children) {
    if (siblings.length > 1) {
      const parent = byHash.get(previousHash);
      report.fail(
        "chain",
        `campaigns ${[...siblings].sort().join(", ")} all name ${
          parent === undefined ? previousHash : `campaign ${parent.campaignId}`
        } as their predecessor: a fork, not a chain`,
      );
    }
  }

  // Cycle detection: walk the predecessor links from every manifest, bounded
  // by the number of manifests. A chain of N nodes cannot need more steps.
  //
  // Stated plainly, because it would be dishonest to let this read as a
  // tested guarantee: with manifests that pass the checks above, a cycle is
  // not constructible. `previousManifestHash` is inside the signed bytes, so
  // manifest A pointing at B while B points at A would require solving
  // H(A) = f(H(B)) and H(B) = g(H(A)) simultaneously — a SHA-256 fixed point.
  // No test in this repository reaches this branch for that reason. It is kept
  // as defence in depth: it costs a dozen lines, and it becomes reachable the
  // day the format changes (a predecessor pointer moved out of the signed
  // bytes, an added hash algorithm, a manifest format that skips the hash
  // check). A chain verifier with no cycle check is one format revision away
  // from accepting a history that has no beginning.
  const inCycle = new Set();
  for (const start of manifests) {
    const walked = new Set([start.campaignId]);
    let current = start;
    for (let step = 0; step <= manifests.length; step++) {
      if (current.previousManifestHash === null) {
        break;
      }
      const previous = byHash.get(current.previousManifestHash);
      if (previous === undefined) {
        break;
      }
      if (walked.has(previous.campaignId)) {
        for (const campaignId of walked) {
          inCycle.add(campaignId);
        }
        break;
      }
      walked.add(previous.campaignId);
      current = previous;
    }
  }
  if (inCycle.size > 0) {
    report.fail(
      "chain",
      `the predecessor links of campaigns ${[...inCycle].sort().join(", ")} form a cycle: a chain built this ` +
        "way has no beginning, so nothing in it can be ordered",
    );
  }

  for (const manifest of manifests) {
    const scope = `${manifest.campaignId}/manifest.json`;
    if (manifest.previousManifestHash === null) {
      report.note(scope, "no predecessor: this manifest claims to open the chain");
      continue;
    }
    const previous = byHash.get(manifest.previousManifestHash);
    if (previous === undefined) {
      report.limit(
        scope,
        `names predecessor ${manifest.previousManifestHash}, which is not in this copy of the archive. An ` +
          "incomplete copy and a removed link are indistinguishable from here, so this verifier cannot tell " +
          "whether a campaign is missing from history.",
      );
      continue;
    }
    if (Date.parse(manifest.createdAt) < Date.parse(previous.createdAt)) {
      report.fail(
        scope,
        `claims to be created at ${manifest.createdAt}, before its own predecessor ${previous.campaignId} ` +
          `(${previous.createdAt}). Both dates are inside signed bytes, so the chain contradicts itself and ` +
          "orders nothing.",
      );
      continue;
    }
    report.pass(scope, `chains to campaign ${previous.campaignId}, whose manifest is present and hashes as claimed`);
  }
}

// ---------------------------------------------------------------------------
// Walking the archive root
// ---------------------------------------------------------------------------

/**
 * Budget for the recursive scan below. A published archive is a Git working
 * copy, and `.git/objects` alone can hold tens of thousands of entries; an
 * unbounded walk would make the verifier appear to hang on a perfectly healthy
 * repository. When the budget runs out the scan says so rather than returning
 * a quietly partial answer — an incomplete search reported as complete is the
 * defect this whole file exists to avoid.
 */
const DEFAULT_SCAN_BUDGET = 50_000;

/**
 * Finds every `manifest.json` at any depth below `dir`.
 *
 * Classification used to look one level down and no further, and the inventory
 * then printed a positive claim that was false. A whole campaign parked under
 * `docs/2026-07-01/`, `assets/` or `.cache/` was neither verified nor named,
 * while the report asserted `docs/ (holds no campaign file)` — and hiding the
 * chain tip that way produced output indistinguishable from a healthy archive,
 * because nothing points at the newest manifest for its absence to show. Depth
 * is the whole trick, so depth is what this searches.
 *
 * **The one place that reads a directory without going through `inspectUnder`,
 * and the reason it is allowed to.** Every directory this enqueues came from a
 * `Dirent` that `classifyEntry` resolved to `"directory"` — a real directory,
 * never a link — and the starting directory is resolved the same way by its
 * caller. The walk is therefore link-free by construction rather than by
 * re-checking each component, which would cost an `lstat` per component per
 * directory on a walk bounded at 50 000 of them. If this function ever gains a
 * second way to enqueue a path, that argument dies with it.
 */
async function scanForManifests(dir, budget) {
  const found = [];
  const unreadable = [];
  const unfollowed = [];
  const queue = [{ absolute: dir, relative: "" }];

  while (queue.length > 0) {
    if (budget.remaining <= 0) {
      return { found, unreadable, unfollowed, truncated: true };
    }
    const current = queue.shift();
    const where = current.relative === "" ? "." : current.relative;
    budget.remaining -= 1;
    const { entries, missing, error } = await readDirEntriesOfKnownDirectory(current.absolute);
    if (error !== null) {
      unreadable.push(`${where} (${error})`);
      continue;
    }
    if (missing) {
      // A directory its own parent listed a moment ago, and that could not be
      // opened now: it was removed under us, or it sits on a volume that went
      // away — the removable-media case this program is written for. Swallowed,
      // it became a fourth way for the parent's summary to print "no
      // manifest.json anywhere inside" about a directory nobody looked into.
      unreadable.push(`${where} (vanished between being listed and being opened)`);
      continue;
    }
    for (const entry of entries === null ? [] : [...entries].sort(byName)) {
      const relative = current.relative === "" ? entry.name : `${current.relative}/${entry.name}`;
      const { kind, description } = await classifyEntry(current.absolute, entry);
      if (kind === "directory") {
        queue.push({ absolute: path.join(current.absolute, entry.name), relative });
        continue;
      }
      if (kind === "file") {
        if (entry.name === "manifest.json") {
          found.push(relative);
        }
        continue;
      }
      // Neither a file nor a directory: not followed, and therefore unsearched.
      unfollowed.push(`${relative} (${description})`);
    }
  }
  return { found, unreadable, unfollowed, truncated: false };
}

/**
 * Walks the archive root, returns the campaigns to verify, and — applying the
 * rule this program is built on — accounts for every other entry.
 *
 * What "accounts for" means, precisely, because the rule needs an operational
 * reading: every entry at a level the archive format defines is named
 * individually (the root, a campaign directory, `payloads/`, `tsr/`, `keys/`);
 * a directory the format does not define is named as a whole and searched for
 * campaign material at any depth. Listing every file inside a cloned `.git`
 * would be absurd, and would bury the report; leaving a campaign hidden inside
 * one would be a hole. Searching for manifests closes the hole without the
 * noise.
 *
 * A directory is a campaign because it holds a `manifest.json` — never because
 * of its name. That matters more than it looks: an archive is meant to be
 * published as a Git repository (the writer names its documentation
 * `README.md` precisely because that is a repository's front page), so the
 * first thing any third party does is clone it and run this program from a
 * working copy containing `.git`, quite possibly beside a `docs/` folder. A
 * severity raised on either would fire on every legitimate run, and it is the
 * same severity the chain checks depend on.
 *
 * Hidden directories are never verified, and that exception is real rather
 * than arbitrary: the writer builds each campaign in `.tmp-<name>-<random>`
 * and parks the previous version in `.stale-<name>-<random>` while it swaps
 * folders, so a crash can leave either behind. A `.stale-` copy holds a
 * perfectly valid manifest whose signed `campaignId` does not match its
 * directory name — verifying it would turn a leftover into an accusation
 * against a healthy archive. Skipping is not silence: the manifests inside are
 * still found and named by the same scan as everywhere else, so the dot
 * prefix can change a severity but cannot hide anything.
 */
async function walkArchiveRoot(root, entries, report, scanBudget) {
  const campaignIds = [];
  const inventory = [];
  const strays = [];
  const unfollowed = [];
  const cutShort = [];
  const budget = { remaining: scanBudget };

  for (const entry of [...entries].sort(byName)) {
    const { kind: entryKind, description } = await classifyEntry(root, entry);
    if (entryKind === "file") {
      inventory.push(TOOLING_ENTRIES.has(entry.name) ? `${entry.name} (this tooling)` : entry.name);
      continue;
    }
    if (entryKind !== "directory") {
      // A root entry that is a link deserves more than an inventory word: what
      // it stands in for is an entire campaign directory's worth of bytes that
      // were neither verified nor searched, and the archive format puts
      // campaigns exactly here.
      report.limit(
        `${entry.name}`,
        `is ${description}. This verifier never follows one — a link can point outside the archive or back ` +
          "at one of its own parents — so nothing behind it was read, verified or searched, and a campaign " +
          "moved out of the tree and replaced by a link would look exactly like this",
      );
      inventory.push(`${entry.name} (${description} — not followed)`);
      continue;
    }

    const absolute = path.join(root, entry.name);
    // `inspectUnder`, not `stat`: a `manifest.json` that is a LINK must not
    // make this directory a campaign, or the run verifies bytes from outside
    // the archive and prints PASS lines about them. It then falls through to
    // the "campaign files but no manifest.json" failure below, which is the
    // truthful description of what is on disk.
    const isCampaign = (await inspectUnder(absolute, ["manifest.json"])).kind === "file";
    // Hidden directories and `keys/` are never verified as campaigns even when
    // they hold a manifest, so their manifest IS a stray and must stay one.
    const willVerify = isCampaign && !entry.name.startsWith(".") && entry.name !== "keys";

    // EVERY directory at the root is searched, campaigns included. A campaign
    // directory used to be exempt, which left the deep search with a blind spot
    // the shape of the archive's own layout: a second campaign parked under
    // `campaign-one/extra-payloads/2026-07-01/` was named only as an unexpected
    // entry, and its manifest — the thing the search exists to find — appeared
    // nowhere. A campaign's OWN manifest.json is not a stray, and it is the
    // only thing filtered out here.
    const scan = await scanForManifests(absolute, budget);
    if (scan.truncated) {
      cutShort.push(`${entry.name}/`);
    }
    for (const relative of scan.found) {
      if (willVerify && relative === "manifest.json") {
        continue;
      }
      strays.push(`${entry.name}/${relative}`);
    }
    for (const relative of scan.unfollowed) {
      unfollowed.push(`${entry.name}/${relative}`);
    }
    for (const problem of scan.unreadable) {
      report.limit(
        `${entry.name}/`,
        `${problem} could not be read, so this verifier cannot say whether it holds campaign material`,
      );
    }

    if (willVerify) {
      campaignIds.push(entry.name);
      continue;
    }

    if (entry.name === "keys") {
      inventory.push(
        "keys/ (the key ring — read, but nothing signs it" +
          (scan.truncated ? "; NOT searched to the end — scan budget exhausted" : "") +
          ")",
      );
      continue;
    }

    // A directory holding campaign parts with no manifest.json beside them is
    // a campaign whose authenticating file was removed: without it nothing in
    // there is signed, so nothing in there can be checked.
    if (!entry.name.startsWith(".")) {
      const parts = [];
      for (const part of ["merkle.json", "payloads", "tsr"]) {
        if ((await inspectUnder(absolute, [part])).kind !== "missing") {
          parts.push(part);
        }
      }
      if (parts.length > 0) {
        report.fail(
          `${entry.name}/`,
          `holds campaign files (${parts.join(", ")}) but no manifest.json: without it nothing in this ` +
            "directory is signed, and no part of it can be checked",
        );
        continue;
      }
    }

    // The summary must never claim more than the search actually established.
    // "no manifest.json anywhere inside" was printed whatever happened: with
    // the budget spent, with a subdirectory unreadable, with a junction left
    // unfollowed. Three ways for a true-sounding sentence to be false about the
    // one directory that mattered, in the line a reader uses to decide there is
    // nothing to look at.
    const summary = [];
    if (scan.truncated) {
      summary.push("NOT searched to the end — scan budget exhausted");
    }
    if (scan.unreadable.length > 0) {
      summary.push(`${scan.unreadable.length} path(s) unreadable — see the limit(s) above`);
    }
    if (scan.unfollowed.length > 0) {
      summary.push(`${scan.unfollowed.length} link(s) not followed — see the limit above`);
    }
    if (scan.found.length > 0) {
      summary.push(`${scan.found.length} manifest.json inside — see the limit above`);
    }
    if (summary.length === 0) {
      summary.push("no manifest.json anywhere inside");
    }
    inventory.push(`${entry.name}/ (${summary.join("; ")})`);
  }

  if (unfollowed.length > 0) {
    report.limit(
      "archive root",
      `${unfollowed.length} entr${unfollowed.length === 1 ? "y" : "ies"} below the directories listed here ` +
        `${unfollowed.length === 1 ? "is" : "are"} neither a file nor a directory and ` +
        `${unfollowed.length === 1 ? "was" : "were"} NOT followed: ${unfollowed.sort().join(", ")}. Following a ` +
        "link would let an archive point at bytes it does not contain, or at one of its own parents, so this " +
        "verifier refuses — but what a link stands for was neither verified nor searched, and moving a campaign " +
        "out of the tree and leaving a link in its place is a way to remove it from history that costs nothing.",
    );
  }
  if (strays.length > 0) {
    report.limit(
      "archive root",
      `${strays.length} manifest.json found outside the campaign layout and NOT verified: ` +
        `${strays.sort().join(", ")}. The archive format puts one campaign per directory at the root, so this ` +
        "verifier does not treat these as campaigns — but it cannot tell an unrelated file from a campaign " +
        "moved out of sight, and moving one out of sight is the cheapest way to remove it from history.",
    );
  }
  if (cutShort.length > 0) {
    // Naming the directories is the point. The budget is global and root
    // entries are walked in alphabetical order, so a directory of 50 000
    // throwaway folders — 17 seconds to fabricate, measured — sorts before
    // `docs/` and switches off the search on whatever comes after it. The
    // generic sentence that used to be printed here named nothing, while each
    // starved directory separately claimed to hold no manifest.
    report.limit(
      "archive root",
      `the search for misplaced campaign material stopped after ${scanBudget} directories, before finishing ` +
        `${cutShort.sort().join(", ")}. Those were not searched to the end, so a campaign hidden inside one of ` +
        "them would not have been found. Raise the ceiling with --scan-budget=<n> to search further.",
    );
  }
  if (inventory.length > 0) {
    report.note("archive root", `not covered by any signature and not verified: ${inventory.join(", ")}`);
  }
  return campaignIds;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const USAGE = `ai-memory archive verifier

Usage: node verify.mjs [archive-root] [--allow-dev-keys] [--scan-budget=<n>]

  archive-root      Directory holding keys/public-keys.json and one folder per
                    campaign. Defaults to the directory this script sits in, so
                    "node verify.mjs" works from inside a copied archive.
  --allow-dev-keys  Downgrade the refusal of development signing keys to a
                    warning. For exercising this verifier against a fabricated
                    corpus only. A published archive must never need it.
  --scan-budget=<n> How many directories the search for misplaced campaign
                    material may open, outside the campaign layout itself.
                    Default ${DEFAULT_SCAN_BUDGET}. Lowering it never hides
                    anything silently: whatever is left unsearched is named as
                    a limit. Raise it if that limit appears.

Exit code 0 means no integrity failure was found; 1 means at least one check
failed; 2 means the verifier could not run at all.`;

/**
 * Prints the collected report and returns the number of failing checks.
 *
 * Printing is separated from deciding the exit code because of a real defect:
 * when every campaign directory had been hidden by renaming it, the run
 * returned "could not run" and threw the report away — including the very
 * limit naming the hidden directories. The case where naming what was skipped
 * matters most was the case that deleted it.
 */
function printReport(report, root, campaignCount, allowDevKeys) {
  print("ai-memory archive verifier — independent reimplementation, no project code, no dependencies.");
  print("");
  print(`Archive root : ${root}`);
  print(`Campaigns    : ${campaignCount}`);
  print("");

  let failures = 0;
  let downgraded = 0;
  for (const line of report.lines) {
    // A development key stays reported word for word; only its severity
    // changes, and the flag that allowed it is restated at the end.
    const downgrade = allowDevKeys && line.kind === "development-key";
    if (downgrade) {
      downgraded += 1;
    }
    const level = downgrade ? "WARN" : line.level;
    if (level === "FAIL") {
      failures += 1;
    }
    print(`${level.padEnd(5)} ${line.scope}: ${line.message}`);
  }

  print("");
  print("What a successful run proves:");
  print("  - every payload file present hashes to a leaf of a Merkle tree whose root is signed;");
  print("  - the signed bytes of each manifest were not altered after signing;");
  print("  - the number of records in a campaign is the one the signature covers;");
  print("  - the manifests present form a single chain, with no fork and no impossible ordering;");
  print("  - nothing else is present that this program failed to mention.");
  print("");
  print("What it does NOT prove, in any circumstance:");
  print("  - that the AI provider ever produced this text. Nothing here comes from the provider;");
  print("    the archive attests what was recorded, not that the recording is faithful;");
  print("  - that the signing key belongs to anyone in particular. keys/public-keys.json ships");
  print("    with the archive, so it is the same party vouching for itself;");
  print("  - WHEN anything was written. A signature carries no date. Only the timestamp tokens do,");
  print("    and this verifier does not decode them: it names the token files a campaign holds and");
  print("    grades none of them, so no arrangement of files in tsr/ establishes anything here;");
  print("  - that this copy is complete. Nothing in an archive can attest to what was removed");
  print("    from it before you received it;");
  print("  - that this program is the one the publisher wrote. verify.mjs travels inside the");
  print("    archive and nothing signs it. Read it, or fetch it from a source you already trust.");
  print("");

  if (allowDevKeys) {
    print("--allow-dev-keys was passed: development-key signatures were downgraded to warnings.");
    print("They still prove nothing. Never use this flag to assess a published archive.");
    print("");
  }
  return { failures, downgraded };
}

async function main(argv) {
  const args = argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    printBlock(USAGE);
    return 0;
  }
  const allowDevKeys = args.includes("--allow-dev-keys");
  const positional = args.filter((arg) => !arg.startsWith("--"));
  const budgetFlags = args.filter((arg) => arg.startsWith("--scan-budget="));
  const unknown = args.filter(
    (arg) => arg.startsWith("--") && arg !== "--allow-dev-keys" && !arg.startsWith("--scan-budget="),
  );
  if (unknown.length > 0 || positional.length > 1) {
    print(`Unrecognized arguments: ${[...unknown, ...positional.slice(1)].join(" ")}`);
    print("");
    printBlock(USAGE);
    return 2;
  }

  let scanBudget = DEFAULT_SCAN_BUDGET;
  if (budgetFlags.length > 0) {
    const value = Number(budgetFlags[budgetFlags.length - 1].slice("--scan-budget=".length));
    if (!Number.isSafeInteger(value) || value < 0) {
      print("--scan-budget must be a non-negative whole number.");
      print("");
      printBlock(USAGE);
      return 2;
    }
    scanBudget = value;
  }

  const root = positional.length === 1
    ? path.resolve(positional[0])
    : path.dirname(fileURLToPath(import.meta.url));

  // The root is the only path this program resolves without asking whether it
  // is a link, and the reason is that it is not archive content: it is either
  // an argument the operator typed or the directory this script sits in.
  // Refusing a symlinked checkout would help nobody. Everything BELOW it is
  // refused, which is where an archive could point somewhere of its choosing.
  const { entries, error } = await readDirEntriesOfKnownDirectory(root);
  if (entries === null) {
    print(error === null ? `Archive root not found: ${root}` : `Archive root could not be read: ${error}`);
    return 2;
  }

  const report = new Report();
  const keys = await loadPublicKeys(root, report);
  await reportUnexpectedKeyRingEntries(root, report);
  const campaignIds = await walkArchiveRoot(root, entries, report, scanBudget);

  const manifests = [];
  let campaignsWithUnlinkedRecords = 0;
  for (const campaignId of campaignIds) {
    const outcome = await verifyCampaign(root, campaignId, keys, report);
    if (outcome.authenticated !== null) {
      manifests.push(outcome.authenticated);
    }
    if (outcome.unlinked > 0) {
      campaignsWithUnlinkedRecords += 1;
    }
  }
  if (campaignsWithUnlinkedRecords > 0) {
    reportUnlinkedRecordsExplanation(campaignsWithUnlinkedRecords, report);
  }
  verifyChain(manifests, report);

  const { failures, downgraded } = printReport(report, root, campaignIds.length, allowDevKeys);

  if (campaignIds.length === 0) {
    print(`Result: NOTHING VERIFIED — no campaign directory under ${root}.`);
    return 2;
  }
  if (failures > 0) {
    print(`Result: FAILED — ${failures} failing check(s).`);
    return 1;
  }
  // A downgraded refusal counts as a qualification, and so does every warning.
  // Otherwise an archive signed entirely with a development key, or one that
  // printed a warning a few lines earlier, could still end on the unqualified
  // success line — a summary contradicting the body of its own report.
  const qualifications = report.counts.LIMIT + report.counts.WARN + downgraded;
  if (qualifications > 0) {
    print(`Result: VERIFIED WITH LIMITS — no failing check, but ${qualifications} qualification(s) above.`);
    print("Read them. They say what this run is not entitled to conclude.");
    return 0;
  }
  // The wording of this line is load-bearing, and it took a wrong turn to find
  // out why. It once read "every check passed", which invites the reader to
  // hear "every check that matters" — a promise this program cannot make,
  // since it does not decode timestamp tokens. The fix attempted first was to
  // make that undecoded state a per-campaign limit, which removed the
  // overstatement by making this line unreachable — and printed twelve
  // identical paragraphs on a healthy twelve-campaign archive, training the
  // reader to skip the very block where the revoked key and the missing
  // predecessor live. What was wrong was the claim, not the ceiling: so the
  // ceiling is back, saying only what was actually established, and pointing
  // at the block that lists what was not.
  print("Result: VERIFIED — no discrepancy found.");
  print('This program does not decode timestamp tokens; read "What it does NOT prove" above.');
  return 0;
}

main(process.argv)
  .then((code) => {
    process.exitCode = code;
  })
  .catch((cause) => {
    // A verifier that crashes has not returned a verdict: say so, and exit
    // with a reserved code — never 0, and never 1, which would mean "archive
    // rejected", a verdict this run did not reach.
    print(`The verifier could not complete: ${cause?.stack ?? String(cause)}`);
    process.exitCode = 2;
  });
