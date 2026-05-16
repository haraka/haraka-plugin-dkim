'use strict'

const assert = require('node:assert/strict')
const { describe, it, afterEach, mock } = require('node:test')
const crypto = require('node:crypto')
const dns = require('node:dns')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { spawnSync } = require('node:child_process')

const message = require('haraka-email-message')

const { DKIMSignStream, DKIMVerifyStream } = require('../lib/dkim')

// ─── Binary discovery ────────────────────────────────────────────────────────
// Searches fixed paths covering MacPorts (/opt/local) and standard system dirs,
// then falls back to PATH.  Returns the first existing binary path, or null.

function findBinary(name) {
  for (const dir of [
    '/opt/local/sbin',
    '/usr/local/sbin',
    '/usr/local/bin',
    '/usr/sbin',
    '/usr/bin',
  ]) {
    const p = path.join(dir, name)
    if (fs.existsSync(p)) return p
  }
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    const p = path.join(dir, name)
    if (fs.existsSync(p)) return p
  }
  return null
}

// The opendkim(8) daemon binary — used in test-file mode (-t) for offline
// signing and verification without a running MTA or real DNS.
const openDkimBin = findBinary('opendkim')

// ─── Test fixtures ───────────────────────────────────────────────────────────

// Well-formed RFC 5322 message accepted by opendkim for signing.
// Headers include all fields opendkim selects by default (Date, From, To, Subject).
const HEADERS = [
  'Date: Sat, 12 Apr 2026 00:00:00 +0000',
  'From: sender@example.org',
  'To: rcpt@example.org',
  'Subject: DKIM Cross-Implementation Test',
  'Message-ID: <dkim-integration-test@example.org>',
  'MIME-Version: 1.0',
  'Content-Type: text/plain',
]
const BODY = 'This is the integration test message body.\r\n'
const DOMAIN = 'example.org'
const SELECTOR = 'crosstest'

// Headers Haraka will sign — same set opendkim covers by default
const SIGN_HEADERS = ['from', 'to', 'subject', 'date']

// ─── Key generation ───────────────────────────────────────────────────────────

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  })
  return {
    // PKCS#1 PEM — opendkim requires the traditional RSA key format
    privKeyPem: privateKey.export({ type: 'pkcs1', format: 'pem' }),
    // SPKI DER base64 — used in DKIM DNS TXT records (p= tag)
    pubKeyDerB64: publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64'),
  }
}

// ─── opendkim helpers ─────────────────────────────────────────────────────────

// Sign a message file using the opendkim daemon in test-file mode.
// Returns the full DKIM-Signature header string (including "DKIM-Signature: "),
// with LF line endings replaced by CRLF for embedding in a MIME message.
//
// opendkim output format:
//   line 1: "opendkim: /path/file:"        ← discard
//   remaining: "DKIM-Signature: v=1; ..."  ← keep
function opendkimSign(msgPath, keyPath) {
  const result = spawnSync(
    openDkimBin,
    [
      '-b',
      's',
      '-d',
      DOMAIN,
      '-s',
      SELECTOR,
      '-k',
      keyPath,
      '-S',
      'rsa-sha256',
      '-c',
      'relaxed/simple',
      '-t',
      msgPath,
    ],
    { encoding: 'utf-8' },
  )

  if (result.status !== 0) {
    throw new Error(
      `opendkim signing failed (exit ${result.status}): ${result.stdout}${result.stderr}`,
    )
  }

  // Strip the "opendkim: path:" preamble line
  const lines = result.stdout.split('\n')
  lines.shift()
  const header = lines.join('\n').trim()

  if (!header.startsWith('DKIM-Signature:')) {
    throw new Error(`Unexpected opendkim output:\n${result.stdout}`)
  }

  // Normalise to CRLF for inclusion in a MIME email
  return header.replace(/\r?\n/g, '\r\n')
}

// Verify a signed message file using the opendkim daemon in test-file mode.
// Supplies the public key via a TestPublicKeys file so no real DNS is needed.
// Returns true when opendkim reports "succeeded".
function opendkimVerify(signedMsgPath, pubKeyDerB64) {
  // TestPublicKeys format: "selector._domainkey.domain v=DKIM1; k=rsa; p=..."
  const keysPath = `${signedMsgPath}.keys`
  const confPath = `${signedMsgPath}.conf`
  fs.writeFileSync(
    keysPath,
    `${SELECTOR}._domainkey.${DOMAIN} v=DKIM1; k=rsa; p=${pubKeyDerB64}\n`,
  )
  fs.writeFileSync(confPath, `Mode v\nTestPublicKeys ${keysPath}\n`)

  const result = spawnSync(
    openDkimBin,
    ['-x', confPath, '-b', 'v', '-t', signedMsgPath],
    { encoding: 'utf-8' },
  )

  return result.stdout.includes('succeeded')
}

// ─── Haraka helpers ───────────────────────────────────────────────────────────

// Sign a CRLF-formatted email with Haraka's DKIMSignStream.
// Resolves with the DKIM-Signature header value (everything after "DKIM-Signature: ").
function harakaSign(headerLines, body, privKeyPem) {
  return new Promise((resolve, reject) => {
    const emailStr = `${headerLines.join('\r\n')}\r\n\r\n${body}`
    const hdr = new message.Header()
    hdr.parse(headerLines)

    const signer = new DKIMSignStream(
      {
        selector: SELECTOR,
        domain: DOMAIN,
        private_key: privKeyPem,
        headers: SIGN_HEADERS,
      },
      hdr,
      (err, value) => {
        if (err) return reject(err)
        resolve(value)
      },
    )
    signer.write(Buffer.from(emailStr))
    signer.end()
  })
}

// Verify a signed email string with Haraka's DKIMVerifyStream.
// DNS is mocked so all selector queries for DOMAIN return the given public key.
// Resolves with the overall result string ('pass', 'fail', etc.).
function harakaVerify(signedEmailStr, pubKeyDerB64) {
  return new Promise((resolve, reject) => {
    mock.method(dns.promises, 'resolveTxt', async (name) => {
      if (name.endsWith(`._domainkey.${DOMAIN}`)) {
        return [[`v=DKIM1; k=rsa; p=${pubKeyDerB64}`]]
      } else {
        throw Object.assign(new Error('NXDOMAIN'), { code: dns.NXDOMAIN })
      }
    })

    const verifier = new DKIMVerifyStream({ timeout: 10 }, (err, result) => {
      if (err) return reject(err)
      resolve(result)
    })
    verifier.write(Buffer.from(signedEmailStr))
    verifier.end()
  })
}

// Extract a DKIM tag value from a DKIM-Signature header value string.
// Handles folded whitespace (tab or space continuation lines).
function extractDkimTag(dkimHeaderValue, tag) {
  const flat = dkimHeaderValue.replace(/\r?\n[ \t]+/g, ' ')
  const re = new RegExp(`(?:^|;)\\s*${tag}=([^;]*)`)
  const m = flat.match(re)
  return m ? m[1].trim() : null
}

// ─── Integration tests ────────────────────────────────────────────────────────

describe('OpenDKIM cross-implementation integration', () => {
  if (!openDkimBin) {
    it(
      'opendkim not found in /{opt,usr}/local/{s}bin or PATH — all tests skipped',
      {
        skip: 'opendkim binary not installed',
      },
      () => {},
    )
    return
  }

  afterEach(() => mock.restoreAll())

  it(`detects opendkim at ${openDkimBin}`, () => {
    assert.ok(fs.existsSync(openDkimBin))
  })

  // ── Test 1: opendkim signs → Haraka verifies ──────────────────────────────
  // Validates that Haraka correctly verifies a signature produced by a
  // reference implementation (opendkim) using rsa-sha256 + relaxed/simple.

  it('Haraka verifies an rsa-sha256 message signed by opendkim', async () => {
    const { privKeyPem, pubKeyDerB64 } = generateKeyPair()

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-dkim-'))
    try {
      const msgPath = path.join(dir, 'msg.eml')
      const keyPath = path.join(dir, 'key.pem')

      // Write CRLF email and PKCS#1 private key
      fs.writeFileSync(msgPath, `${HEADERS.join('\r\n')}\r\n\r\n${BODY}`)
      fs.writeFileSync(keyPath, privKeyPem, { mode: 0o600 })

      // opendkim produces the DKIM-Signature header (CRLF-normalised)
      const dkimHeader = opendkimSign(msgPath, keyPath)

      // Reconstruct the signed email: prepend DKIM-Signature to original
      const rawEmail = `${HEADERS.join('\r\n')}\r\n\r\n${BODY}`
      const signedEmail = `${dkimHeader}\r\n${rawEmail}`

      const result = await harakaVerify(signedEmail, pubKeyDerB64)
      assert.equal(
        result,
        'pass',
        `Haraka must verify opendkim's rsa-sha256 signature as pass, got '${result}'`,
      )
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  // ── Test 2: Haraka signs → opendkim verifies ──────────────────────────────
  // Validates that a Haraka-generated signature is accepted by the reference
  // implementation, confirming correct header/body canonicalization and format.

  it('opendkim verifies an rsa-sha256 message signed by Haraka', async () => {
    const { privKeyPem, pubKeyDerB64 } = generateKeyPair()
    const dkimValue = await harakaSign(HEADERS, BODY, privKeyPem)

    // Build the signed email Haraka produced
    const rawEmail = `${HEADERS.join('\r\n')}\r\n\r\n${BODY}`
    const signedEmail = `DKIM-Signature: ${dkimValue}\r\n${rawEmail}`

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-dkim-'))
    try {
      const signedPath = path.join(dir, 'signed.eml')
      fs.writeFileSync(signedPath, signedEmail)

      const succeeded = opendkimVerify(signedPath, pubKeyDerB64)
      assert.ok(
        succeeded,
        "opendkim must report 'succeeded' when verifying Haraka's rsa-sha256 signature",
      )
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })

  // ── Test 3: body hash agreement ───────────────────────────────────────────
  // Both implementations must produce the same bh= (SHA-256 of the
  // simple-canonicalized body) for the same input message.  A mismatch here
  // indicates a canonicalization bug in one of the two implementations.

  it('Haraka and opendkim produce identical body hashes (bh=)', async () => {
    const { privKeyPem } = generateKeyPair()

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'haraka-dkim-'))
    try {
      const msgPath = path.join(dir, 'msg.eml')
      const keyPath = path.join(dir, 'key.pem')

      const rawEmail = `${HEADERS.join('\r\n')}\r\n\r\n${BODY}`
      fs.writeFileSync(msgPath, rawEmail)
      fs.writeFileSync(keyPath, privKeyPem, { mode: 0o600 })

      // opendkim body hash
      const opendkimDkimHeader = opendkimSign(msgPath, keyPath)
      const opendkimBh = extractDkimTag(opendkimDkimHeader, 'bh')
      assert.ok(opendkimBh, 'opendkim must produce a bh= tag')

      // Haraka body hash
      const harakaDkimValue = await harakaSign(HEADERS, BODY, privKeyPem)
      const harakaBh = extractDkimTag(harakaDkimValue, 'bh')
      assert.ok(harakaBh, 'Haraka must produce a bh= tag')

      assert.equal(
        harakaBh,
        opendkimBh,
        `Body hash mismatch: Haraka bh=${harakaBh}, opendkim bh=${opendkimBh}. ` +
          'A mismatch indicates a simple-body-canonicalization divergence.',
      )
    } finally {
      fs.rmSync(dir, { recursive: true, force: true })
    }
  })
})
