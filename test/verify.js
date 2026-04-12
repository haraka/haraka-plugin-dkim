'use strict'

const assert = require('node:assert/strict')
const { describe, it, mock, afterEach } = require('node:test')
const crypto = require('node:crypto')
const dns = require('node:dns')
const fs = require('node:fs')
const path = require('node:path')

const message = require('haraka-email-message')

const { DKIMObject, DKIMSignStream, DKIMVerifyStream } = require('../lib/dkim')

// ─── Fixtures ────────────────────────────────────────────────────────────────

const rsa1280PrivateKey = fs.readFileSync(
  path.join(__dirname, 'fixtures', 'rsa1280.private.pem'),
  'utf8',
)
const rsa1280PublicKeyDer = fs
  .readFileSync(
    path.join(__dirname, 'fixtures', 'rsa1280.public.der.b64'),
    'utf8',
  )
  .trim()

// SHA-256 of '\r\n' — the body hash for an empty body under simple canonicalization.
// Using this as bh= lets DKIMObject reach DNS without a real signed message.
const EMPTY_BH = 'frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY='

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeDkimHeader(overrides = {}) {
  const tags = {
    v: '1',
    a: 'rsa-sha256',
    d: 'example.com',
    s: 'test',
    h: 'from',
    bh: 'dGVzdA==',
    b: 'dGVzdA==',
    ...overrides,
  }
  return `DKIM-Signature: ${Object.entries(tags)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')}`
}

// Sign an email and return the full signed email string
function buildSignedEmail(headerLines, body, headersList) {
  return new Promise((resolve, reject) => {
    const emailStr = `${headerLines.join('\r\n')}\r\n\r\n${body}`
    const header = new message.Header()
    header.parse(headerLines)

    const props = {
      selector: 'testkey',
      domain: 'example.com',
      private_key: rsa1280PrivateKey,
      headers: headersList,
    }

    const signer = new DKIMSignStream(props, header, (err, dkimValue) => {
      if (err) return reject(err)
      resolve(`DKIM-Signature: ${dkimValue}\r\n${emailStr}`)
    })
    signer.write(Buffer.from(emailStr))
    signer.end()
  })
}

// Run a DKIMObject to completion with empty-body trick (reaches DNS path).
// Returns a Promise resolving to { err, result }.
function runDkimObjectToDns(headerOverrides, dnsResponse) {
  return new Promise((resolve) => {
    const header = makeDkimHeader({
      bh: EMPTY_BH,
      b: 'dGVzdA==',
      ...headerOverrides,
    })

    mock.method(dns, 'resolveTxt', (_name, cb) => {
      if (dnsResponse instanceof Error) {
        cb(dnsResponse)
      } else {
        cb(null, dnsResponse)
      }
    })

    const obj = new DKIMObject(
      header,
      {},
      (err, result) => resolve({ err, result }),
      { timeout: 5 },
    )
    // Only call end() if the constructor didn't already fire the callback
    // (which it does for early-exit error cases)
    if (!obj.run_cb) obj.end()
  })
}

afterEach(() => {
  mock.restoreAll()
})

// ─── DKIMObject field validation (RFC 6376 §6.1.1 — fires before DNS) ────────

describe('DKIMObject field validation', () => {
  const emptyIdx = {}

  function validate(headerOverrides) {
    let result
    new DKIMObject(
      makeDkimHeader(headerOverrides),
      emptyIdx,
      (_err, r) => {
        result = r
      },
      { timeout: 5 },
    )
    return result
  }

  describe('v= (version)', () => {
    it('missing v= produces invalid', () => {
      // Remove v= by building the header manually
      const header =
        'DKIM-Signature: a=rsa-sha256; d=example.com; s=test; h=from; bh=dGVzdA==; b=dGVzdA=='
      let result
      new DKIMObject(
        header,
        emptyIdx,
        (_err, r) => {
          result = r
        },
        { timeout: 5 },
      )
      assert.ok(result, 'callback must fire synchronously')
      assert.equal(result.result, 'invalid')
    })

    it('wrong version (v=2) produces invalid', () => {
      const r = validate({ v: '2' })
      assert.ok(r, 'callback must fire synchronously')
      assert.equal(r.result, 'invalid')
    })
  })

  describe('l= (body length tag)', () => {
    it('l= tag produces invalid (not none)', () => {
      // 'none' semantically means no signature; but the signature IS present.
      // RFC 6376 §3.5: l= is dangerous and rejected by this implementation.
      const r = validate({ l: '100' })
      assert.ok(r, 'callback must fire synchronously')
      assert.equal(
        r.result,
        'invalid',
        `l= should produce 'invalid', got '${r?.result}'`,
      )
    })
  })

  describe('a= (algorithm)', () => {
    it('rsa-sha1 produces invalid (RFC 8301 §3.2)', () => {
      const r = validate({ a: 'rsa-sha1' })
      assert.ok(r, 'callback must fire synchronously')
      assert.equal(r.result, 'invalid', `rsa-sha1 must be rejected`)
    })

    it('unknown algorithm produces invalid', () => {
      const r = validate({ a: 'rsa-sha512' })
      assert.ok(r, 'callback must fire synchronously')
      assert.equal(r.result, 'invalid')
    })

    it('missing a= produces invalid', () => {
      const header =
        'DKIM-Signature: v=1; d=example.com; s=test; h=from; bh=dGVzdA==; b=dGVzdA=='
      let result
      new DKIMObject(
        header,
        emptyIdx,
        (_err, r) => {
          result = r
        },
        { timeout: 5 },
      )
      assert.ok(result)
      assert.equal(result.result, 'invalid')
    })
  })

  describe('required tags', () => {
    it('missing b= produces invalid', () => {
      const header =
        'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; h=from; bh=dGVzdA=='
      let result
      new DKIMObject(
        header,
        emptyIdx,
        (_err, r) => {
          result = r
        },
        { timeout: 5 },
      )
      assert.ok(result)
      assert.equal(result.result, 'invalid')
    })

    it('missing bh= produces invalid', () => {
      const header =
        'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; h=from; b=dGVzdA=='
      let result
      new DKIMObject(
        header,
        emptyIdx,
        (_err, r) => {
          result = r
        },
        { timeout: 5 },
      )
      assert.ok(result)
      assert.equal(result.result, 'invalid')
    })

    it('missing d= produces invalid', () => {
      const header =
        'DKIM-Signature: v=1; a=rsa-sha256; s=test; h=from; bh=dGVzdA==; b=dGVzdA=='
      let result
      new DKIMObject(
        header,
        emptyIdx,
        (_err, r) => {
          result = r
        },
        { timeout: 5 },
      )
      assert.ok(result)
      assert.equal(result.result, 'invalid')
    })

    it('missing h= produces invalid', () => {
      const header =
        'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; bh=dGVzdA==; b=dGVzdA=='
      let result
      new DKIMObject(
        header,
        emptyIdx,
        (_err, r) => {
          result = r
        },
        { timeout: 5 },
      )
      assert.ok(result)
      assert.equal(result.result, 'invalid')
    })

    it('h= without From produces invalid', () => {
      const r = validate({ h: 'subject:date' })
      assert.ok(r)
      assert.equal(r.result, 'invalid')
    })
  })

  describe('q= (query method)', () => {
    it('q=dns/txt is accepted (callback not fired synchronously)', () => {
      const r = validate({ q: 'dns/txt' })
      assert.equal(
        r,
        undefined,
        'valid q= must not fire callback synchronously',
      )
    })

    it('unsupported q= method produces invalid', () => {
      const r = validate({ q: 'other/method' })
      assert.ok(r)
      assert.equal(r.result, 'invalid')
    })
  })

  describe('i= (signing identity)', () => {
    it('i=@d is valid', () => {
      const r = validate({ i: '@example.com' })
      assert.equal(r, undefined, 'i=@d must be valid')
    })

    it('i=user@d is valid', () => {
      const r = validate({ i: 'user@example.com' })
      assert.equal(r, undefined)
    })

    it('i=user@subdomain.d is valid (subdomain)', () => {
      const r = validate({ i: 'user@sub.example.com' })
      assert.equal(r, undefined)
    })

    it('i= with different domain produces invalid', () => {
      const r = validate({ i: 'user@other.com' })
      assert.ok(r)
      assert.equal(r.result, 'invalid')
    })

    it('i= that ends with d= but is not a subdomain produces invalid', () => {
      // '@evilexample.com' ends with 'example.com' but prevChar is not '@' or '.'
      const r = validate({ i: '@evilexample.com' })
      assert.ok(r)
      assert.equal(r.result, 'invalid')
    })
  })

  describe('t= (signature timestamp)', () => {
    it('future t= produces invalid', () => {
      const future = Math.floor(Date.now() / 1000) + 86400
      const r = validate({ t: String(future) })
      assert.ok(r)
      assert.equal(r.result, 'invalid')
    })

    it('past t= is accepted', () => {
      const past = Math.floor(Date.now() / 1000) - 86400
      const r = validate({ t: String(past) })
      assert.equal(r, undefined)
    })
  })

  describe('x= (expiration)', () => {
    it('expired x= produces invalid', () => {
      const past = Math.floor(Date.now() / 1000) - 86400
      const r = validate({ x: String(past) })
      assert.ok(r)
      assert.equal(r.result, 'invalid')
    })

    it('x= before t= (expiry < creation) produces invalid', () => {
      const now = Math.floor(Date.now() / 1000)
      const r = validate({ t: String(now - 100), x: String(now - 200) })
      assert.ok(r)
      assert.equal(r.result, 'invalid')
    })

    it('future x= with past t= is accepted', () => {
      const now = Math.floor(Date.now() / 1000)
      const r = validate({ t: String(now - 100), x: String(now + 86400) })
      assert.equal(r, undefined)
    })
  })

  describe('c= (canonicalization)', () => {
    it('c=relaxed/relaxed sets both canon modes without error', () => {
      const r = validate({ c: 'relaxed/relaxed' })
      assert.equal(r, undefined)
    })

    it('c=simple/simple sets both canon modes without error', () => {
      const r = validate({ c: 'simple/simple' })
      assert.equal(r, undefined)
    })
  })
})

// ─── DNS record validation (DKIMObject reaching the DNS path) ────────────────
// Tests use the empty-body-hash trick: bh=SHA256('\r\n') so body hash matches
// without needing a real signed message, allowing testing of DNS-path logic.

describe('DNS record validation', () => {
  it('NXDOMAIN produces invalid', async () => {
    const nxErr = Object.assign(new Error('NXDOMAIN'), { code: dns.NXDOMAIN })
    const { result } = await runDkimObjectToDns({}, nxErr)
    assert.equal(result.result, 'invalid')
  })

  it('NOTFOUND produces invalid', async () => {
    const err = Object.assign(new Error('NOTFOUND'), { code: dns.NOTFOUND })
    const { result } = await runDkimObjectToDns({}, err)
    assert.equal(result.result, 'invalid')
  })

  it('NODATA produces invalid', async () => {
    const err = Object.assign(new Error('NODATA'), { code: dns.NODATA })
    const { result } = await runDkimObjectToDns({}, err)
    assert.equal(result.result, 'invalid')
  })

  it('transient DNS error produces tempfail', async () => {
    const err = Object.assign(new Error('SERVFAIL'), { code: 'ESERVFAIL' })
    const { result } = await runDkimObjectToDns({}, err)
    assert.equal(result.result, 'tempfail')
  })

  it('empty DNS response produces invalid', async () => {
    const { result } = await runDkimObjectToDns({}, [])
    assert.equal(result.result, 'invalid')
  })

  it('multiple TXT records produce invalid', async () => {
    const { result } = await runDkimObjectToDns({}, [
      ['v=DKIM1; k=rsa; p=' + rsa1280PublicKeyDer],
      ['v=DKIM1; k=rsa; p=' + rsa1280PublicKeyDer],
    ])
    assert.equal(result.result, 'invalid')
  })

  describe('p= (public key)', () => {
    it('empty p= (revoked key) produces invalid', async () => {
      const { result } = await runDkimObjectToDns({}, [['v=DKIM1; k=rsa; p=']])
      assert.equal(result.result, 'invalid')
    })

    it('p= value with base64 = padding is parsed correctly', (t, done) => {
      // Regression test: element.split('=') truncated base64 padding.
      assert.ok(
        rsa1280PublicKeyDer.endsWith('='),
        'test premise: DER must have = padding',
      )
      buildSignedEmail(['From: test@example.com'], 'Hello world\r\n', ['from'])
        .then((signedEmail) => {
          mock.method(dns, 'resolveTxt', (_name, cb) => {
            cb(null, [['v=DKIM1; k=rsa; p=' + rsa1280PublicKeyDer]])
          })

          const verifier = new DKIMVerifyStream(
            { timeout: 5 },
            (err, result) => {
              assert.ifError(err)
              assert.equal(
                result,
                'pass',
                `p= with '=' padding must verify as pass; got '${result}'. ` +
                  `Regression: split('=') drops base64 padding.`,
              )
              done()
            },
          )
          verifier.write(Buffer.from(signedEmail))
          verifier.end()
        })
        .catch(done)
    })
  })

  describe('v= (DNS record version)', () => {
    it('wrong DNS v= produces invalid', async () => {
      const { result } = await runDkimObjectToDns({}, [
        ['v=DKIM2; k=rsa; p=' + rsa1280PublicKeyDer],
      ])
      assert.equal(result.result, 'invalid')
    })
  })

  describe('k= (key type)', () => {
    it('k=rsa matches rsa-sha256 signature', (t, done) => {
      buildSignedEmail(['From: test@example.com'], 'Hello world\r\n', ['from'])
        .then((signedEmail) => {
          mock.method(dns, 'resolveTxt', (_name, cb) => {
            cb(null, [['v=DKIM1; k=rsa; p=' + rsa1280PublicKeyDer]])
          })
          const verifier = new DKIMVerifyStream(
            { timeout: 5 },
            (err, result) => {
              assert.ifError(err)
              assert.equal(result, 'pass')
              done()
            },
          )
          verifier.write(Buffer.from(signedEmail))
          verifier.end()
        })
        .catch(done)
    })

    it('k= mismatch produces invalid', async () => {
      // a=rsa-sha256 but DNS says k=ec
      const { result } = await runDkimObjectToDns({}, [
        ['v=DKIM1; k=ec; p=' + rsa1280PublicKeyDer],
      ])
      assert.equal(result.result, 'invalid')
    })
  })

  describe('h= (acceptable hash algorithms in DNS record)', () => {
    it('hash algorithm in single-value h= list produces pass', (t, done) => {
      buildSignedEmail(['From: test@example.com'], 'Hello world\r\n', ['from'])
        .then((signedEmail) => {
          mock.method(dns, 'resolveTxt', (_name, cb) => {
            cb(null, [['v=DKIM1; k=rsa; h=sha256; p=' + rsa1280PublicKeyDer]])
          })
          const verifier = new DKIMVerifyStream(
            { timeout: 5 },
            (err, result) => {
              assert.ifError(err)
              assert.equal(result, 'pass')
              done()
            },
          )
          verifier.write(Buffer.from(signedEmail))
          verifier.end()
        })
        .catch(done)
    })

    it('hash algorithm in multi-value h= list produces pass', (t, done) => {
      // Regression: old code checked if each h= value was a substring of a=,
      // so h=sha256:sha512 failed because 'sha512' is not in 'rsa-sha256'.
      buildSignedEmail(['From: test@example.com'], 'Hello world\r\n', ['from'])
        .then((signedEmail) => {
          mock.method(dns, 'resolveTxt', (_name, cb) => {
            cb(null, [
              ['v=DKIM1; k=rsa; h=sha256:sha512; p=' + rsa1280PublicKeyDer],
            ])
          })
          const verifier = new DKIMVerifyStream(
            { timeout: 5 },
            (err, result) => {
              assert.ifError(err)
              assert.equal(
                result,
                'pass',
                `sha256 is in [sha256, sha512]; expected pass, got '${result}'`,
              )
              done()
            },
          )
          verifier.write(Buffer.from(signedEmail))
          verifier.end()
        })
        .catch(done)
    })

    it('hash algorithm not in h= list produces invalid', (t, done) => {
      buildSignedEmail(['From: test@example.com'], 'Hello world\r\n', ['from'])
        .then((signedEmail) => {
          mock.method(dns, 'resolveTxt', (_name, cb) => {
            // Only sha1 is acceptable; signature uses sha256
            cb(null, [['v=DKIM1; k=rsa; h=sha1; p=' + rsa1280PublicKeyDer]])
          })
          const verifier = new DKIMVerifyStream(
            { timeout: 5 },
            (err, result) => {
              assert.ifError(err)
              assert.equal(
                result,
                'invalid',
                `sha256 not in h=sha1; expected invalid, got '${result}'`,
              )
              done()
            },
          )
          verifier.write(Buffer.from(signedEmail))
          verifier.end()
        })
        .catch(done)
    })
  })

  describe('g= (granularity)', () => {
    it('g=* (wildcard) matches any local part', (t, done) => {
      buildSignedEmail(['From: test@example.com'], 'Hello\r\n', ['from'])
        .then((signedEmail) => {
          mock.method(dns, 'resolveTxt', (_name, cb) => {
            cb(null, [['v=DKIM1; k=rsa; g=*; p=' + rsa1280PublicKeyDer]])
          })
          const verifier = new DKIMVerifyStream(
            { timeout: 5 },
            (err, result) => {
              assert.ifError(err)
              assert.equal(result, 'pass')
              done()
            },
          )
          verifier.write(Buffer.from(signedEmail))
          verifier.end()
        })
        .catch(done)
    })

    it('g= pattern mismatch produces invalid', async () => {
      // i=@example.com (default), g=admin — '@' does not match '^admin@'
      const { result } = await runDkimObjectToDns({}, [
        ['v=DKIM1; k=rsa; g=admin; p=' + rsa1280PublicKeyDer],
      ])
      assert.equal(result.result, 'invalid')
    })
  })

  describe('t= (DNS flags)', () => {
    it('t=y (test mode) flag does not cause premature rejection', async () => {
      // t=y means the domain owner is testing DKIM; verification continues normally.
      // With a dummy b= the crypto verify fails → 'fail', not 'invalid'.
      const { result } = await runDkimObjectToDns({}, [
        ['v=DKIM1; k=rsa; t=y; p=' + rsa1280PublicKeyDer],
      ])
      // Result is either 'pass' or 'fail' (crypto) but NOT 'invalid' (premature rejection)
      assert.notEqual(result.result, 'invalid', 't=y must not cause invalid')
    })

    it('t=s (strict) flag: subdomain i= produces invalid', async () => {
      // With t=s, i= local domain must exactly match d=, not merely be a subdomain.
      // i=user@sub.example.com, d=example.com → 'sub.example.com' !== 'example.com' → invalid
      const { result } = await runDkimObjectToDns(
        { i: 'user@sub.example.com' },
        [['v=DKIM1; k=rsa; t=s; p=' + rsa1280PublicKeyDer]],
      )
      assert.equal(result.result, 'invalid')
    })

    it('t=s (strict) flag: exact domain i= is accepted', async () => {
      // i=@example.com, d=example.com → after '@' gives 'example.com' === d → passes t=s
      // Crypto verify fails (dummy b=) → 'fail', not 'invalid'
      const { result } = await runDkimObjectToDns({ i: '@example.com' }, [
        ['v=DKIM1; k=rsa; t=s; p=' + rsa1280PublicKeyDer],
      ])
      assert.notEqual(
        result.result,
        'invalid',
        't=s with exact domain must not produce invalid',
      )
    })
  })
})

// ─── DKIMVerifyStream flow tests ──────────────────────────────────────────────

describe('DKIMVerifyStream', () => {
  it('email with no DKIM-Signature header produces result none', (t, done) => {
    const email = 'From: test@example.com\r\n\r\nHello world\r\n'
    const verifier = new DKIMVerifyStream(
      { timeout: 5 },
      (err, result, results) => {
        assert.ifError(err)
        assert.equal(result, 'none')
        assert.deepEqual(results, [])
        done()
      },
    )
    verifier.write(Buffer.from(email))
    verifier.end()
  })

  it('result aggregation: pass then fail yields overall pass', (t, done) => {
    // Regression: the priority loop could overwrite 'pass' with a later 'fail'.
    // RFC 6376 §6.1: the most favorable result across all signatures must be used.
    //
    // The GOOD signature is first (testkey); the BAD signature has a wrong body
    // hash so it fails before any DNS call.  With the bug, 'fail' would overwrite
    // the earlier 'pass'.
    buildSignedEmail(['From: test@example.com'], 'Hello world\r\n', ['from'])
      .then((signedEmail) => {
        const badSig =
          'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=badsig; ' +
          'h=from; bh=dGVzdA==; b=dGVzdA==\r\n'
        // Insert bad signature AFTER the good one so good sig is processed first
        const twoSigEmail = signedEmail.replace(
          '\r\nFrom: test@example.com',
          `\r\n${badSig}From: test@example.com`,
        )

        mock.method(dns, 'resolveTxt', (name, cb) => {
          if (name.startsWith('testkey.')) {
            cb(null, [['v=DKIM1; k=rsa; p=' + rsa1280PublicKeyDer]])
          } else {
            const err = Object.assign(new Error('NXDOMAIN'), {
              code: dns.NXDOMAIN,
            })
            cb(err)
          }
        })

        const verifier = new DKIMVerifyStream({ timeout: 5 }, (err, result) => {
          assert.ifError(err)
          assert.equal(
            result,
            'pass',
            `A passing signature must not be overridden by a later failing one; got '${result}'`,
          )
          done()
        })
        verifier.write(Buffer.from(twoSigEmail))
        verifier.end()
      })
      .catch(done)
  })

  it('result aggregation: fail then pass yields overall pass', (t, done) => {
    // Complementary to the above: good signature comes SECOND.
    buildSignedEmail(['From: test@example.com'], 'Hello world\r\n', ['from'])
      .then((signedEmail) => {
        const badSig =
          'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=badsig; ' +
          'h=from; bh=dGVzdA==; b=dGVzdA==\r\n'
        // Insert bad signature BEFORE the good one — bad sig processed first
        const twoSigEmail = badSig + signedEmail

        mock.method(dns, 'resolveTxt', (name, cb) => {
          if (name.startsWith('testkey.')) {
            cb(null, [['v=DKIM1; k=rsa; p=' + rsa1280PublicKeyDer]])
          } else {
            const err = Object.assign(new Error('NXDOMAIN'), {
              code: dns.NXDOMAIN,
            })
            cb(err)
          }
        })

        const verifier = new DKIMVerifyStream({ timeout: 5 }, (err, result) => {
          assert.ifError(err)
          assert.equal(
            result,
            'pass',
            `pass must win regardless of order; got '${result}'`,
          )
          done()
        })
        verifier.write(Buffer.from(twoSigEmail))
        verifier.end()
      })
      .catch(done)
  })

  it('two signatures with wrong body hashes both produce fail overall', (t, done) => {
    // Both signatures have bh= that does not match the actual body.
    // Body hash mismatch → 'fail' (not 'invalid'); both fail → overall 'fail'.
    const badSig1 =
      'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=bad1; h=from; bh=dGVzdA==; b=dGVzdA==\r\n'
    const badSig2 =
      'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=bad2; h=from; bh=dGVzdA==; b=dGVzdA==\r\n'
    const email = `${badSig1}${badSig2}From: test@example.com\r\n\r\nHello\r\n`

    const verifier = new DKIMVerifyStream({ timeout: 5 }, (err, result) => {
      assert.ifError(err)
      // Body hash mismatch fires before DNS → 'fail', not 'invalid'
      assert.equal(result, 'fail')
      done()
    })
    verifier.write(Buffer.from(email))
    verifier.end()
  })
})

describe('MAX_HEADER_SIZE', () => {
  it('rejects headers exceeding MAX_HEADER_SIZE', (t, done) => {
    process.env.MAX_HEADER_SIZE = '100'
    const verifier = new DKIMVerifyStream({}, (err) => {
      assert.ok(err)
      assert.equal(err.message, 'maximum header size exceeded')
      delete process.env.MAX_HEADER_SIZE
      done()
    })

    const largeHeader = 'X-Large: ' + 'a'.repeat(200) + '\r\n'
    verifier.write(Buffer.from(largeHeader))
  })
})

describe('Ed25519 Support (RFC 8463)', () => {
  it('verifies an Ed25519 signature', (t, done) => {
    // Generate Ed25519 key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
    const pubKeyBase64 = publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64')

    const header = 'From: <user@example.com>\r\n'
    const body = 'Hello World\r\n'

    const bh = crypto.createHash('sha256').update(body).digest('base64')

    // Manually construct DKIM-Signature for ed25519-sha256
    const dkimHeaderPartial = `v=1; a=ed25519-sha256; c=relaxed/simple; d=example.com; s=ed25519; h=from; bh=${bh}; b=`

    // Use the actual implementation's canonicalization
    const dkimObj = new DKIMObject(
      `DKIM-Signature: ${dkimHeaderPartial}`,
      {},
      () => {},
      { timeout: 1 },
    )
    const canonHeader = dkimObj.header_canon_relaxed(header)

    let canonDkimSig = dkimObj.header_canon_relaxed(
      `DKIM-Signature: ${dkimHeaderPartial}`,
    )
    canonDkimSig = canonDkimSig.replace(/\r\n$/, '') // implementation removes trailing CRLF

    const dataToSign = Buffer.from(canonHeader + canonDkimSig)
    const signature = crypto
      .sign(null, dataToSign, privateKey)
      .toString('base64')

    const fullDkimHeader = `DKIM-Signature: ${dkimHeaderPartial}${signature}\r\n`
    const fullEmail = `${fullDkimHeader}${header}\r\n${body}`

    mock.method(dns, 'resolveTxt', (name, cb) => {
      assert.equal(name, 'ed25519._domainkey.example.com')
      cb(null, [['v=DKIM1; k=ed25519; p=' + pubKeyBase64]])
    })

    const verifier = new DKIMVerifyStream({}, (err, result, results) => {
      assert.ifError(err)
      assert.equal(result, 'pass')
      assert.equal(results[0].result, 'pass')
      done()
    })

    verifier.write(Buffer.from(fullEmail))
    verifier.end()
  })
})
