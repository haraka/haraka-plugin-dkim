'use strict'

const assert = require('node:assert/strict')
const { describe, it, mock, afterEach } = require('node:test')
const crypto = require('node:crypto')
const dns = require('node:dns')
const fs = require('node:fs')
const path = require('node:path')

const message = require('haraka-email-message')

const { DKIMObject, DKIMSignStream, DKIMVerifyStream } = require('../lib/dkim')

// ─── Fixtures ───────────────────────────────────────────────────────────────

// 1024-bit RSA key — large enough for RSA-SHA256 signing, used for body hash
// and signing tests where key padding in DER doesn't matter.
const rsa1024PrivateKey = fs.readFileSync(
  path.join(__dirname, 'fixtures', 'rsa1024.private.pem'),
  'utf8',
)

// 1280-bit RSA key — always produces DER with base64 '=' padding; used for
// round-trip sign+verify to exercise the DNS p= truncation fix.
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

assert.ok(
  rsa1280PublicKeyDer.endsWith('='),
  'rsa1280 public key DER must have base64 = padding to exercise the truncation fix',
)

// ─── Helpers ────────────────────────────────────────────────────────────────

function getValueFromDKIMHeader(dkimHeader, key) {
  for (const kv of dkimHeader.split(';')) {
    const m = kv.match(/^\s*([^=]+)=(.*)$/)
    if (m && m[1].trim() === key) return m[2].trim()
  }
  throw new Error(`Key '${key}' not found in DKIM header: ${dkimHeader}`)
}

// Sign an email and resolve with the DKIM-Signature header value (after 'v=1; ...')
function signEmail(headerLines, body, headersList, privateKey) {
  return new Promise((resolve, reject) => {
    const emailStr = `${headerLines.join('\r\n')}\r\n\r\n${body}`
    const header = new message.Header()
    header.parse(headerLines)

    const props = {
      selector: 'testkey',
      domain: 'example.com',
      private_key: privateKey,
      headers: headersList,
    }

    const signer = new DKIMSignStream(props, header, (err, dkimValue) => {
      if (err) return reject(err)
      resolve(dkimValue)
    })
    signer.write(Buffer.from(emailStr))
    signer.end()
  })
}

// Build a full signed email string (DKIM-Signature header prepended)
function buildSignedEmail(headerLines, body, headersList, privateKey) {
  return signEmail(headerLines, body, headersList, privateKey).then(
    (dkimValue) => {
      const emailStr = `${headerLines.join('\r\n')}\r\n\r\n${body}`
      return `DKIM-Signature: ${dkimValue}\r\n${emailStr}`
    },
  )
}

afterEach(() => {
  mock.restoreAll()
})

// ─── DKIMObject.canonicalize — RFC 6376 §3.4.4 relaxed body canonicalization ─

describe('DKIMObject.canonicalize (relaxed body)', () => {
  function canon(str) {
    return DKIMObject.canonicalize(Buffer.from(str)).toString()
  }

  it('preserves normal line with CRLF', () => {
    assert.equal(canon('Hello world\r\n'), 'Hello world\r\n')
  })

  it('collapses multiple spaces to a single space', () => {
    assert.equal(canon('Hello  world\r\n'), 'Hello world\r\n')
  })

  it('replaces tab with a single space', () => {
    assert.equal(canon('Hello\tworld\r\n'), 'Hello world\r\n')
  })

  it('strips trailing whitespace before CRLF', () => {
    assert.equal(canon('Hello world   \r\n'), 'Hello world\r\n')
  })

  it('strips trailing tab before CRLF', () => {
    assert.equal(canon('Hello world\t\r\n'), 'Hello world\r\n')
  })

  it('collapses mixed WSP and strips trailing', () => {
    assert.equal(canon('Hello\t  world  \t\r\n'), 'Hello world\r\n')
  })

  it('returns CRLF-only line unchanged', () => {
    assert.equal(canon('\r\n'), '\r\n')
  })

  it('handles LF-only line ending', () => {
    // LF-only input: canonicalize should still append CRLF
    assert.equal(canon('Hello\n'), 'Hello\r\n')
  })

  it('signs with relaxed body canonicalization', (t, done) => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 1024,
    })
    const headerLines = ['From: <user@example.com>', 'Subject: Test']
    const hdr = new message.Header()
    hdr.parse(headerLines)

    const props = {
      selector: 'test',
      domain: 'example.com',
      private_key: privateKey,
      headers: ['from', 'subject'],
      body_canon: 'relaxed',
    }

    const signer = new DKIMSignStream(props, hdr, (err, dkimValue) => {
      assert.ifError(err)
      assert.ok(dkimValue.includes('c=relaxed/relaxed'))
      done()
    })

    // Relaxed body: ignore trailing spaces, collapse multiple spaces
    signer.write(Buffer.from('Line 1  \r\n'))
    signer.write(Buffer.from('Line    2\r\n'))
    signer.end()
  })
})

// ─── DKIMObject.header_canon_relaxed — RFC 6376 §3.4.2 relaxed header canon ──

describe('DKIMObject.header_canon_relaxed', () => {
  // Instantiate a DKIMObject just to access the method; use a valid header that
  // passes all constructor checks and never reaches DNS.
  // We only need prototype access — create via Object.create to avoid DNS calls
  function makeObj() {
    return Object.create(DKIMObject.prototype)
  }

  const obj = makeObj()

  it('lowercases the header name', () => {
    const result = obj.header_canon_relaxed('From: Alice\r\n')
    assert.ok(result.startsWith('from:'), `expected 'from:', got '${result}'`)
  })

  it('removes leading whitespace after the colon', () => {
    const result = obj.header_canon_relaxed('From:   Alice\r\n')
    assert.equal(result, 'from:Alice\r\n')
  })

  it('collapses internal whitespace in value', () => {
    const result = obj.header_canon_relaxed('Subject: Hello   World\r\n')
    assert.equal(result, 'subject:Hello World\r\n')
  })

  it('strips trailing whitespace before CRLF', () => {
    const result = obj.header_canon_relaxed('Subject: Hello  \r\n')
    assert.equal(result, 'subject:Hello\r\n')
  })

  it('unfolds continuation lines (FWS)', () => {
    const result = obj.header_canon_relaxed('Subject: Hello\r\n World\r\n')
    // CRLF + WSP → WSP, then WSP collapsed → single space
    assert.equal(result, 'subject:Hello World\r\n')
  })
})

// ─── DKIMSignStream body hashing — RFC 6376 §3.4.3 simple body canon ─────────

describe('DKIMSignStream body hashing (simple canonicalization)', () => {
  const props = {
    selector: 'selector',
    domain: 'haraka.top',
    private_key: rsa1024PrivateKey,
  }

  function makeSignStream(headers, callback) {
    const header = new message.Header()
    header.parse(headers)
    props.headers = ['from']
    return new DKIMSignStream(props, header, callback)
  }

  // RFC 6376 Appendix A known body hash for the example in that appendix.
  // Verified independently: echo -e -n 'Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n' | openssl dgst -binary -sha256 | openssl base64
  it('produces correct body hash for RFC 6376 Appendix A message', () => {
    const email =
      'Ignored: header\r\n\r\nHi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n'
    const signer = makeSignStream(['Ignored: header'], (_n, dkim) => {
      assert.equal(
        getValueFromDKIMHeader(dkim, 'bh'),
        '2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=',
      )
    })
    signer.write(Buffer.from(email))
    signer.end()
  })

  // SHA-256 of '\r\n' (empty body canonicalized) = frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=
  it('produces correct hash for empty body', () => {
    const email = 'Ignored: header\r\n\r\n'
    const signer = makeSignStream(['Ignored: header'], (_n, dkim) => {
      assert.equal(
        getValueFromDKIMHeader(dkim, 'bh'),
        'frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=',
      )
    })
    signer.write(Buffer.from(email))
    signer.end()
  })

  it('produces same hash when message is written in two chunks', () => {
    const signer = makeSignStream(['Ignored: header'], (_n, dkim) => {
      assert.equal(
        getValueFromDKIMHeader(dkim, 'bh'),
        '2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=',
      )
    })
    signer.write(
      Buffer.from('Ignored: header\r\n\r\nHi.\r\n\r\nWe lost the game. '),
    )
    signer.write(Buffer.from('Are you hungry yet?\r\n\r\nJoe.\r\n'))
    signer.end()
  })

  it('strips trailing CRLF lines per simple body canonicalization', () => {
    // Trailing empty lines must be removed; body hash must equal the one for
    // the same message without trailing CRLFs.
    const email =
      'Ignored: header\r\n\r\nHi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n\r\n\r\n'
    const signer = makeSignStream(['Ignored: header'], (_n, dkim) => {
      assert.equal(
        getValueFromDKIMHeader(dkim, 'bh'),
        '2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=',
      )
    })
    signer.write(Buffer.from(email))
    signer.end()
  })
})

// ─── DKIMSignStream header format ────────────────────────────────────────────

describe('DKIMSignStream header format', () => {
  it('produces a DKIM-Signature header with required tags', async () => {
    const dkimValue = await signEmail(
      ['From: test@example.com', 'Subject: Hello'],
      'Hello world\r\n',
      ['from', 'subject'],
      rsa1024PrivateKey,
    )
    // RFC 6376 §3.5: v=, a=, b=, bh=, d=, h=, s= are required
    assert.ok(dkimValue.includes('v=1'), 'must include v=1')
    assert.ok(dkimValue.includes('a=rsa-sha256'), 'must include a=rsa-sha256')
    assert.ok(dkimValue.includes('d=example.com'), 'must include d=')
    assert.ok(dkimValue.includes('s=testkey'), 'must include s=')
    assert.ok(dkimValue.includes('h=from'), 'must include h=')
    assert.ok(dkimValue.includes('bh='), 'must include bh=')
    assert.ok(dkimValue.includes('b='), 'must include b=')
  })

  it('emits one h= entry per signed instance when a header repeats (RFC 6376 §5.4.2)', async () => {
    // Two Received fields — both must be signed and named in h=.
    const dkimValue = await signEmail(
      [
        'Received: from mx2.example.net by relay.example.com',
        'Received: from sender.example.org by mx2.example.net',
        'From: test@example.com',
        'Subject: Hello',
      ],
      'Hello world\r\n',
      ['from', 'received', 'subject'],
      rsa1024PrivateKey,
    )
    const h = getValueFromDKIMHeader(dkimValue, 'h')
    // Two received instances → two `received` entries in h=
    const recvCount = h
      .toLowerCase()
      .split(':')
      .filter((n) => n === 'received').length
    assert.equal(
      recvCount,
      2,
      `expected two 'received' entries in h=, got: ${h}`,
    )
  })

  it('uses relaxed/simple canonicalization', async () => {
    const dkimValue = await signEmail(
      ['From: test@example.com'],
      'Hello\r\n',
      ['from'],
      rsa1024PrivateKey,
    )
    assert.ok(
      dkimValue.includes('c=relaxed/simple'),
      'must specify c=relaxed/simple',
    )
  })
})

// ─── Round-trip sign + verify ─────────────────────────────────────────────────

describe('sign + verify round-trip', () => {
  it('a signed message verifies as pass (1024-bit key)', (t, done) => {
    const crypto = require('node:crypto')
    const pubDer = crypto
      .createPublicKey(rsa1024PrivateKey)
      .export({ type: 'spki', format: 'der' })
      .toString('base64')

    buildSignedEmail(
      ['From: test@example.com'],
      'Hello world\r\n',
      ['from'],
      rsa1024PrivateKey,
    )
      .then((signedEmail) => {
        mock.method(dns.promises, 'resolveTxt', async () => {
          return [[`v=DKIM1; k=rsa; p=${pubDer}`]]
        })

        const verifier = new DKIMVerifyStream({ timeout: 5 }, (err, result) => {
          assert.ifError(err)
          assert.equal(result, 'pass', `expected pass, got ${result}`)
          done()
        })
        verifier.write(Buffer.from(signedEmail))
        verifier.end()
      })
      .catch(done)
  })

  it('a signed message verifies as pass (1280-bit key, DER with = padding)', (t, done) => {
    buildSignedEmail(
      ['From: test@example.com'],
      'Hello world\r\n',
      ['from'],
      rsa1280PrivateKey,
    )
      .then((signedEmail) => {
        mock.method(dns.promises, 'resolveTxt', async () => {
          return [[`v=DKIM1; k=rsa; p=${rsa1280PublicKeyDer}`]]
        })

        const verifier = new DKIMVerifyStream({ timeout: 5 }, (err, result) => {
          assert.ifError(err)
          assert.equal(
            result,
            'pass',
            `1280-bit key DER (ends with '=') must verify as pass; got ${result}`,
          )
          done()
        })
        verifier.write(Buffer.from(signedEmail))
        verifier.end()
      })
      .catch(done)
  })

  it('tampered body produces fail', (t, done) => {
    buildSignedEmail(
      ['From: test@example.com'],
      'Hello world\r\n',
      ['from'],
      rsa1280PrivateKey,
    )
      .then((signedEmail) => {
        const tamperedEmail = signedEmail.replace(
          'Hello world',
          'Tampered body',
        )

        mock.method(dns.promises, 'resolveTxt', async () => {
          return [[`v=DKIM1; k=rsa; p=${rsa1280PublicKeyDer}`]]
        })

        const verifier = new DKIMVerifyStream({ timeout: 5 }, (err, result) => {
          assert.ifError(err)
          assert.equal(
            result,
            'fail',
            `tampered body must produce fail; got ${result}`,
          )
          done()
        })
        verifier.write(Buffer.from(tamperedEmail))
        verifier.end()
      })
      .catch(done)
  })
})
