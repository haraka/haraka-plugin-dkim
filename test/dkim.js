'use strict'

const assert = require('node:assert/strict')
const { describe, it, mock, afterEach } = require('node:test')
const dns = require('node:dns')
const message = require('haraka-email-message')

const { DKIMObject, DKIMSignStream, DKIMVerifyStream } = require('../lib/dkim')

// 1280-bit RSA key pair used only for testing.
// 1280-bit was chosen because: (a) large enough for RSA-SHA256, (b) the public
// key DER encoding is guaranteed to have base64 '=' padding — which is exactly
// the condition that exposes the DNS record parsing bug (split('=') truncation).
const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIC7QIBAAKBoQDIsvWBWZJjFs7w4ytubt57+gcw6DNk99YWDMI3JJwsaB9Nh6sO
f8S9e8SmiHqmlSXn3d5WuzJ19MgKrPnrjJkbcuxR4qIDIFWsxRhp3ba7zrWy8B73
HM03GzEFzSzTftKPXdKdqXz7MMywGSimFsztJpJyUdbnvj4ArT2vSw3HYNVPCofl
NnPd43iaDgQSHbZvtZYJ25AayJyj3cuLD2rNAgMBAAECgaBYgLJKjBlFoPU4vLSW
SkXKHgO1yW+Agtnhd1bdwkMsQe4r3jvMdQNpG38ogN61PugsS2aUkJA7++mK66R5
/tI1jIQxx+LxxfyB55hQdvjx7/lqyp81KQXJbwum9gAaAxyvyjEij4M/8aZTl3oE
Uj91scPNjjclfi0Hk/t38YZAkM6S6256PZcqvv0mhPhKvnvvKIEKRtBlACWA+JTB
zJPxAlEA8AHBOFWtOh3k08w64ujJAgohaBlvtEuXFNoEUr3SXr0qt2B2Q1hnRbWY
gqtl6ye0h/ms0GJe1QjKR4axCzw+nQZKc7pdqeodYUvc21iL8sMCUQDWEqhhnmwK
adlzUSelJ82HyYY/0EsqTq89sHi0o1AyKk3DMbqnQ1NDN7C/li/p8tduW+dA51QM
CFCS2yX9w1niehFhtclq7AgB5dJUReszLwJQcZMTAXqhx9+/mm6J6zjnbhynJGDt
GG+w5gApjZIgTA7OeQqfzEy4SieeLS+4wif+6V3AZrg2Ui+fsWtOupdeteX1M4Cc
tDyCfLluoSnsyAsCUQC76J7DKaOetHE65zbMoxanpb7hDv6bwXvTw68AqQZBMp8V
wvYb0l4o955/Xd7rFc4CwktIzoYZFcdcUV+U08B3qzzMrxyBbXRN7iVk8gbV4wJR
AJS7xoGl7EnnmaaQNriVJ6pyDMiP4V/pAxL2c/Qv1T7Jp9OfC42hfXCoJu0tp8VO
HI8m/wPxYzR34+wsmcaaNALgXHOTWvkiOHiefWSBYZRH
-----END RSA PRIVATE KEY-----`

// DER base64 of the public key — ends with '=' (confirmed during key generation)
const testPublicKeyDer =
  'MIG/MA0GCSqGSIb3DQEBAQUAA4GtADCBqQKBoQDIsvWBWZJjFs7w4ytubt57+gcw' +
  '6DNk99YWDMI3JJwsaB9Nh6sOf8S9e8SmiHqmlSXn3d5WuzJ19MgKrPnrjJkbcux' +
  'R4qIDIFWsxRhp3ba7zrWy8B73HM03GzEFzSzTftKPXdKdqXz7MMywGSimFsztJpJ' +
  'yUdbnvj4ArT2vSw3HYNVPCoflNnPd43iaDgQSHbZvtZYJ25AayJyj3cuLD2rNAgMBAAE='

// Verify that our test key actually has '=' padding (guards the test premise)
assert.ok(
  testPublicKeyDer.endsWith('='),
  'test public key DER must have base64 = padding to exercise the truncation bug',
)

// Build a DKIMObject header string with specified tag overrides
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
  const value = Object.entries(tags)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ')
  return `DKIM-Signature: ${value}`
}

// Sign an email string and call done(err, signedEmailString)
function signEmail(emailLines, bodyLine, headersList, done) {
  const emailStr = `${emailLines.join('\r\n')}\r\n\r\n${bodyLine}`
  const header = new message.Header()
  header.parse(emailLines)

  const props = {
    selector: 'testkey',
    domain: 'example.com',
    private_key: testPrivateKey,
    headers: headersList,
  }

  const signer = new DKIMSignStream(props, header, (err, dkimValue) => {
    if (err) return done(err)
    // Prepend the DKIM-Signature header to the original email
    const signedEmail = `DKIM-Signature: ${dkimValue}\r\n${emailStr}`
    done(null, signedEmail)
  })
  signer.write(Buffer.from(emailStr))
  signer.end()
}

afterEach(() => {
  mock.restoreAll()
})

// ─── DKIMObject unit tests (synchronous — no DNS needed) ─────────────────────

describe('DKIMObject', () => {
  const emptyIdx = {}

  describe('l= tag', () => {
    it('returns invalid (not none) when l= tag is present', () => {
      // The l= (body length) tag is rejected as a security risk.
      // Result must be 'invalid' — NOT 'none' which means "no signature present".
      const header = makeDkimHeader({ l: '100' })
      let callbackResult
      new DKIMObject(
        header,
        emptyIdx,
        (err, result) => {
          callbackResult = result
        },
        { timeout: 5 },
      )
      assert.ok(callbackResult, 'callback must fire synchronously')
      assert.equal(
        callbackResult.result,
        'invalid',
        `l= tag should produce 'invalid', got '${callbackResult?.result}'`,
      )
    })
  })

  describe('rsa-sha1 rejection', () => {
    it('rejects rsa-sha1 as an insecure algorithm (RFC 8301)', () => {
      // RFC 8301 §3.2: verifiers MUST NOT treat messages with rsa-sha1 as
      // having a valid author signature.
      const header = makeDkimHeader({ a: 'rsa-sha1' })
      let callbackResult
      new DKIMObject(
        header,
        emptyIdx,
        (err, result) => {
          callbackResult = result
        },
        { timeout: 5 },
      )
      assert.ok(callbackResult, 'callback must fire synchronously for rejected algorithm')
      assert.equal(
        callbackResult.result,
        'invalid',
        `rsa-sha1 should be rejected with 'invalid', got '${callbackResult?.result}'`,
      )
    })
  })
})

// ─── End-to-end verification tests (require DNS mock) ────────────────────────

describe('DNS record parsing', () => {
  it('correctly parses p= value containing base64 = padding', (t, done) => {
    // BUG: element.split('=') discards everything after the first '='.
    // The test public key ends with '=' (base64 padding).  The bug truncates
    // the key, causing crypto.createVerify().verify() to throw → result 'invalid'.
    // After fix (split only on the first '='), the full key is used → 'pass'.
    signEmail(['From: test@example.com'], 'Hello world\r\n', ['from'], (err, signedEmail) => {
      assert.ifError(err)

      mock.method(dns, 'resolveTxt', (_name, cb) => {
        // p= value has trailing '=' — the bug silently drops it
        cb(null, [['v=DKIM1; k=rsa; p=' + testPublicKeyDer]])
      })

      const verifier = new DKIMVerifyStream({ timeout: 5 }, (vErr, result) => {
        assert.ifError(vErr)
        assert.equal(
          result,
          'pass',
          `p= with '=' padding must verify as 'pass', got '${result}'. ` +
            `Bug: split('=') truncates the trailing base64 padding.`,
        )
        done()
      })
      verifier.write(Buffer.from(signedEmail))
      verifier.end()
    })
  })
})

describe('h= algorithm restriction', () => {
  it('accepts a signature whose hash algorithm is in a multi-value h= list', (t, done) => {
    // BUG: the check iterates over each value in h= and tests whether it is a
    // substring of the a= tag.  For h=sha256:sha512 this fails because 'sha512'
    // is not in 'rsa-sha256' — but it SHOULD pass because the algorithm actually
    // used ('sha256') IS in the acceptable list [sha256, sha512].
    signEmail(['From: test@example.com'], 'Hello world\r\n', ['from'], (err, signedEmail) => {
      assert.ifError(err)

      mock.method(dns, 'resolveTxt', (_name, cb) => {
        // sha256 and sha512 are both acceptable; signature uses sha256 → pass
        cb(null, [['v=DKIM1; k=rsa; h=sha256:sha512; p=' + testPublicKeyDer]])
      })

      const verifier = new DKIMVerifyStream({ timeout: 5 }, (vErr, result) => {
        assert.ifError(vErr)
        assert.equal(
          result,
          'pass',
          `sha256 is in acceptable list [sha256, sha512]; expected 'pass', got '${result}'. ` +
            `Bug: h= check tests each acceptable hash as substring of a= instead of the reverse.`,
        )
        done()
      })
      verifier.write(Buffer.from(signedEmail))
      verifier.end()
    })
  })

  it('rejects a signature whose hash algorithm is not in the h= list', (t, done) => {
    signEmail(['From: test@example.com'], 'Hello world\r\n', ['from'], (err, signedEmail) => {
      assert.ifError(err)

      mock.method(dns, 'resolveTxt', (_name, cb) => {
        // Only sha1 is acceptable; signature uses sha256 → must be rejected
        cb(null, [['v=DKIM1; k=rsa; h=sha1; p=' + testPublicKeyDer]])
      })

      const verifier = new DKIMVerifyStream({ timeout: 5 }, (vErr, result) => {
        assert.ifError(vErr)
        assert.equal(
          result,
          'invalid',
          `sha256 is not in h=sha1 list; expected 'invalid', got '${result}'`,
        )
        done()
      })
      verifier.write(Buffer.from(signedEmail))
      verifier.end()
    })
  })
})

describe('result aggregation for multiple DKIM signatures', () => {
  it('returns pass when first signature passes and second has a body hash mismatch', (t, done) => {
    // BUG: the priority loop sets self.result to each new result that differs
    // from the current value, so when 'fail' arrives after 'pass' it overwrites
    // the 'pass'.  RFC 6376 §6.1: take the most favorable result.
    //
    // To trigger the bug the PASSING signature must be processed FIRST and the
    // FAILING one second.  Because DNS is mocked synchronously, processing order
    // follows declaration order in the email headers.  We put the good signature
    // first (testkey) and a fake signature with a wrong body hash second so it
    // fails at body-hash check without a DNS call.
    signEmail(['From: test@example.com'], 'Hello world\r\n', ['from'], (err, signedEmail) => {
      assert.ifError(err)

      // signedEmail = "DKIM-Signature: <good>\r\nFrom: ...\r\n\r\nbody"
      // Insert a bad DKIM-Signature AFTER the good one, before From:
      const badSig =
        'DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=badsig; ' +
        'h=from; bh=dGVzdA==; b=dGVzdA==\r\n'
      const twoSigEmail = signedEmail.replace(
        '\r\nFrom: test@example.com',
        `\r\n${badSig}From: test@example.com`,
      )

      mock.method(dns, 'resolveTxt', (name, cb) => {
        if (name.startsWith('testkey.')) {
          cb(null, [['v=DKIM1; k=rsa; p=' + testPublicKeyDer]])
        } else {
          // badsig selector — but body hash mismatch fires before DNS is called
          const nxErr = new Error('NXDOMAIN')
          nxErr.code = dns.NXDOMAIN
          cb(nxErr)
        }
      })

      const verifier = new DKIMVerifyStream({ timeout: 5 }, (vErr, result) => {
        assert.ifError(vErr)
        assert.equal(
          result,
          'pass',
          `A passing signature must not be overridden by a later failing one; ` +
            `expected 'pass', got '${result}'`,
        )
        done()
      })
      verifier.write(Buffer.from(twoSigEmail))
      verifier.end()
    })
  })
})
