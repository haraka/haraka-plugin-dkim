'use strict'

const assert = require('node:assert/strict')
const { afterEach, beforeEach, describe, it, mock } = require('node:test')
const crypto = require('node:crypto')
const dns = require('node:dns')
const fsSync = require('node:fs')
const fs = require('node:fs/promises')
const path = require('node:path')
const { PassThrough } = require('node:stream')

const { Address } = require('@haraka/email-address')
const { makeConnection, makePlugin } = require('haraka-test-fixtures')
const utils = require('haraka-utils')

// The 512-bit RSA key stored in test/config/dkim/example.com/private.
// Its value is produced by load_key(), which calls config.get(file, 'data').join('\n').
const insecure_512b_test_key =
  '-----BEGIN RSA PRIVATE KEY-----\nMIGqAgEAAiEAsw3E27MbZuxmWpYfjNX5XzKTMxIv8bIAU/MpjiJE5rkCAwEAAQIg\nIVsyTj96nlzx4HRRIlqGXw7wx3C+vGhoM/Ql/eFXRVECEQDbUYF19fyzPDKAqb7p\nEu5tAhEA0QBD5Ns4QgpC8m1Qob05/QIQf1jWWU5aSyC7GmZ2ChQKCQIQIACNZNaY\nZ6xQkfRhG1LxNQIRAIyKwDCULf7Jl5ygc1MIIdk=\n-----END RSA PRIVATE KEY-----'

// ─── Shared setup ────────────────────────────────────────────────────────────

let plugin
let connection

beforeEach(() => {
  plugin = makePlugin('dkim', { register: false })
  plugin.config.root_path = path.resolve('test', 'config')
  delete plugin.config.overrides_path

  connection = makeConnection({ withTxn: true })
})

// ─── Plugin bootstrap ─────────────────────────────────────────────────────────

describe('plugin', () => {
  it('loads', () => {
    assert.ok(plugin)
  })

  it('loads dkim.ini', () => {
    plugin.load_dkim_ini()
    assert.ok(plugin.cfg)
  })

  it('initializes sign.enabled boolean', () => {
    plugin.load_dkim_ini()
    assert.equal(plugin.cfg.sign.enabled, true, JSON.stringify(plugin.cfg))
  })
})

describe('uses haraka-test-fixtures', () => {
  it('sets up a connection', () => {
    const conn = makeConnection()
    assert.ok(conn.server)
  })

  it('sets up a transaction', () => {
    const conn = makeConnection({ withTxn: true })
    assert.ok(conn.transaction.header)
  })
})

const expectedCfg = {
  main: {},
  sign: {
    enabled: true,
    selector: 'mail',
    domain: 'example.com',
    headers:
      'From, Sender, Reply-To, Subject, Date, Message-ID, To, Cc, MIME-Version',
  },
  verify: {
    enabled: true,
    timeout: 9,
  },
  headers_to_sign: [
    'from',
    'sender',
    'reply-to',
    'subject',
    'date',
    'message-id',
    'to',
    'cc',
    'mime-version',
  ],
}

describe('register', () => {
  beforeEach(() => {
    plugin.config.root_path = path.resolve(__dirname, 'config')
  })

  it('registers and populates cfg', () => {
    assert.equal(plugin.cfg, undefined)
    plugin.register()
    assert.deepEqual(plugin.cfg, expectedCfg)
  })
})

describe('load_dkim_ini', () => {
  beforeEach(() => {
    plugin.config.root_path = path.resolve(__dirname, 'config')
  })

  it('loads dkim.ini and populates cfg', () => {
    assert.equal(plugin.cfg, undefined)
    plugin.load_dkim_ini()
    assert.deepEqual(plugin.cfg, expectedCfg)
  })
})

// ─── get_sender_domain ────────────────────────────────────────────────────────

describe('get_sender_domain', () => {
  beforeEach(() => {
    connection.transaction.mail_from = {}
  })

  it('no transaction returns undefined', () => {
    delete connection.transaction
    assert.equal(plugin.get_sender_domain(connection), undefined)
  })

  it('no headers returns undefined', () => {
    assert.equal(plugin.get_sender_domain(connection), undefined)
  })

  it('no From header returns undefined', () => {
    connection.transaction.header.add('Date', utils.date_to_str(new Date()))
    assert.equal(plugin.get_sender_domain(connection), undefined)
  })

  it('no From header but env MAIL FROM returns envelope domain', () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    assert.equal(plugin.get_sender_domain(connection), 'example.com')
  })

  it('env MAIL FROM domain is lowercased', () => {
    connection.transaction.mail_from = new Address('<test@Example.cOm>')
    assert.equal(plugin.get_sender_domain(connection), 'example.com')
  })

  it('From header that is not an FQDN returns undefined from key dir lookup', async () => {
    connection.transaction.header.add('From', 'root (Cron Daemon)')
    const r = plugin.get_sender_domain(connection)
    assert.equal(await plugin.get_key_dir(connection, r), undefined)
  })

  it('simple From header returns domain', () => {
    connection.transaction.header.add('From', 'John Doe <jdoe@example.com>')
    assert.equal(plugin.get_sender_domain(connection), 'example.com')
  })

  it('From header domain is lowercased', () => {
    connection.transaction.header.add('From', 'John Doe <jdoe@Example.Com>')
    assert.equal(plugin.get_sender_domain(connection), 'example.com')
  })

  it('quoted-name From header returns domain', () => {
    connection.transaction.header.add(
      'From',
      '"Joe Q. Public" <john.q.public@example.com>',
    )
    assert.equal(plugin.get_sender_domain(connection), 'example.com')
  })

  it('From header with RFC 5322 comments returns domain', () => {
    connection.transaction.header.add(
      'From',
      'Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>',
    )
    assert.equal(plugin.get_sender_domain(connection), 'silly.test')
  })

  it('multi-address From uses Sender header domain', () => {
    connection.transaction.header.add(
      'From',
      'ben@example.com,carol@example.com',
    )
    connection.transaction.header.add('Sender', 'dave@example.net')
    assert.equal(plugin.get_sender_domain(connection), 'example.net')
  })

  it('MIME-encoded From with encoded commas returns domain', () => {
    connection.transaction.header.add(
      'From',
      '=?utf-8?Q?PORT_Mozipremierek=2C_filmes_h=C3=ADrek=2C_=C3=A9rdekess=C3=A9g?=\n =?utf-8?Q?ek=2C_kritik=C3=A1k_=2831=2E_h=C3=A9t=29?= <hirlevel@example.hu>',
    )
    assert.equal(plugin.get_sender_domain(connection), 'example.hu')
  })

  it('MIME-encoded Sender with encoded commas returns domain', () => {
    connection.transaction.header.add(
      'From',
      'ben@example.com,carol@example.com',
    )
    connection.transaction.header.add(
      'Sender',
      '=?utf-8?Q?Doe=2C_Dave?= <dave@example.net>',
    )
    assert.equal(plugin.get_sender_domain(connection), 'example.net')
  })

  it('RFC 6854 group syntax From falls back to Sender header', () => {
    // TODO: From addr parser does not fully support RFC 6854 Group Syntax
    connection.transaction.header.add(
      'From',
      'Managing Partners:ben@example.com,carol@example.com;',
    )
    connection.transaction.header.add('Sender', 'dave@example.net')
    assert.equal(plugin.get_sender_domain(connection), 'example.net')
  })
})

// ─── get_key_dir ─────────────────────────────────────────────────────────────

describe('get_key_dir', () => {
  beforeEach(async () => {
    await fs.mkdir(path.resolve('test', 'config', 'dkim', 'example.com'), {
      recursive: true,
    })
  })

  it('empty domain returns undefined dir', async () => {
    assert.equal(await plugin.get_key_dir(connection, ''), undefined)
  })

  it('domain with no key dir returns undefined', async () => {
    connection.transaction.mail_from = new Address('<matt@non-exist.com>')
    assert.equal(
      await plugin.get_key_dir(connection, 'non-exist.com'),
      undefined,
    )
  })

  it('resolves example.com key dir when HARAKA env is set', async () => {
    process.env.HARAKA = path.resolve('test')
    connection.transaction.mail_from = new Address('<matt@example.com>')
    const expected = path.resolve('test', 'config', 'dkim', 'example.com')
    assert.equal(await plugin.get_key_dir(connection, 'example.com'), expected)
  })

  it('does not walk into a single-label TLD directory', async () => {
    // Create config/dkim/com/ to simulate the audit's worst case: a stray
    // single-label dir that the old walk would have matched for any *.com.
    process.env.HARAKA = path.resolve('test')
    const tldDir = path.resolve('test', 'config', 'dkim', 'com')
    await fs.mkdir(tldDir, { recursive: true })
    try {
      assert.equal(
        await plugin.get_key_dir(connection, 'unmatched.com'),
        undefined,
      )
    } finally {
      await fs.rm(tldDir, { recursive: true, force: true })
    }
  })
})

// ─── get_headers_to_sign ─────────────────────────────────────────────────────

describe('get_headers_to_sign', () => {
  it('no configuration returns [from]', () => {
    plugin.cfg = { sign: {} }
    assert.deepEqual(plugin.get_headers_to_sign(), ['from'])
  })

  it('from,subject configuration returns both', () => {
    plugin.cfg = { sign: { headers: 'from,subject' } }
    assert.deepEqual(plugin.get_headers_to_sign(), ['from', 'subject'])
  })

  it('subject-only configuration appends from', () => {
    plugin.cfg = { sign: { headers: 'subject' } }
    assert.deepEqual(plugin.get_headers_to_sign(), ['subject', 'from'])
  })
})

// ─── get_sign_properties ─────────────────────────────────────────────────────

describe('get_sign_properties', () => {
  beforeEach(() => {
    // root_path must point to test/config so load_key can find dkim/example.com/private
    plugin.config.root_path = path.resolve('test', 'config')
    plugin.load_dkim_ini()
    plugin.load_dkim_default_key()
    // HARAKA must be set so get_key_dir resolves the test/config/dkim/ directory
    process.env.HARAKA = path.resolve('test')
  })

  it('example.com domain resolves to per-domain key', async () => {
    connection.transaction.mail_from = new Address('<test@example.com>')
    const props = await plugin.get_sign_properties(connection)
    assert.deepEqual(props, {
      domain: 'example.com',
      selector: 'aug2019',
      private_key: insecure_512b_test_key,
    })
  })

  it('no domain discovered falls back to default key', async () => {
    connection.transaction.mail_from = {}
    const props = await plugin.get_sign_properties(connection)
    assert.deepEqual(props, {
      domain: plugin.cfg.sign.domain,
      selector: plugin.cfg.sign.selector,
      private_key: plugin.private_key,
    })
  })
})

// ─── has_key_data ─────────────────────────────────────────────────────────────

describe('has_key_data', () => {
  it('empty props returns false', () => {
    assert.equal(plugin.has_key_data(connection, {}), false)
  })

  it('missing selector returns false', () => {
    assert.equal(
      plugin.has_key_data(connection, {
        private_key: 'key',
        domain: 'example.com',
      }),
      false,
    )
  })

  it('missing domain returns false', () => {
    assert.equal(
      plugin.has_key_data(connection, {
        private_key: 'key',
        selector: 'sel',
      }),
      false,
    )
  })

  it('fully populated props returns true', () => {
    assert.equal(
      plugin.has_key_data(connection, {
        selector: 'foo',
        domain: 'bar',
        private_key: 'anything',
      }),
      true,
    )
  })
})

// ─── load_key ─────────────────────────────────────────────────────────────────

describe('load_key', () => {
  it('loads example.com test key from config directory', () => {
    const testKey = path.resolve(
      'test',
      'config',
      'dkim',
      'example.com',
      'private',
    )
    assert.equal(plugin.load_key(testKey), insecure_512b_test_key)
  })
})

// ─── Fixtures for hook tests ──────────────────────────────────────────────────

const rsa1024PrivateKey = fsSync.readFileSync(
  path.join(__dirname, 'fixtures', 'rsa1024.private.pem'),
  'utf8',
)
const rsa1024PublicKeyDer = crypto
  .createPublicKey(rsa1024PrivateKey)
  .export({ type: 'spki', format: 'der' })
  .toString('base64')

// Build a signed email string using the rsa1024 key.
function buildSignedEmail(headerLines, body) {
  return new Promise((resolve, reject) => {
    const { DKIMSignStream } = require('../lib/dkim')
    const message = require('haraka-email-message')
    const emailStr = `${headerLines.join('\r\n')}\r\n\r\n${body}`
    const header = new message.Header()
    header.parse(headerLines)
    const props = {
      selector: 'testkey',
      domain: 'example.com',
      private_key: rsa1024PrivateKey,
      headers: ['from'],
    }
    const signer = new DKIMSignStream(props, header, (err, val) => {
      if (err) return reject(err)
      resolve(`DKIM-Signature: ${val}\r\n${emailStr}`)
    })
    signer.write(Buffer.from(emailStr))
    signer.end()
  })
}

// Set up a plugin instance configured for hook tests (sign.enabled=true, 1024-bit key).
// Uses an invalid HARAKA path so get_key_dir falls back to the default key.
function makeSignPlugin() {
  const p = makePlugin('dkim', { register: false })
  p.config.root_path = path.resolve('test', 'config')
  delete p.config.overrides_path
  p.register()
  p.private_key = rsa1024PrivateKey // override 512-bit key with usable key
  process.env.HARAKA = path.join(__dirname, 'fixtures') // no dkim/ subdir here → falls back
  return p
}

afterEach(() => {
  mock.restoreAll()
})

// ─── hook_pre_send_trans_email ────────────────────────────────────────────────

describe('hook_pre_send_trans_email', () => {
  it('skips when sign.enabled is false', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.sign.enabled = false
    plugin.hook_pre_send_trans_email(() => done(), connection)
  })

  it('skips when transaction is absent', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.sign.enabled = true
    delete connection.transaction
    plugin.hook_pre_send_trans_email(() => done(), connection)
  })

  it('skips when already signed', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.sign.enabled = true
    connection.transaction.notes.dkim_signed = true
    plugin.hook_pre_send_trans_email(() => done(), connection)
  })

  it('signs the message and adds DKIM-Signature header', (t, done) => {
    const plugin = makeSignPlugin()

    const conn = makeConnection({ withTxn: true })
    conn.transaction.mail_from = new Address('<test@example.com>')
    conn.transaction.header.add('From', 'test@example.com')

    const pass = new PassThrough()
    conn.transaction.message_stream = pass
    pass.write(Buffer.from('From: test@example.com\r\n\r\nHello world\r\n'))
    pass.end()

    plugin.hook_pre_send_trans_email(() => {
      const sig = conn.transaction.header.get('DKIM-Signature')
      assert.ok(sig, 'DKIM-Signature header must be present after signing')
      assert.ok(
        conn.transaction.notes.dkim_signed,
        'dkim_signed note must be set',
      )
      done()
    }, conn)
  })

  it('skips when no key data available', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.sign.enabled = true
    plugin.cfg.sign.domain = undefined
    plugin.cfg.sign.selector = undefined
    plugin.private_key = undefined
    // No per-domain key dir (HARAKA points to fixtures, no dkim/ dir)
    process.env.HARAKA = path.join(__dirname, 'fixtures')

    connection.transaction.mail_from = new Address('<test@example.com>')
    plugin.hook_pre_send_trans_email(() => {
      const sig = connection.transaction.header.get('DKIM-Signature')
      assert.equal(
        sig,
        '',
        'DKIM-Signature must NOT be added when key is missing',
      )
      done()
    }, connection)
  })
})

// ─── dkim_verify ──────────────────────────────────────────────────────────────

describe('dkim_verify', () => {
  it('skips when verify.enabled is false', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.verify.enabled = false
    plugin.dkim_verify(() => done(), connection)
  })

  it('skips when transaction is absent', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.verify.enabled = true
    delete connection.transaction
    plugin.dkim_verify(() => done(), connection)
  })

  it('returns no/bad signature when email has no DKIM-Signature', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.verify.enabled = true

    const pass = new PassThrough()
    connection.transaction.message_stream = pass

    plugin.dkim_verify((code) => {
      assert.equal(code, CONT, 'next must be called with CONT for no-sig')
      done()
    }, connection)

    pass.end(Buffer.from('From: test@example.com\r\n\r\nHello\r\n'))
  })

  it('verifies a valid DKIM-signed email and produces pass result', (t, done) => {
    buildSignedEmail(['From: test@example.com'], 'Hello world\r\n')
      .then((signedEmail) => {
        mock.method(dns.promises, 'resolveTxt', async () => {
          return [[`v=DKIM1; k=rsa; p=${rsa1024PublicKeyDer}`]]
        })

        plugin.load_dkim_ini()
        plugin.cfg.verify.enabled = true

        const pass = new PassThrough()
        connection.transaction.message_stream = pass

        plugin.dkim_verify(() => {
          const notes = connection.transaction.notes.dkim_results
          assert.ok(notes, 'dkim_results must be set on transaction notes')
          assert.equal(
            notes[0].result,
            'pass',
            `expected pass, got ${notes[0].result}`,
          )
          done()
        }, connection)

        pass.end(Buffer.from(signedEmail))
      })
      .catch(done)
  })

  it('adds error to results when signature fails', (t, done) => {
    // Use a signed email but mock DNS to return a different key → fail
    buildSignedEmail(['From: test@example.com'], 'Hello\r\n')
      .then((signedEmail) => {
        mock.method(dns.promises, 'resolveTxt', async () => {
          // Return a DIFFERENT public key → crypto verify returns false → 'fail'
          const wrongKey = crypto
            .createPublicKey(
              fsSync.readFileSync(
                path.join(__dirname, 'fixtures', 'rsa1280.private.pem'),
                'utf8',
              ),
            )
            .export({ type: 'spki', format: 'der' })
            .toString('base64')
          return [[`v=DKIM1; k=rsa; p=${wrongKey}`]]
        })

        plugin.load_dkim_ini()
        plugin.cfg.verify.enabled = true

        const pass = new PassThrough()
        connection.transaction.message_stream = pass

        plugin.dkim_verify(() => {
          const notes = connection.transaction.notes.dkim_results
          assert.ok(notes)
          assert.equal(notes[0].result, 'fail')
          done()
        }, connection)

        pass.end(Buffer.from(signedEmail))
      })
      .catch(done)
  })

  it('stores pass result in ResultStore', (t, done) => {
    buildSignedEmail(['From: test@example.com'], 'Hello\r\n')
      .then((signedEmail) => {
        mock.method(dns.promises, 'resolveTxt', async () => {
          return [[`v=DKIM1; k=rsa; p=${rsa1024PublicKeyDer}`]]
        })

        plugin.load_dkim_ini()
        plugin.cfg.verify.enabled = true

        const pass = new PassThrough()
        connection.transaction.message_stream = pass

        plugin.dkim_verify(() => {
          const results = connection.transaction.results.get(plugin)
          assert.ok(results, 'results must be stored')
          assert.ok(results.pass, 'pass domain must be stored')
          done()
        }, connection)

        pass.end(Buffer.from(signedEmail))
      })
      .catch(done)
  })

  // Regression for haraka/message-stream#22.
  it('calls message_stream.unpipe() after verify completes', (t, done) => {
    plugin.load_dkim_ini()
    plugin.cfg.verify.enabled = true

    const pass = new PassThrough()
    let unpipeCalls = 0
    const origUnpipe = pass.unpipe.bind(pass)
    pass.unpipe = (...args) => {
      unpipeCalls++
      return origUnpipe(...args)
    }
    connection.transaction.message_stream = pass

    plugin.dkim_verify(() => {
      assert.ok(unpipeCalls >= 1, 'unpipe() must be called before next()')
      done()
    }, connection)

    pass.end(Buffer.from('From: test@example.com\r\n\r\nHello\r\n'))
  })
})

// Regression for haraka/message-stream#22.
describe('hook_pre_send_trans_email unpipe', () => {
  it('calls message_stream.unpipe() after signing completes', (t, done) => {
    const plugin = makeSignPlugin()
    // Defensive: an earlier test in this file mutates the cached cfg to
    // undefined. Re-assert sign properties so this test stays order-independent.
    plugin.cfg.sign.domain = 'example.com'
    plugin.cfg.sign.selector = 'mail'

    const conn = makeConnection({ withTxn: true })
    conn.transaction.mail_from = new Address('<test@example.com>')
    conn.transaction.header.add('From', 'test@example.com')

    const pass = new PassThrough()
    let unpipeCalls = 0
    const origUnpipe = pass.unpipe.bind(pass)
    pass.unpipe = (...args) => {
      unpipeCalls++
      return origUnpipe(...args)
    }
    conn.transaction.message_stream = pass
    pass.write(Buffer.from('From: test@example.com\r\n\r\nHello world\r\n'))
    pass.end()

    plugin.hook_pre_send_trans_email(() => {
      assert.ok(unpipeCalls >= 1, 'unpipe() must be called before next()')
      done()
    }, conn)
  })
})
