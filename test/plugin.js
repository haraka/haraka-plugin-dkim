'use strict'

const assert = require('node:assert/strict')
const { afterEach, beforeEach, describe, it, mock } = require('node:test')
const crypto = require('node:crypto')
const dns = require('node:dns')
const fsSync = require('node:fs')
const fs = require('node:fs/promises')
const path = require('node:path')
const { PassThrough } = require('node:stream')

const Address = require('address-rfc2821')
const fixtures = require('haraka-test-fixtures')
const utils = require('haraka-utils')

// The 512-bit RSA key stored in test/config/dkim/example.com/private.
// Its value is produced by load_key(), which calls config.get(file, 'data').join('\n').
const insecure_512b_test_key =
  '-----BEGIN RSA PRIVATE KEY-----\nMIGqAgEAAiEAsw3E27MbZuxmWpYfjNX5XzKTMxIv8bIAU/MpjiJE5rkCAwEAAQIg\nIVsyTj96nlzx4HRRIlqGXw7wx3C+vGhoM/Ql/eFXRVECEQDbUYF19fyzPDKAqb7p\nEu5tAhEA0QBD5Ns4QgpC8m1Qob05/QIQf1jWWU5aSyC7GmZ2ChQKCQIQIACNZNaY\nZ6xQkfRhG1LxNQIRAIyKwDCULf7Jl5ygc1MIIdk=\n-----END RSA PRIVATE KEY-----'

// ─── Shared setup ────────────────────────────────────────────────────────────

beforeEach(() => {
  this.plugin = new fixtures.plugin('dkim')
  this.plugin.config.root_path = path.resolve('test', 'config')
  delete this.plugin.config.overrides_path

  this.connection = fixtures.connection.createConnection()
  this.connection.init_transaction()
})

// ─── Plugin bootstrap ─────────────────────────────────────────────────────────

describe('plugin', () => {
  it('loads', () => {
    assert.ok(this.plugin)
  })

  it('loads dkim.ini', () => {
    this.plugin.load_dkim_ini()
    assert.ok(this.plugin.cfg)
  })

  it('initializes sign.enabled boolean', () => {
    this.plugin.load_dkim_ini()
    assert.equal(
      this.plugin.cfg.sign.enabled,
      true,
      JSON.stringify(this.plugin.cfg),
    )
  })
})

describe('uses haraka-test-fixtures', () => {
  it('sets up a connection', () => {
    const conn = fixtures.connection.createConnection({})
    assert.ok(conn.server)
  })

  it('sets up a transaction', () => {
    const conn = fixtures.connection.createConnection({})
    conn.init_transaction()
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
    this.plugin.config.root_path = path.resolve(__dirname, 'config')
  })

  it('registers and populates cfg', () => {
    assert.equal(this.plugin.cfg, undefined)
    this.plugin.register()
    assert.deepEqual(this.plugin.cfg, expectedCfg)
  })
})

describe('load_dkim_ini', () => {
  beforeEach(() => {
    this.plugin.config.root_path = path.resolve(__dirname, 'config')
  })

  it('loads dkim.ini and populates cfg', () => {
    assert.equal(this.plugin.cfg, undefined)
    this.plugin.load_dkim_ini()
    assert.deepEqual(this.plugin.cfg, expectedCfg)
  })
})

// ─── get_sender_domain ────────────────────────────────────────────────────────

describe('get_sender_domain', () => {
  beforeEach(() => {
    this.connection.transaction.mail_from = {}
  })

  it('no transaction returns undefined', () => {
    delete this.connection.transaction
    assert.equal(this.plugin.get_sender_domain(this.connection), undefined)
  })

  it('no headers returns undefined', () => {
    assert.equal(this.plugin.get_sender_domain(this.connection), undefined)
  })

  it('no From header returns undefined', () => {
    this.connection.transaction.header.add(
      'Date',
      utils.date_to_str(new Date()),
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), undefined)
  })

  it('no From header but env MAIL FROM returns envelope domain', () => {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('env MAIL FROM domain is lowercased', () => {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@Example.cOm>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('From header that is not an FQDN returns undefined from key dir lookup', () => {
    this.connection.transaction.header.add('From', 'root (Cron Daemon)')
    const r = this.plugin.get_sender_domain(this.connection)
    this.plugin.get_key_dir(this.connection, { domain: r }, (err, dir) => {
      assert.equal(dir, undefined)
    })
  })

  it('simple From header returns domain', () => {
    this.connection.transaction.header.add(
      'From',
      'John Doe <jdoe@example.com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('From header domain is lowercased', () => {
    this.connection.transaction.header.add(
      'From',
      'John Doe <jdoe@Example.Com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('quoted-name From header returns domain', () => {
    this.connection.transaction.header.add(
      'From',
      '"Joe Q. Public" <john.q.public@example.com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('From header with RFC 5322 comments returns domain', () => {
    this.connection.transaction.header.add(
      'From',
      'Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'silly.test')
  })

  it('multi-address From uses Sender header domain', () => {
    this.connection.transaction.header.add(
      'From',
      'ben@example.com,carol@example.com',
    )
    this.connection.transaction.header.add('Sender', 'dave@example.net')
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.net')
  })

  it('RFC 6854 group syntax From falls back to Sender header', () => {
    // TODO: From addr parser does not fully support RFC 6854 Group Syntax
    this.connection.transaction.header.add(
      'From',
      'Managing Partners:ben@example.com,carol@example.com;',
    )
    this.connection.transaction.header.add('Sender', 'dave@example.net')
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.net')
  })
})

// ─── get_key_dir ─────────────────────────────────────────────────────────────

describe('get_key_dir', () => {
  beforeEach(async () => {
    await fs.mkdir(path.resolve('test', 'config', 'dkim', 'example.com'), {
      recursive: true,
    })
  })

  it('empty props returns undefined dir', (t, done) => {
    this.plugin.get_key_dir(this.connection, '', (err, dir) => {
      assert.ifError(err)
      assert.equal(dir, undefined)
      done()
    })
  })

  it('domain with no key dir returns undefined', (t, done) => {
    this.connection.transaction.mail_from = new Address.Address(
      '<matt@non-exist.com>',
    )
    this.plugin.get_key_dir(this.connection, 'non-exist.com', (err, dir) => {
      assert.equal(dir, undefined)
      done()
    })
  })

  it('resolves example.com key dir when HARAKA env is set', (t, done) => {
    process.env.HARAKA = path.resolve('test')
    this.connection.transaction.mail_from = new Address.Address(
      '<matt@example.com>',
    )
    this.plugin.get_key_dir(
      this.connection,
      { domain: 'example.com' },
      (err, dir) => {
        const expected = path.resolve('test', 'config', 'dkim', 'example.com')
        assert.equal(dir, expected)
        done()
      },
    )
  })
})

// ─── get_headers_to_sign ─────────────────────────────────────────────────────

describe('get_headers_to_sign', () => {
  it('no configuration returns [from]', () => {
    this.plugin.cfg = { sign: {} }
    assert.deepEqual(this.plugin.get_headers_to_sign(), ['from'])
  })

  it('from,subject configuration returns both', () => {
    this.plugin.cfg = { sign: { headers: 'from,subject' } }
    assert.deepEqual(this.plugin.get_headers_to_sign(), ['from', 'subject'])
  })

  it('subject-only configuration appends from', () => {
    this.plugin.cfg = { sign: { headers: 'subject' } }
    assert.deepEqual(this.plugin.get_headers_to_sign(), ['subject', 'from'])
  })
})

// ─── get_sign_properties ─────────────────────────────────────────────────────

describe('get_sign_properties', () => {
  beforeEach(() => {
    // root_path must point to test/config so load_key can find dkim/example.com/private
    this.plugin.config.root_path = path.resolve('test', 'config')
    this.plugin.load_dkim_ini()
    this.plugin.load_dkim_default_key()
    // HARAKA must be set so get_key_dir resolves the test/config/dkim/ directory
    process.env.HARAKA = path.resolve('test')
  })

  it('example.com domain resolves to per-domain key', (t, done) => {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.plugin.get_sign_properties(this.connection, (err, props) => {
      if (err) console.error(err)
      assert.deepEqual(props, {
        domain: 'example.com',
        selector: 'aug2019',
        private_key: insecure_512b_test_key,
      })
      done()
    })
  })

  it('no domain discovered falls back to default key', (t, done) => {
    this.connection.transaction.mail_from = {}
    this.plugin.get_sign_properties(this.connection, (err, props) => {
      if (err) console.error(err)
      assert.deepEqual(props, {
        domain: this.plugin.cfg.sign.domain,
        selector: this.plugin.cfg.sign.selector,
        private_key: this.plugin.private_key,
      })
      done()
    })
  })
})

// ─── has_key_data ─────────────────────────────────────────────────────────────

describe('has_key_data', () => {
  it('empty props returns false', () => {
    assert.equal(this.plugin.has_key_data(this.connection, {}), false)
  })

  it('missing selector returns false', () => {
    assert.equal(
      this.plugin.has_key_data(this.connection, {
        private_key: 'key',
        domain: 'example.com',
      }),
      false,
    )
  })

  it('missing domain returns false', () => {
    assert.equal(
      this.plugin.has_key_data(this.connection, {
        private_key: 'key',
        selector: 'sel',
      }),
      false,
    )
  })

  it('fully populated props returns true', () => {
    assert.equal(
      this.plugin.has_key_data(this.connection, {
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
    assert.equal(this.plugin.load_key(testKey), insecure_512b_test_key)
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
  const p = new fixtures.plugin('dkim')
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
    this.plugin.load_dkim_ini()
    this.plugin.cfg.sign.enabled = false
    this.plugin.hook_pre_send_trans_email(() => done(), this.connection)
  })

  it('skips when transaction is absent', (t, done) => {
    this.plugin.load_dkim_ini()
    this.plugin.cfg.sign.enabled = true
    delete this.connection.transaction
    this.plugin.hook_pre_send_trans_email(() => done(), this.connection)
  })

  it('skips when already signed', (t, done) => {
    this.plugin.load_dkim_ini()
    this.plugin.cfg.sign.enabled = true
    this.connection.transaction.notes.dkim_signed = true
    this.plugin.hook_pre_send_trans_email(() => done(), this.connection)
  })

  it('signs the message and adds DKIM-Signature header', (t, done) => {
    const plugin = makeSignPlugin()

    const conn = fixtures.connection.createConnection()
    conn.init_transaction()
    conn.transaction.mail_from = new Address.Address('<test@example.com>')
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
    this.plugin.load_dkim_ini()
    this.plugin.cfg.sign.enabled = true
    this.plugin.cfg.sign.domain = undefined
    this.plugin.cfg.sign.selector = undefined
    this.plugin.private_key = undefined
    // No per-domain key dir (HARAKA points to fixtures, no dkim/ dir)
    process.env.HARAKA = path.join(__dirname, 'fixtures')

    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    this.plugin.hook_pre_send_trans_email(() => {
      const sig = this.connection.transaction.header.get('DKIM-Signature')
      assert.equal(
        sig,
        '',
        'DKIM-Signature must NOT be added when key is missing',
      )
      done()
    }, this.connection)
  })
})

// ─── dkim_verify ──────────────────────────────────────────────────────────────

describe('dkim_verify', () => {
  it('skips when verify.enabled is false', (t, done) => {
    this.plugin.load_dkim_ini()
    this.plugin.cfg.verify.enabled = false
    this.plugin.dkim_verify(() => done(), this.connection)
  })

  it('skips when transaction is absent', (t, done) => {
    this.plugin.load_dkim_ini()
    this.plugin.cfg.verify.enabled = true
    delete this.connection.transaction
    this.plugin.dkim_verify(() => done(), this.connection)
  })

  it('returns no/bad signature when email has no DKIM-Signature', (t, done) => {
    this.plugin.load_dkim_ini()
    this.plugin.cfg.verify.enabled = true

    const pass = new PassThrough()
    this.connection.transaction.message_stream = pass

    this.plugin.dkim_verify((code) => {
      assert.equal(code, CONT, 'next must be called with CONT for no-sig')
      done()
    }, this.connection)

    pass.end(Buffer.from('From: test@example.com\r\n\r\nHello\r\n'))
  })

  it('verifies a valid DKIM-signed email and produces pass result', (t, done) => {
    buildSignedEmail(['From: test@example.com'], 'Hello world\r\n')
      .then((signedEmail) => {
        mock.method(dns, 'resolveTxt', (_name, cb) => {
          cb(null, [[`v=DKIM1; k=rsa; p=${rsa1024PublicKeyDer}`]])
        })

        this.plugin.load_dkim_ini()
        this.plugin.cfg.verify.enabled = true

        const pass = new PassThrough()
        this.connection.transaction.message_stream = pass

        this.plugin.dkim_verify(() => {
          const notes = this.connection.transaction.notes.dkim_results
          assert.ok(notes, 'dkim_results must be set on transaction notes')
          assert.equal(
            notes[0].result,
            'pass',
            `expected pass, got ${notes[0].result}`,
          )
          done()
        }, this.connection)

        pass.end(Buffer.from(signedEmail))
      })
      .catch(done)
  })

  it('adds error to results when signature fails', (t, done) => {
    // Use a signed email but mock DNS to return a different key → fail
    buildSignedEmail(['From: test@example.com'], 'Hello\r\n')
      .then((signedEmail) => {
        mock.method(dns, 'resolveTxt', (_name, cb) => {
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
          cb(null, [[`v=DKIM1; k=rsa; p=${wrongKey}`]])
        })

        this.plugin.load_dkim_ini()
        this.plugin.cfg.verify.enabled = true

        const pass = new PassThrough()
        this.connection.transaction.message_stream = pass

        this.plugin.dkim_verify(() => {
          const notes = this.connection.transaction.notes.dkim_results
          assert.ok(notes)
          assert.equal(notes[0].result, 'fail')
          done()
        }, this.connection)

        pass.end(Buffer.from(signedEmail))
      })
      .catch(done)
  })

  it('stores pass result in ResultStore', (t, done) => {
    buildSignedEmail(['From: test@example.com'], 'Hello\r\n')
      .then((signedEmail) => {
        mock.method(dns, 'resolveTxt', (_name, cb) => {
          cb(null, [[`v=DKIM1; k=rsa; p=${rsa1024PublicKeyDer}`]])
        })

        this.plugin.load_dkim_ini()
        this.plugin.cfg.verify.enabled = true

        const pass = new PassThrough()
        this.connection.transaction.message_stream = pass

        this.plugin.dkim_verify(() => {
          const results = this.connection.transaction.results.get(this.plugin)
          assert.ok(results, 'results must be stored')
          assert.ok(results.pass, 'pass domain must be stored')
          done()
        }, this.connection)

        pass.end(Buffer.from(signedEmail))
      })
      .catch(done)
  })
})
