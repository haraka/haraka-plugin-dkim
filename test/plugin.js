'use strict'

const assert = require('node:assert/strict')
const { beforeEach, describe, it } = require('node:test')
const fs = require('node:fs/promises')
const path = require('node:path')

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
