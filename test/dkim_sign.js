'use strict'

const assert = require('node:assert')
const { beforeEach, describe, it } = require('node:test')

const fs = require('node:fs/promises')
const path = require('path')

const Address = require('address-rfc2821')
const fixtures = require('haraka-test-fixtures')
const utils = require('haraka-utils')

beforeEach(() => {
  this.plugin = new fixtures.plugin('dkim')

  this.connection = fixtures.connection.createConnection()
  this.connection.transaction = fixtures.transaction.createTransaction()
})

describe('get_sender_domain', () => {
  beforeEach(() => {
    this.connection.transaction.mail_from = {}
  })

  it('no transaction', () => {
    delete this.connection.transaction
    assert.equal(this.plugin.get_sender_domain(this.connection), undefined)
  })

  it('no headers', () => {
    assert.equal(this.plugin.get_sender_domain(this.connection), undefined)
  })

  it('no from header', () => {
    this.connection.transaction.header.add(
      'Date',
      utils.date_to_str(new Date()),
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), undefined)
  })

  it('no from header, env MAIL FROM', () => {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@example.com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('env MAIL FROM, case insensitive', () => {
    this.connection.transaction.mail_from = new Address.Address(
      '<test@Example.cOm>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('From header not a fqdn', () => {
    this.connection.transaction.header.add('From', 'root (Cron Daemon)')
    const r = this.plugin.get_sender_domain(this.connection)
    this.plugin.get_key_dir(this.connection, { domain: r }, (err, dir) => {
      assert.equal(dir, undefined)
    })
  })

  it('from header, simple', () => {
    this.connection.transaction.header.add(
      'From',
      'John Doe <jdoe@example.com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('from header, case insensitive', () => {
    this.connection.transaction.header.add(
      'From',
      'John Doe <jdoe@Example.Com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('from header, less simple', () => {
    this.connection.transaction.header.add(
      'From',
      '"Joe Q. Public" <john.q.public@example.com>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.com')
  })

  it('from header, RFC 5322 odd', () => {
    this.connection.transaction.header.add(
      'From',
      'Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>',
    )
    assert.equal(this.plugin.get_sender_domain(this.connection), 'silly.test')
  })

  it('from header group', () => {
    this.connection.transaction.header.add(
      'From',
      'ben@example.com,carol@example.com',
    )
    this.connection.transaction.header.add('Sender', 'dave@example.net')
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.net')
  })

  it('from header group, RFC 6854', () => {
    // TODO: this test passes, but the parsing isn't correct. The From
    // addr parser doesn't support the RFC 6854 Group Syntax
    this.connection.transaction.header.add(
      'From',
      'Managing Partners:ben@example.com,carol@example.com;',
    )
    this.connection.transaction.header.add('Sender', 'dave@example.net')
    assert.equal(this.plugin.get_sender_domain(this.connection), 'example.net')
  })
})

describe('get_key_dir', () => {
  beforeEach(async () => {
    await fs.mkdir(path.resolve('test', 'config', 'dkim', 'example.com'), {
      recursive: true,
    })
  })

  it('no transaction', (t, done) => {
    this.plugin.get_key_dir(this.connection, '', (err, dir) => {
      assert.ifError(err)
      assert.equal(dir, undefined)
      done()
    })
  })

  it('no key dir', (t, done) => {
    this.connection.transaction.mail_from = new Address.Address(
      '<matt@non-exist.com>',
    )
    this.plugin.get_key_dir(this.connection, 'non-exist.com', (err, dir) => {
      assert.equal(dir, undefined)
      done()
    })
  })

  it('test example.com key dir', (t, done) => {
    process.env.HARAKA = path.resolve('test')
    this.connection.transaction.mail_from = new Address.Address(
      '<matt@example.com>',
    )
    this.plugin.get_key_dir(
      this.connection,
      { domain: 'example.com' },
      (err, dir) => {
        // console.log(arguments);
        const expected = path.resolve('test', 'config', 'dkim', 'example.com')
        assert.equal(dir, expected)
        done()
      },
    )
  })
})

describe('get_headers_to_sign', () => {
  it('none configured, includes from', () => {
    this.plugin.cfg = { sign: {} }
    assert.deepEqual(this.plugin.get_headers_to_sign(), ['from'])
  })

  it('from, subject', () => {
    this.plugin.cfg = { sign: { headers: 'from,subject' } }
    assert.deepEqual(this.plugin.get_headers_to_sign(), ['from', 'subject'])
  })

  it('subject configured, subject and from returned', () => {
    this.plugin.cfg = { sign: { headers: 'subject' } }
    assert.deepEqual(this.plugin.get_headers_to_sign(), ['subject', 'from'])
  })
})

const insecure_512b_test_key =
  '-----BEGIN RSA PRIVATE KEY-----\nMIGqAgEAAiEAsw3E27MbZuxmWpYfjNX5XzKTMxIv8bIAU/MpjiJE5rkCAwEAAQIg\nIVsyTj96nlzx4HRRIlqGXw7wx3C+vGhoM/Ql/eFXRVECEQDbUYF19fyzPDKAqb7p\nEu5tAhEA0QBD5Ns4QgpC8m1Qob05/QIQf1jWWU5aSyC7GmZ2ChQKCQIQIACNZNaY\nZ6xQkfRhG1LxNQIRAIyKwDCULf7Jl5ygc1MIIdk=\n-----END RSA PRIVATE KEY-----'

describe('get_sign_properties', () => {
  beforeEach(() => {
    this.plugin.config.root_path = path.resolve(__dirname, '../config')
    this.plugin.load_dkim_ini()
    this.plugin.load_dkim_default_key()
  })

  it('example.com from ENV mail from', () => {
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
    })
  })

  it('no domain discovered returns default', () => {
    this.connection.transaction.mail_from = {}
    this.plugin.get_sign_properties(this.connection, (err, props) => {
      if (err) console.error(err)
      assert.deepEqual(props, {
        domain: this.plugin.cfg.sign.domain,
        selector: this.plugin.cfg.sign.selector,
        private_key: this.plugin.private_key,
      })
    })
  })
})

describe('has_key_data', () => {
  it('no data', () => {
    assert.equal(this.plugin.has_key_data(this.connection, {}), false)
  })

  it('fully populated', () => {
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

describe('load_key', () => {
  it('example.com test key', () => {
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
