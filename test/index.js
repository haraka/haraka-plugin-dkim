const assert = require('node:assert')
const { beforeEach, describe, it } = require('node:test')
const path = require('path')

// npm modules
const fixtures = require('haraka-test-fixtures')

beforeEach(() => {
  this.plugin = new fixtures.plugin('dkim')
  this.plugin.config.root_path = path.resolve('test','config')
  delete this.plugin.config.overrides_path
})

describe('plugin', () => {

  it('loads', () => {
    assert.ok(this.plugin)
  })

  it('loads dkim.ini', () => {
    this.plugin.load_dkim_ini()
    assert.ok(this.plugin.cfg)
  })

  it('initializes enabled boolean', () => {
    this.plugin.load_dkim_ini()
    // console.log(this.plugin.cfg?.sign)
    assert.equal(this.plugin.cfg.sign.enabled, true, this.plugin.cfg)
  })
})

describe('uses text fixtures', () => {
  it('sets up a connection', () => {
    this.connection = fixtures.connection.createConnection({})
    assert.ok(this.connection.server)
  })

  it('sets up a transaction', () => {
    this.connection = fixtures.connection.createConnection({})
    this.connection.transaction = fixtures.transaction.createTransaction({})
    assert.ok(this.connection.transaction.header)
  })
})

const expectedCfg = {
  main: {},
  sign: {
    enabled: false,
    selector: 'mail',
    domain: 'example.com',
    headers:
      'From, Sender, Reply-To, Subject, Date, Message-ID, To, Cc, MIME-Version',
  },
  verify: {
    timeout: 29,
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
    this.plugin.config.root_path = path.resolve(__dirname, '../config')
  })

  it('registers', () => {
    assert.deepEqual(this.plugin.cfg, undefined)
    this.plugin.register()
    assert.deepEqual(this.plugin.cfg, expectedCfg)
  })
})

describe('load_dkim_ini', () => {
  beforeEach(() => {
    this.plugin.config.root_path = path.resolve(__dirname, '../config')
  })

  it('loads dkim.ini', () => {
    // console.log(this.plugin)
    assert.deepEqual(this.plugin.cfg, undefined)
    this.plugin.load_dkim_ini()
    assert.deepEqual(this.plugin.cfg, expectedCfg)
  })
})
