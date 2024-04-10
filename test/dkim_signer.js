'use strict'

const assert = require('node:assert')
const { beforeEach, describe, it } = require('node:test')

const fixtures = require('haraka-test-fixtures')
const message = require('haraka-email-message')

const { DKIMSignStream } = require('../lib/dkim')

const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----`

/*
Body hash can be checked by:

$ echo -e -n 'Hello world!\r\n'| openssl dgst -binary -sha256 | openssl base64
z6TUz85EdYrACGMHYgZhJGvVy5oQI0dooVMKa2ZT7c4=
$ echo -e -n '\r\n' | openssl dgst -binary -sha256 | openssl base64
frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=
*/

function getValueFromDKIM(dkim_header, key) {
  const kv = dkim_header.split(';')
  for (let i = 0, len = kv.length; i < len; i++) {
    const arr = kv[i].match(/^\s*([^=]+)=(.*)$/)
    if (arr[1] === key) {
      return arr[2]
    }
  }
  throw `Key ${key} not found at ${dkim_header}`
}

const props = {
  selector: 'selector',
  domain: 'haraka.top',
  private_key: privateKey,
}

beforeEach(() => {
  this.plugin = new fixtures.plugin('dkim')

  this.connection = fixtures.connection.createConnection()
  this.connection.transaction = fixtures.transaction.createTransaction()
  // this.connection.transaction.mail_from = {}
})

describe('sign', () => {
  beforeEach(() => {
    this.plugin.load_dkim_ini()
    props.headers = this.plugin.cfg.headers_to_sign
  })

  it('body hash simple', () => {
    // from RFC
    const email =
      'Ignored: header\r\n\r\nHi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n'

    const header = new message.Header()
    header.parse(['Ignored: header'])
    const signer = new DKIMSignStream(props, header, (n, dkim) => {
      assert.equal(
        getValueFromDKIM(dkim, 'bh'),
        '2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=',
      )
    })
    signer.write(Buffer.from(email))
    signer.end()
  })

  it('empty body hash simple', () => {
    const email = 'Ignored: header\r\n\r\n'
    const header = new message.Header()
    header.parse(['Ignored: header'])
    const signer = new DKIMSignStream(props, header, (n, dkim) => {
      assert.equal(
        getValueFromDKIM(dkim, 'bh'),
        'frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=',
      )
    })
    signer.write(Buffer.from(email))
    signer.end()
  })

  it('body hash simple, two writes', () => {
    const header = new message.Header()
    header.parse(['Ignored: header'])
    const signer = new DKIMSignStream(props, header, (n, dkim) => {
      assert.equal(
        getValueFromDKIM(dkim, 'bh'),
        '2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=',
      )
    })
    signer.write(
      Buffer.from('Ignored: header\r\n\r\nHi.\r\n\r\nWe lost the game. '),
    )
    signer.write(Buffer.from('Are you hungry yet?\r\n\r\nJoe.\r\n'))
    signer.end()
  })

  it('body hash simple, empty lines', () => {
    const email =
      'Ignored: header\r\n\r\nHi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n\r\n\r\n'

    const header = new message.Header()
    header.parse(['Ignored: header'])
    const signer = new DKIMSignStream(props, header, (n, dkim) => {
      assert.equal(
        getValueFromDKIM(dkim, 'bh'),
        '2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=',
      )
    })
    signer.write(Buffer.from(email))
    signer.end()
  })
})