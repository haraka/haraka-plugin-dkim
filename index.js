'use strict'

const fs = require('fs')
const path = require('path')

const async = require('async')
const addrparser = require('address-rfc2822')

const dkim = require('./lib/dkim')

const { DKIMVerifyStream, DKIMSignStream } = dkim

exports.register = function () {
  const plugin = this
  this.load_dkim_ini()

  dkim.DKIMObject.prototype.debug = (str) => {
    plugin.logdebug(str)
  }

  DKIMVerifyStream.prototype.debug = (str) => {
    plugin.logdebug(str)
  }

  this.register_hook('data_post', 'dkim_verify')
  this.register_hook('queue_outbound', 'hook_pre_send_trans_email')
}

exports.load_dkim_ini = function () {
  this.cfg = this.config.get(
    'dkim.ini',
    {
      booleans: ['-sign.enabled'],
    },
    () => {
      this.load_dkim_ini()
    },
  )

  if (this.cfg.verify === undefined) this.cfg.verify = {}
  if (!this.cfg.verify.timeout) {
    this.cfg.verify.timeout = this.timeout ? this.timeout - 1 : 29
  }

  this.load_dkim_default_key()
  this.cfg.headers_to_sign = this.get_headers_to_sign()
}

// dkim_signer
// Implements DKIM core as per www.dkimcore.org

exports.load_dkim_default_key = function () {
  this.private_key = this.config
    .get('dkim.private.key', 'data', () => {
      this.load_dkim_default_key()
    })
    .join('\n')
}

exports.load_key = function (file) {
  return this.config.get(file, 'data').join('\n')
}

exports.hook_pre_send_trans_email = function (next, connection) {
  if (!this.cfg.sign.enabled) return next()
  if (!connection?.transaction) return next()

  if (connection.transaction.notes?.dkim_signed) {
    connection.logdebug(this, 'already signed')
    return next()
  }

  exports.get_sign_properties(connection, (err, props) => {
    if (!connection?.transaction) return next()
    // props: selector, domain, & private_key
    if (err) connection.logerror(this, `${err.message}`)

    if (!this.has_key_data(connection, props)) return next()

    connection.logdebug(this, `domain: ${props.domain}`)

    const txn = connection.transaction
    props.headers = this.cfg.headers_to_sign

    txn.message_stream.pipe(
      new DKIMSignStream(props, txn.header, (err2, dkim_header) => {
        if (err2) {
          txn.results.add(this, { err: err2.message })
          return next(err2)
        }

        connection.loginfo(this, `signed for ${props.domain}`)
        txn.results.add(this, { pass: dkim_header })
        txn.add_header('DKIM-Signature', dkim_header)

        connection.transaction.notes.dkim_signed = true
        next()
      }),
    )
  })
}

exports.get_sign_properties = function (connection, done) {
  if (!connection.transaction) return

  const domain = this.get_sender_domain(connection)

  if (!domain) {
    connection.transaction.results.add(this, {
      msg: 'sending domain not detected',
      emit: true,
    })
  }

  const props = { domain }

  this.get_key_dir(connection, props, (err, keydir) => {
    if (err) {
      console.error(`err: ${err}`)
      connection.logerror(this, err)
      return done(
        new Error(`Error getting DKIM key_dir for ${domain}: ${err}`),
        props,
      )
    }

    if (!connection.transaction) return done(null, props)

    // a directory for ${domain} exists
    if (keydir) {
      props.domain = path.basename(keydir) // keydir might be apex (vs sub)domain
      props.private_key = this.load_key(
        path.join('dkim', props.domain, 'private'),
      )
      props.selector = this.load_key(
        path.join('dkim', props.domain, 'selector'),
      ).trim()

      if (!props.selector) {
        connection.transaction.results.add(this, {
          err: `missing selector for domain ${domain}`,
        })
      }
      if (!props.private_key) {
        connection.transaction.results.add(this, {
          err: `missing dkim private_key for domain ${domain}`,
        })
      }

      if (props.selector && props.private_key) {
        // AND has correct files
        return done(null, props)
      }
    }

    // try [default / single domain] configuration
    if (this.cfg.sign.domain && this.cfg.sign.selector && this.private_key) {
      connection.transaction.results.add(this, {
        msg: 'using default key',
        emit: true,
      })

      props.domain = this.cfg.sign.domain
      props.private_key = this.private_key
      props.selector = this.cfg.sign.selector

      return done(null, props)
    }

    console.error(`no valid DKIM properties found`)
    done(null, props)
  })
}

exports.get_key_dir = function (connection, props, done) {
  if (!props.domain) return done()

  // split the domain name into labels
  const labels = props.domain.split('.')
  const haraka_dir = process.env.HARAKA || ''

  // list possible matches (ex: mail.example.com, example.com, com)
  const dom_hier = []
  for (let i = 0; i < labels.length; i++) {
    const dom = labels.slice(i).join('.')
    dom_hier[i] = path.resolve(haraka_dir, 'config', 'dkim', dom)
  }

  async.detectSeries(
    dom_hier,
    (filePath, iterDone) => {
      fs.stat(filePath, (err, stats) => {
        if (err) return iterDone(null, false)
        iterDone(null, stats.isDirectory())
      })
    },
    (err, results) => {
      connection.logdebug(this, results)
      done(err, results)
    },
  )
}

exports.has_key_data = function (conn, props) {
  let missing = undefined

  // Make sure we have all the relevant configuration
  if (!props.private_key) {
    missing = 'private key'
  } else if (!props.selector) {
    missing = 'selector'
  } else if (!props.domain) {
    missing = 'domain'
  }

  if (missing) {
    if (props.domain) {
      conn.lognotice(this, `skipped: no ${missing} for ${props.domain}`)
    } else {
      conn.lognotice(this, `skipped: no ${missing}`)
    }
    return false
  }

  conn.logprotocol(
    this,
    `using selector: ${props.selector} at domain ${props.domain}`,
  )
  return true
}

exports.get_headers_to_sign = function () {
  if (!this.cfg?.sign?.headers) return ['from']

  const headers = this.cfg.sign.headers
    .toLowerCase()
    .replace(/\s+/g, '')
    .split(/[,;:]/)

  // From MUST be present
  if (!headers.includes('from')) headers.push('from')

  return headers
}

exports.get_sender_domain = function (connection) {
  const txn = connection?.transaction
  if (!txn) return

  // fallback: use Envelope FROM when header parsing fails
  let domain
  if (txn.mail_from.host) {
    try {
      domain = txn.mail_from.host.toLowerCase()
    } catch (e) {
      connection.logerror(this, e)
    }
  }

  // In case of forwarding, only use the Envelope
  if (txn.notes.forward) return domain
  if (!txn.header) return domain

  // the DKIM signing key should be aligned with the domain in the From
  // header (see DMARC). Try to parse the domain from there.
  const from_hdr = txn.header.get_decoded('From')
  if (!from_hdr) return domain

  // The From header can contain multiple addresses and should be
  // parsed as described in RFC 2822 3.6.2.
  let addrs
  try {
    addrs = addrparser.parse(from_hdr)
  } catch (e) {
    connection.logerror(
      this,
      `address-rfc2822 failed to parse From header: ${from_hdr}`,
    )
    return domain
  }
  if (!addrs || !addrs.length) return domain

  // If From has a single address, we're done
  if (addrs.length === 1 && addrs[0].host) {
    let fromHost = addrs[0].host()
    if (fromHost) {
      // don't attempt to lower a null or undefined value #1575
      fromHost = fromHost.toLowerCase()
    }
    return fromHost
  }

  // If From has multiple-addresses, we must parse and
  // use the domain in the Sender header.
  const sender = txn.header.get_decoded('Sender')
  if (sender) {
    try {
      domain = addrparser.parse(sender)[0].host().toLowerCase()
    } catch (e) {
      connection.logerror(this, e)
    }
  }
  return domain
}

exports.dkim_verify = function (next, connection) {
  const txn = connection?.transaction
  if (!txn) return next()

  const verifier = new DKIMVerifyStream(
    this.cfg.verify,
    (err, result, results) => {
      if (err) {
        txn.results.add(this, { err })
        return next()
      }
      if (!results || results.length === 0) {
        txn.results.add(this, { skip: 'no/bad dkim signature' })
        return next(CONT, 'no/bad signature')
      }
      for (const res of results) {
        let res_err = ''
        if (res.error) res_err = ` (${res.error})`
        connection.auth_results(
          `dkim=${res.result}${res_err} header.i=${res.identity} header.d=${res.domain} header.s=${res.selector}`,
        )
        connection.loginfo(
          this,
          `identity="${res.identity}" domain="${res.domain}" selector="${res.selector}" result=${res.result} ${res_err}`,
        )

        // save to ResultStore
        const rs_obj = JSON.parse(JSON.stringify(res))
        if (res.result === 'pass') {
          rs_obj.pass = res.domain
        } else if (res.result === 'fail') {
          rs_obj.fail = res.domain + res_err
        } else {
          rs_obj.err = res.domain + res_err
        }
        txn.results.add(this, rs_obj)
      }

      connection.logdebug(this, JSON.stringify(results))
      // Store results for other plugins
      txn.notes.dkim_results = results
      next()
    },
  )

  txn.message_stream.pipe(verifier, { line_endings: '\r\n' })
}
