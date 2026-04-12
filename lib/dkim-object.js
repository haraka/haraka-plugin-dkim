'use strict'

const crypto = require('node:crypto')
const dns = require('node:dns')

function md5(str) {
  if (!str) str = ''
  const h = crypto.createHash('md5')
  return h.update(str).digest('hex')
}

class DKIMObject {
  constructor(header, header_idx, cb, opts) {
    this.cb = cb
    this.sig = header
    this.sig_md5 = md5(header)
    this.run_cb = false
    this.header_idx = JSON.parse(JSON.stringify(header_idx))
    this.timeout = opts.timeout || 30
    this.allowed_time_skew = opts.allowed_time_skew
    this.fields = {}
    this.headercanon = this.bodycanon = 'simple'
    this.signed_headers = []
    this.identity = 'unknown'
    this.line_buffer = []
    this.body_found = false
    this.dns_fields = {
      v: 'DKIM1',
      k: 'rsa',
      g: '*',
    }

    const [, , dkim_signature] = /^([^:]+):\s*((?:.|[\r\n])*)$/.exec(header)
    const sig = dkim_signature.trim().replace(/\s+/g, '')
    const keys = sig.split(';')
    for (const keyElement of keys) {
      const key = keyElement.trim()
      if (!key) continue // skip empty keys
      const [, key_name, key_value] =
        /^([^= ]+)=((?:.|[\r\n])+)$/.exec(key) || []
      if (key_name) {
        this.fields[key_name] = key_value
      } else {
        return this.result('header parse error', 'invalid')
      }
    }
    /////////////////////
    // Validate fields //
    /////////////////////

    if (this.fields.v) {
      if (this.fields.v !== '1') {
        return this.result('incompatible version', 'invalid')
      }
    } else {
      return this.result('missing version', 'invalid')
    }

    if (this.fields.l) {
      return this.result('length tag is unsupported', 'invalid')
    }

    if (this.fields.a) {
      switch (this.fields.a) {
        case 'rsa-sha1':
          // RFC 8301 §3.2: verifiers MUST NOT treat messages with rsa-sha1
          // as having a valid author signature.
          return this.result(
            'rsa-sha1 is insecure and not supported',
            'invalid',
          )
        case 'rsa-sha256':
          this.bh = crypto.createHash('SHA256')
          this.verifier = crypto.createVerify('RSA-SHA256')
          break
        default:
          this.debug(`Invalid algorithm: ${this.fields.a}`)
          return this.result('invalid algorithm', 'invalid')
      }
    } else {
      return this.result('missing algorithm', 'invalid')
    }

    if (!this.fields.b) return this.result('signature missing', 'invalid')
    if (!this.fields.bh) return this.result('body hash missing', 'invalid')

    if (this.fields.c) {
      const c = this.fields.c.split('/')
      if (c[0]) this.headercanon = c[0]
      if (c[1]) this.bodycanon = c[1]
    }

    if (!this.fields.d) return this.result('domain missing', 'invalid')

    if (this.fields.h) {
      const headers = this.fields.h.split(':')
      for (const h of headers) {
        this.signed_headers.push(h.trim().toLowerCase())
      }
      if (!this.signed_headers.includes('from')) {
        return this.result('from field not signed', 'invalid')
      }
    } else {
      return this.result('signed headers missing', 'invalid')
    }

    if (this.fields.i) {
      // Make sure that this is a sub-domain of the 'd' field
      const dom = this.fields.i.substr(
        this.fields.i.length - this.fields.d.length,
      )
      const prevChar = this.fields.i.charAt(
        this.fields.i.length - this.fields.d.length - 1,
      )
      if (
        dom.toLowerCase() !== this.fields.d.toLowerCase() ||
        (prevChar !== '' && prevChar !== '@' && prevChar !== '.')
      ) {
        return this.result('i/d selector domain mismatch', 'invalid')
      }
    } else {
      this.fields.i = `@${this.fields.d}`
    }
    this.identity = this.fields.i

    if (this.fields.q && this.fields.q !== 'dns/txt') {
      return this.result('unknown query method', 'invalid')
    }

    const now = new Date().getTime() / 1000
    if (this.fields.t) {
      const sigTimestamp = parseInt(this.fields.t, 10)
      if (
        sigTimestamp >
        (this.allowed_time_skew
          ? now + parseInt(this.allowed_time_skew, 10)
          : now)
      ) {
        return this.result(
          'creation date is invalid or in the future',
          'invalid',
        )
      }
    }

    if (this.fields.x) {
      const expireTimestamp = parseInt(this.fields.x, 10)
      const createTimestamp = this.fields.t ? parseInt(this.fields.t, 10) : 0
      if (this.fields.t && expireTimestamp < createTimestamp) {
        return this.result('invalid expiration date', 'invalid')
      }
      if (
        (this.allowed_time_skew
          ? now - parseInt(this.allowed_time_skew, 10)
          : now) > expireTimestamp
      ) {
        return this.result(`signature expired`, 'invalid')
      }
    }

    this.debug(`${this.identity}: DKIM fields validated OK`)
    this.debug(
      `${this.identity}: a=${this.fields.a} c=${this.headercanon}/${this.bodycanon} h=${this.signed_headers}`,
    )
  }

  debug(str) {
    console.debug(str)
  }

  header_canon_relaxed(header) {
    // `|| []` prevents errors thrown when no match
    // `\s*` eats all FWS after the colon
    // eslint-disable-next-line prefer-const
    let [, header_name, header_value] = /^([^:]+):\s*([^]*)$/.exec(header) || []

    if (!header_name) return header
    if (header_value.length === 0) header_value = '\r\n'

    let hc = `${header_name.trim().toLowerCase()}:${header_value}`
    hc = hc.replace(/\r\n([\t ]+)/g, '$1')
    hc = hc.replace(/[\t ]+/g, ' ')
    hc = hc.replace(/[\t ]+(\r?\n)$/, '$1')
    return hc
  }

  add_body_line(line) {
    if (this.run_cb) return

    if (this.bodycanon === 'relaxed') {
      line = DKIMObject.canonicalize(line)
    }

    // Buffer any lines
    const isCRLF = line.length === 2 && line[0] === 0x0d && line[1] === 0x0a
    const isLF = line.length === 1 && line[0] === 0x0a
    if (isCRLF || isLF) {
      // Store any empty lines as both canonicalization algorithms
      // ignore all empty lines at the end of the message body.
      this.line_buffer.push(line)
    } else {
      this.body_found = true
      if (this.line_buffer.length > 0) {
        this.line_buffer.forEach((v) => this.bh.update(v))
        this.line_buffer = []
      }
      this.bh.update(line)
    }
  }

  result(error, result) {
    this.run_cb = true
    return this.cb(error ? new Error(error) : null, {
      identity: this.identity,
      selector: this.fields.s,
      domain: this.fields.d,
      result,
    })
  }

  end() {
    if (this.run_cb) return

    if (!this.body_found) {
      this.bh.update('\r\n')
    }

    const bh = this.bh.digest('base64')
    this.debug(`${this.identity}: bodyhash=${this.fields.bh} computed=${bh}`)
    if (bh !== this.fields.bh) {
      return this.result('body hash did not verify', 'fail')
    }

    // Now we canonicalize the specified headers
    for (const header of this.signed_headers) {
      this.debug(`${this.identity}: canonicalize header: ${header}`)
      if (this.header_idx[header]) {
        // RFC 6376 section 5.4.2, read headers from bottom to top
        const this_header = this.header_idx[header].pop()
        if (this_header) {
          // Skip this signature if dkim-signature is specified
          if (header === 'dkim-signature') {
            const h_md5 = md5(this_header)
            if (h_md5 === this.sig_md5) {
              this.debug(`${this.identity}: skipped our own DKIM-Signature`)
              continue
            }
          }
          if (this.headercanon === 'simple') {
            this.verifier.update(this_header)
          } else if (this.headercanon === 'relaxed') {
            const hc = this.header_canon_relaxed(this_header)
            this.verifier.update(hc)
          }
        }
      }
    }

    // Now add in our original DKIM-Signature header without the b= and trailing CRLF
    let our_sig = this.sig.replace(/([:;\s\t]|^)b=([^;]+)/, '$1b=')
    if (this.headercanon === 'relaxed') {
      our_sig = this.header_canon_relaxed(our_sig)
    }
    our_sig = our_sig.replace(/\r\n$/, '')
    this.verifier.update(our_sig)

    let timeout = false
    const timer = setTimeout(() => {
      timeout = true
      return this.result('DNS timeout', 'tempfail')
    }, this.timeout * 1000)
    const lookup = `${this.fields.s}._domainkey.${this.fields.d}`
    this.debug(
      `${this.identity}: DNS lookup ${lookup} (timeout= ${this.timeout}s)`,
    )
    dns.resolveTxt(lookup, (err, res) => {
      if (timeout) return
      clearTimeout(timer)
      if (err) {
        switch (err.code) {
          case dns.NOTFOUND:
          case dns.NODATA:
          case dns.NXDOMAIN:
            return this.result('no key for signature', 'invalid')
          default:
            this.debug(`${this.identity}: DNS lookup error: ${err.code}`)
            return this.result('key unavailable', 'tempfail')
        }
      }
      if (!res || res.length === 0)
        return this.result('no key for signature', 'invalid')
      if (res.length > 1) {
        this.debug(`${this.identity}: multiple DNS records found`)
        return this.result('multiple DNS records found', 'invalid')
      }

      for (const recordSegments of res) {
        const record = recordSegments.join('')
        if (!record.includes('p=')) {
          this.debug(`${this.identity}: ignoring TXT record: ${record}`)
          continue
        }
        this.debug(`${this.identity}: got DNS record: ${record}`)
        const rec = record.replace(/\r?\n/g, '').replace(/\s+/g, '')
        const split = rec.split(';')
        for (const element of split) {
          const eqIdx = element.indexOf('=')
          if (eqIdx > 0) {
            this.dns_fields[element.slice(0, eqIdx)] = element.slice(eqIdx + 1)
          }
        }

        // Validate
        if (!this.dns_fields.v || this.dns_fields.v !== 'DKIM1') {
          return this.result('invalid version', 'invalid')
        }
        if (this.dns_fields.g) {
          if (this.dns_fields.g !== '*') {
            let s = this.dns_fields.g
            // Escape any special regexp characters
            s = s.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&')
            // Make * a non-greedy match against anything except @
            s = s.replace('\\*', '[^@]*?')
            const reg = new RegExp(`^${s}@`)
            this.debug(
              `${this.identity}: matching ${this.dns_fields.g} against i=${this.fields.i} regexp=${reg.toString()}`,
            )
            if (!reg.test(this.fields.i)) {
              return this.result('inapplicable key', 'invalid')
            }
          }
        } else {
          return this.result('inapplicable key', 'invalid')
        }
        if (this.dns_fields.h) {
          // h= lists the hash algorithms the key owner considers acceptable.
          // Check that the hash algorithm used in the signature (a= field) is
          // in that list.  a= is "keytype-hashalg" e.g. "rsa-sha256".
          const acceptableHashes = this.dns_fields.h
            .split(':')
            .map((h) => h.trim())
          const sigHash = this.fields.a.split('-').pop() // 'sha256' from 'rsa-sha256'
          if (!acceptableHashes.includes(sigHash)) {
            return this.result('inappropriate hash algorithm', 'invalid')
          }
        }
        if (this.dns_fields.k) {
          // k= specifies the key type.  Extract the key-type component of a=
          // (everything before the first '-') and compare exactly.
          const sigKeyType = this.fields.a.split('-')[0] // 'rsa' from 'rsa-sha256'
          if (sigKeyType !== this.dns_fields.k) {
            return this.result('inappropriate key type', 'invalid')
          }
        }
        if (this.dns_fields.t) {
          const flags = this.dns_fields.t.split(':')
          for (const flagElement of flags) {
            const flag = flagElement.trim()
            if (flag === 'y') {
              // Test mode
              this.test_mode = true
            } else if (flag === 's') {
              // 'i' and 'd' domain much match exactly
              let { i } = this.fields
              i = i.substr(i.indexOf('@') + 1, i.length)
              if (i.toLowerCase() !== this.fields.d.toLowerCase()) {
                return this.result(
                  'i/d selector domain mismatch (t=s)',
                  'invalid',
                )
              }
            }
          }
        }
        if (!this.dns_fields.p) return this.result('key revoked', 'invalid')

        // crypto.verifier requires the key in PEM format
        this.public_key = `-----BEGIN PUBLIC KEY-----\r\n${this.dns_fields.p.replace(
          /(.{1,76})/g,
          '$1\r\n',
        )}-----END PUBLIC KEY-----\r\n`

        let verified
        try {
          verified = this.verifier.verify(
            this.public_key,
            this.fields.b,
            'base64',
          )
          this.debug(`${this.identity}: verified=${verified}`)
        } catch (e) {
          this.debug(`${this.identity}: verification error: ${e.message}`)
          return this.result('verification error', 'invalid')
        }
        return this.result(null, verified ? 'pass' : 'fail')
      }
      // We didn't find a valid DKIM record for this signature
      this.result('no key for signature', 'invalid')
    })
  }

  static canonicalize(bufin) {
    const tmp = []
    const len = bufin.length
    let last_chunk_idx = 0
    let idx_wsp = 0
    let in_wsp = false

    for (let idx = 0; idx < len; idx++) {
      const char = bufin[idx]
      if (char === 9 || char === 32) {
        // inside WSP
        if (!in_wsp) {
          // WSP started
          in_wsp = true
          idx_wsp = idx
        }
      } else if (char === 13 || char === 10) {
        // CR?LF
        if (in_wsp) {
          // just after WSP
          tmp.push(bufin.slice(last_chunk_idx, idx_wsp))
        } else {
          // just after regular char
          tmp.push(bufin.slice(last_chunk_idx, idx))
        }
        break
      } else if (in_wsp) {
        // regular char after WSP
        in_wsp = false
        tmp.push(bufin.slice(last_chunk_idx, idx_wsp))
        tmp.push(Buffer.from(' '))
        last_chunk_idx = idx
      }
    }

    tmp.push(Buffer.from([13, 10]))

    return Buffer.concat(tmp)
  }
}

module.exports = DKIMObject
