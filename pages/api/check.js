import dns from "dns/promises"
import tls from "tls"
import https from "https"

/* -----------------------------
 utils
------------------------------*/

function uniq(arr) {
  return [...new Set(arr)]
}

function safeLower(v) {
  return String(v || "").trim().toLowerCase()
}

function parseTags(record) {
  const tags = {}
  const parts = String(record)
    .split(";")
    .map(v => v.trim())
    .filter(Boolean)

  for (const part of parts) {
    const i = part.indexOf("=")
    if (i > -1) {
      const k = part.slice(0, i).trim()
      const v = part.slice(i + 1).trim()
      tags[k] = v
    }
  }
  return tags
}

function extractRootDomain(domain) {
  const parts = domain.split(".")
  if (parts.length <= 2) return domain

  const last2 = parts.slice(-2).join(".")
  const last3 = parts.slice(-3).join(".")

  const jpSuffix = [
    "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp",
    "ed.jp", "go.jp", "gr.jp", "lg.jp"
  ]

  if (jpSuffix.includes(last2) && parts.length >= 3) {
    return last3
  }

  return last2
}

async function getTxtRecords(name) {
  const txt = await dns.resolveTxt(name)
  return txt.map(r => r.join(""))
}

/* -----------------------------
 SPF
------------------------------*/

function countSpfLookups(record) {
  const patterns = [
    /include:/gi,
    /\ba(?=[:\s]|$)/gi,
    /\bmx(?=[:\s]|$)/gi,
    /\bptr(?=[:\s]|$)/gi,
    /exists:/gi,
    /redirect=/gi
  ]

  let count = 0
  for (const p of patterns) {
    const m = record.match(p)
    if (m) count += m.length
  }
  return count
}

function getSpfIncludes(record) {
  const matches = [...String(record).matchAll(/include:([^\s]+)/gi)]
  return uniq(matches.map(m => m[1].trim()).filter(Boolean))
}

function flattenSpfRecord(record, includeRecords) {
  let flattened = record

  for (const inc of includeRecords) {
    flattened += `  # include:${inc.domain} => ${inc.record}`
  }

  return flattened
}

async function resolveSpfRecursive(domain, visited = new Set(), depth = 0, maxDepth = 10) {
  const result = {
    found: false,
    record: "",
    includes: [],
    totalLookups: 0,
    warning: false,
    tree: [],
    includeRecords: [],
    errors: []
  }

  const key = safeLower(domain)
  if (!key) return result
  if (visited.has(key)) {
    result.errors.push(`loop detected: ${key}`)
    return result
  }
  if (depth > maxDepth) {
    result.errors.push(`max depth exceeded at ${key}`)
    return result
  }

  visited.add(key)

  try {
    const records = await getTxtRecords(domain)
    const spfRecord = records.find(r => r.toLowerCase().includes("v=spf1"))

    if (!spfRecord) return result

    result.found = true
    result.record = spfRecord

    const directLookups = countSpfLookups(spfRecord)
    const includes = getSpfIncludes(spfRecord)

    result.includes = includes
    result.totalLookups += directLookups
    result.tree.push({
      domain,
      record: spfRecord,
      directLookups,
      includes
    })

    for (const inc of includes) {
      const child = await resolveSpfRecursive(inc, visited, depth + 1, maxDepth)
      result.totalLookups += child.totalLookups
      result.tree.push(...child.tree)
      result.includeRecords.push(
        ...(child.record ? [{ domain: inc, record: child.record }] : [])
      )
      result.includeRecords.push(...(child.includeRecords || []))
      result.errors.push(...child.errors)
    }

    result.warning = result.totalLookups > 10
    result.flattenedCandidate = flattenSpfRecord(spfRecord, result.includeRecords)

    return result
  } catch (e) {
    result.errors.push(`${domain}: ${String(e.message || e)}`)
    return result
  }
}

/* -----------------------------
 DKIM
------------------------------*/

function buildSelectors(domain) {
  const local = domain.split(".")[0] || "default"

  const common = [
    "selector1", "selector2", "selector3", "selector4", "selector5",
    "default", "google", "k1", "k2", "dkim", "mail", "smtp", "mx", "s1", "s2",
    "zendesk", "sendgrid", "sg", "mg", "mandrill", "mailgun", "amazonses", "ses",
    "sparkpost", "postmark", "pm", "brevo", "sendinblue", "hubspot", "hs1", "hs2",
    "zoho", "zmail", "outlook", "microsoft", "ms", "o365", "office365",
    "gmail", "workspace", "googleworkspace",
    "mailer", "newsletter", "news", "campaign", "bulk", "bounce", "transactional",
    "pmta", "mta", "relay", "postfix", "exim", "qmail", "smtp1", "smtp2",
    "dkim1", "dkim2", "dkim3",
    local
  ]

  const numbered = []
  for (let i = 1; i <= 40; i++) {
    numbered.push(`s${i}`)
    numbered.push(`k${i}`)
  }

  return uniq([...common, ...numbered]).slice(0, 100)
}

function estimateDkimKeyStrength(record) {
  const tags = parseTags(record)
  const p = tags.p || ""

  if (!p) {
    return {
      bitsEstimate: null,
      rating: "unknown",
      note: "public key not found"
    }
  }

  const len = p.replace(/\s+/g, "").length

  if (len >= 680) {
    return {
      bitsEstimate: 4096,
      rating: "strong",
      note: "estimated from public key length"
    }
  }

  if (len >= 340) {
    return {
      bitsEstimate: 2048,
      rating: "good",
      note: "estimated from public key length"
    }
  }

  if (len >= 170) {
    return {
      bitsEstimate: 1024,
      rating: "weak",
      note: "estimated from public key length"
    }
  }

  return {
    bitsEstimate: null,
    rating: "unknown",
    note: "could not estimate key size reliably"
  }
}

async function findDkim(domain) {
  const selectors = buildSelectors(domain)

  for (const s of selectors) {
    const host = `${s}._domainkey.${domain}`
    try {
      const txts = await getTxtRecords(host)
      if (txts.length > 0) {
        const joined = txts.join("")
        if (
          joined.toLowerCase().includes("v=dkim1") ||
          joined.toLowerCase().includes("k=rsa") ||
          joined.toLowerCase().includes("p=")
        ) {
          const tags = parseTags(joined)
          return {
            found: true,
            selector: s,
            host,
            record: joined,
            tags,
            keyStrength: estimateDkimKeyStrength(joined),
            triedCount: selectors.indexOf(s) + 1
          }
        }
      }
    } catch (e) {}
  }

  return {
    found: false,
    selector: null,
    host: null,
    record: "",
    tags: null,
    keyStrength: {
      bitsEstimate: null,
      rating: "unknown",
      note: "dkim not found"
    },
    triedCount: selectors.length
  }
}

/* -----------------------------
 MX / RBL
------------------------------*/

async function resolveMxSmart(domain) {
  const domainsToTry = [domain, extractRootDomain(domain)]

  for (const d of domainsToTry) {
    try {
      const mx = await dns.resolveMx(d)
      if (mx.length > 0) {
        return {
          found: true,
          domain: d,
          mx
        }
      }
    } catch (e) {}
  }

  return {
    found: false,
    domain: null,
    mx: []
  }
}

function reverseIPv4(ip) {
  return ip.split(".").reverse().join(".")
}

async function checkRblForIp(ip) {
  const zones = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net"
  ]

  const results = []

  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    return {
      listed: false,
      results: [{ zone: "n/a", listed: false, note: "IPv6 or invalid IP skipped" }]
    }
  }

  const rev = reverseIPv4(ip)

  for (const zone of zones) {
    const q = `${rev}.${zone}`
    try {
      const ans = await dns.resolve4(q)
      results.push({
        zone,
        listed: true,
        response: ans.join(", ")
      })
    } catch (e) {
      results.push({
        zone,
        listed: false
      })
    }
  }

  return {
    listed: results.some(r => r.listed),
    results
  }
}

async function resolveMxIps(mxHosts) {
  const out = []

  for (const mx of mxHosts) {
    const entry = {
      exchange: mx.exchange,
      priority: mx.priority,
      ipv4: [],
      ipv6: [],
      rbl: {
        listed: false,
        results: []
      }
    }

    try {
      entry.ipv4 = await dns.resolve4(mx.exchange)
    } catch (e) {}

    try {
      entry.ipv6 = await dns.resolve6(mx.exchange)
    } catch (e) {}

    if (entry.ipv4.length > 0) {
      const rblChecks = []
      for (const ip of entry.ipv4.slice(0, 3)) {
        const rbl = await checkRblForIp(ip)
        rblChecks.push({ ip, ...rbl })
      }
      entry.rbl = {
        listed: rblChecks.some(x => x.listed),
        results: rblChecks
      }
    }

    out.push(entry)
  }

  return out
}

/* -----------------------------
 DMARC
------------------------------*/

function parseDmarcRua(record) {
  const m = String(record).match(/rua=([^;]+)/i)
  if (!m) return []
  return m[1]
    .split(",")
    .map(v => v.trim())
    .filter(Boolean)
}

function parseDmarcRuf(record) {
  const m = String(record).match(/ruf=([^;]+)/i)
  if (!m) return []
  return m[1]
    .split(",")
    .map(v => v.trim())
    .filter(Boolean)
}

/* -----------------------------
 HTTPS fetch for MTA-STS
------------------------------*/

function fetchText(url, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      let data = ""
      res.on("data", chunk => {
        data += chunk
      })
      res.on("end", () => {
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          body: data
        })
      })
    })

    req.on("error", (e) => {
      resolve({
        ok: false,
        status: 0,
        body: "",
        error: String(e.message || e)
      })
    })

    req.on("timeout", () => {
      req.destroy()
      resolve({
        ok: false,
        status: 0,
        body: "",
        error: "timeout"
      })
    })
  })
}

/* -----------------------------
 SMTP TLS handshake
------------------------------*/

function smtpTlsProbe(host, port = 25, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: timeoutMs
      },
      () => {
        const cert = socket.getPeerCertificate?.() || null
        socket.end()

        resolve({
          ok: true,
          host,
          port,
          protocol: socket.getProtocol?.() || null,
          cipher: socket.getCipher?.() || null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
          certificateSubject: cert?.subject || null,
          certificateIssuer: cert?.issuer || null,
          valid_from: cert?.valid_from || null,
          valid_to: cert?.valid_to || null,
          note: "implicit TLS probe succeeded"
        })
      }
    )

    socket.on("error", (e) => {
      resolve({
        ok: false,
        host,
        port,
        error: String(e.message || e),
        note: "TLS probe failed; common on serverless or if host expects STARTTLS only"
      })
    })

    socket.on("timeout", () => {
      socket.destroy()
      resolve({
        ok: false,
        host,
        port,
        error: "timeout",
        note: "TLS probe timed out"
      })
    })
  })
}

async function testSmtpTls(mxResolved, tlsRpt, mtaSts) {
  if (!mxResolved || mxResolved.length === 0) {
    return {
      checked: false,
      supported: false,
      mode: "not-run",
      note: "no MX hosts found",
      probes: []
    }
  }

  const probes = []
  const targets = mxResolved.slice(0, 2)

  for (const mx of targets) {
    const host = mx.exchange

    // Try 465 first as pure TLS, then 25 as opportunistic attempt.
    const p465 = await smtpTlsProbe(host, 465, 4000)
    probes.push(p465)
    if (p465.ok) {
      return {
        checked: true,
        supported: true,
        mode: "live-tls-probe",
        note: "TLS handshake succeeded on port 465",
        probes
      }
    }

    const p25 = await smtpTlsProbe(host, 25, 4000)
    probes.push(p25)
    if (p25.ok) {
      return {
        checked: true,
        supported: true,
        mode: "live-tls-probe",
        note: "TLS handshake succeeded on port 25",
        probes
      }
    }
  }

  return {
    checked: true,
    supported: Boolean(tlsRpt || mtaSts),
    mode: "dns-fallback",
    note: (tlsRpt || mtaSts)
      ? "live probe failed, but DNS signals indicate mail TLS policy/reporting exists"
      : "live probe failed and no DNS TLS policy/reporting found",
    probes
  }
}

/* -----------------------------
 Deliverability Score
------------------------------*/

function scoreMailSecurity(data) {
  let score = 0
  const notes = []

  if (data.spf) score += 15
  else notes.push("SPF missing")

  if (data.dkim) score += 18
  else notes.push("DKIM missing")

  if (data.dmarc) score += 18
  else notes.push("DMARC missing")

  if (data.dmarc) {
    if (data.dmarcPolicy === "none") {
      score += 4
      notes.push("DMARC policy is monitoring only")
    } else if (data.dmarcPolicy === "quarantine") {
      score += 8
    } else if (data.dmarcPolicy === "reject") {
      score += 12
    }
  }

  if (data.spfRecursive?.found && !data.spfRecursive.warning) score += 8
  else if (data.spfRecursive?.warning) notes.push("SPF lookup count exceeds 10")

  if (data.dmarcAlignment?.overall) score += 8
  else notes.push("DMARC alignment not fully satisfied")

  if (data.mx) score += 5
  else notes.push("MX missing")

  if (data.tlsRpt) score += 4
  if (data.mtaSts) score += 5
  if (data.bimi) score += 4

  if (!data.blacklist) score += 5
  else notes.push("RBL listing detected on MX IP")

  if (data.dkimKeyStrength?.bitsEstimate >= 2048) score += 5
  else if (data.dkim && data.dkimKeyStrength?.bitsEstimate === 1024) notes.push("DKIM key appears weak (1024-bit class)")
  else if (data.dkim) notes.push("DKIM key strength unknown")

  if (data.smtpTls?.supported) score += 5
  else notes.push("SMTP TLS not confirmed")

  if (data.rua?.length > 0) score += 3
  else if (data.dmarc) notes.push("DMARC rua not configured")

  if (score > 100) score = 100
  if (score < 0) score = 0

  let grade = "D"
  if (score >= 90) grade = "A"
  else if (score >= 75) grade = "B"
  else if (score >= 60) grade = "C"

  return { score, grade, notes }
}

function buildDeliverabilityScore(data) {
  let score = 0
  const reasons = []

  if (data.spf) score += 20
  else reasons.push("SPF missing")

  if (data.dkim) score += 20
  else reasons.push("DKIM missing")

  if (data.dmarc) score += 20
  else reasons.push("DMARC missing")

  if (data.dmarcPolicy === "reject") score += 10
  else if (data.dmarcPolicy === "quarantine") score += 6
  else if (data.dmarcPolicy === "none") reasons.push("DMARC policy not enforcing")

  if (data.blacklist) {
    reasons.push("RBL listing detected")
  } else {
    score += 10
  }

  if (data.smtpTls?.supported) score += 8
  else reasons.push("SMTP TLS not confirmed")

  if (data.mtaSts) score += 4
  if (data.tlsRpt) score += 4
  if (data.bimi) score += 4

  if (data.spfRecursive?.warning) reasons.push("SPF lookup budget too high")

  if (score > 100) score = 100

  let label = "Poor"
  if (score >= 85) label = "Excellent"
  else if (score >= 70) label = "Good"
  else if (score >= 55) label = "Fair"

  return { score, label, reasons }
}

/* -----------------------------
 main
------------------------------*/

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method not allowed" })
    }

    const domain = safeLower(req.body?.domain)
    if (!domain) {
      return res.status(400).json({ error: "domain required" })
    }

    const rootDomain = extractRootDomain(domain)

    let spf = false
    let spfRecord = ""
    let spfLookups = 0
    let spfLookupWarning = false
    let spfRecursive = null

    let dkim = false
    let dkimSelector = null
    let dkimHost = null
    let dkimRecord = ""
    let dkimTags = null
    let dkimKeyStrength = null
    let dkimTriedCount = 0

    let dmarc = false
    let dmarcRecord = ""
    let dmarcPolicy = "none"
    let rua = []
    let ruf = []
    let dmarcAlignment = {
      spfAligned: false,
      dkimAligned: false,
      overall: false,
      note: "strict validation requires actual mail header analysis"
    }

    let mx = false
    let mxFoundOn = null
    let mxHosts = []
    let mxResolved = []

    let bimi = false
    let bimiRecord = ""

    let tlsRpt = false
    let tlsRptRecord = ""

    let mtaSts = false
    let mtaStsRecord = ""
    const mtaStsPolicyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`
    let mtaStsPolicy = {
      fetched: false,
      ok: false,
      status: 0,
      body: "",
      parsed: null
    }

    // SPF basic
    try {
      const txts = await getTxtRecords(domain)
      const rec = txts.find(r => r.toLowerCase().includes("v=spf1"))
      if (rec) {
        spf = true
        spfRecord = rec
        spfLookups = countSpfLookups(rec)
      }
    } catch (e) {}

    // SPF recursive
    spfRecursive = await resolveSpfRecursive(domain)
    if (spfRecursive?.found) {
      spf = true
      spfLookupWarning = spfRecursive.warning
      if (!spfRecord) spfRecord = spfRecursive.record
      if (!spfLookups) spfLookups = spfRecursive.totalLookups
    }

    // DKIM
    const dkimFound = await findDkim(domain)
    dkim = dkimFound.found
    dkimSelector = dkimFound.selector
    dkimHost = dkimFound.host
    dkimRecord = dkimFound.record
    dkimTags = dkimFound.tags
    dkimKeyStrength = dkimFound.keyStrength
    dkimTriedCount = dkimFound.triedCount

    // DMARC
    try {
      const txts = await getTxtRecords(`_dmarc.${domain}`)
      const rec = txts.find(r => r.toLowerCase().includes("v=dmarc1"))
      if (rec) {
        dmarc = true
        dmarcRecord = rec
        const m = rec.match(/p=([^;]+)/i)
        if (m) dmarcPolicy = safeLower(m[1])
        rua = parseDmarcRua(rec)
        ruf = parseDmarcRuf(rec)
      }
    } catch (e) {}

    // MX
    const mxResult = await resolveMxSmart(domain)
    mx = mxResult.found
    mxFoundOn = mxResult.domain
    mxHosts = mxResult.mx
      .sort((a, b) => a.priority - b.priority)
      .map(r => ({ exchange: r.exchange, priority: r.priority }))

    if (mxHosts.length > 0) {
      mxResolved = await resolveMxIps(mxHosts)
    }

    const blacklist = mxResolved.some(x => x.rbl?.listed)

    // DMARC alignment approximation
    dmarcAlignment = {
      spfAligned: spf,
      dkimAligned: dkim,
      overall: dmarc && (spf || dkim),
      note: "strict validation requires actual mail header analysis"
    }

    // BIMI
    try {
      const txts = await getTxtRecords(`default._bimi.${domain}`)
      const rec = txts.find(r => r.toLowerCase().includes("v=bimi1"))
      if (rec) {
        bimi = true
        bimiRecord = rec
      }
    } catch (e) {}

    // TLS-RPT
    try {
      const txts = await getTxtRecords(`_smtp._tls.${domain}`)
      const rec = txts.find(r => r.toLowerCase().includes("v=tlsrptv1"))
      if (rec) {
        tlsRpt = true
        tlsRptRecord = rec
      }
    } catch (e) {}

    // MTA-STS DNS
    try {
      const txts = await getTxtRecords(`_mta-sts.${domain}`)
      const rec = txts.find(r => r.toLowerCase().includes("v=stsv1"))
      if (rec) {
        mtaSts = true
        mtaStsRecord = rec
      }
    } catch (e) {}

    // MTA-STS policy fetch
    const policyFetch = await fetchText(mtaStsPolicyUrl, 5000)
    if (policyFetch.ok) {
      const body = policyFetch.body || ""
      const parsed = parseTags(body.replace(/\n/g, ";"))
      mtaStsPolicy = {
        fetched: true,
        ok: true,
        status: policyFetch.status,
        body,
        parsed
      }
    } else {
      mtaStsPolicy = {
        fetched: true,
        ok: false,
        status: policyFetch.status || 0,
        body: "",
        parsed: null,
        error: policyFetch.error || null
      }
    }

    // SMTP TLS
    const smtpTls = await testSmtpTls(mxResolved, tlsRpt, mtaSts)

    // Provider readiness
    const gmailPass = spf && dmarc && (dkim || spf)
    const outlookPass = spf && dmarc && (dkim || spf)

    // Scoring
    const scoreObj = scoreMailSecurity({
      spf,
      dkim,
      dkimKeyStrength,
      dmarc,
      dmarcPolicy,
      rua,
      spfRecursive,
      dmarcAlignment,
      mx,
      tlsRpt,
      mtaSts,
      bimi,
      blacklist,
      smtpTls
    })

    const deliverability = buildDeliverabilityScore({
      spf,
      dkim,
      dmarc,
      dmarcPolicy,
      blacklist,
      smtpTls,
      mtaSts,
      tlsRpt,
      bimi,
      spfRecursive
    })

    return res.status(200).json({
      domain,
      rootDomain,

      spf,
      spfRecord,
      spfLookups,
      spfLookupWarning,
      spfRecursive,

      dkim,
      dkimSelector,
      dkimHost,
      dkimRecord,
      dkimTags,
      dkimKeyStrength,
      dkimTriedCount,

      dmarc,
      dmarcRecord,
      dmarcPolicy,
      rua,
      ruf,
      dmarcAlignment,

      mx,
      mxFoundOn,
      mxHosts,
      mxResolved,

      bimi,
      bimiRecord,

      tlsRpt,
      tlsRptRecord,

      mtaSts,
      mtaStsRecord,
      mtaStsPolicyUrl,
      mtaStsPolicy,

      smtpTls,

      gmailPass,
      outlookPass,

      blacklist,

      securityScore: scoreObj.score,
      securityGrade: scoreObj.grade,
      securityNotes: scoreObj.notes,

      deliverabilityScore: deliverability.score,
      deliverabilityLabel: deliverability.label,
      deliverabilityReasons: deliverability.reasons
    })
  } catch (e) {
    return res.status(500).json({
      error: "internal error",
      detail: String(e?.message || e)
    })
  }
}
