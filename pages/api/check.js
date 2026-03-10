import dns from "dns/promises"

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
  const jp3 = parts.slice(-3).join(".")

  const jpPublicSuffix2 = [
    "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp"
  ]

  if (jpPublicSuffix2.includes(last2) && parts.length >= 3) {
    return jp3
  }

  return last2
}

function countDirectSpfLookups(record) {
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

async function getTxtRecords(name) {
  const txt = await dns.resolveTxt(name)
  return txt.map(r => r.join(""))
}

async function resolveSpfRecursive(domain, visited = new Set(), depth = 0, maxDepth = 10) {
  const result = {
    found: false,
    record: "",
    includes: [],
    visited: [],
    totalLookups: 0,
    warning: false,
    tree: [],
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
  result.visited = [...visited]

  try {
    const records = await getTxtRecords(domain)
    const spfRecord = records.find(r => r.toLowerCase().includes("v=spf1"))

    if (!spfRecord) {
      return result
    }

    result.found = true
    result.record = spfRecord

    const directLookups = countDirectSpfLookups(spfRecord)
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
      result.errors.push(...child.errors)
    }

    result.warning = result.totalLookups > 10
    return result
  } catch (e) {
    result.errors.push(`${domain}: ${String(e.message || e)}`)
    return result
  }
}

function buildSelectorList(domain) {
  const local = domain.split(".")[0] || "default"

  const common = [
    "selector1","selector2","selector3","selector4","selector5",
    "default","google","k1","k2","dkim","mail","smtp","mx","s1","s2",
    "zendesk","sendgrid","sg","mg","mandrill","mailgun","amazonses","ses",
    "sparkpost","postmark","pm","brevo","sendinblue","hubspot","hs1","hs2",
    "zoho","zmail","outlook","microsoft","ms","o365","office365","protection",
    "gmail","gworkspace","workspace","googleworkspace",
    "mailer","newsletter","news","campaign","bulk","bounce","transactional",
    "pmta","mta","relay","postfix","exim","qmail","smtp1","smtp2",
    "dkim1","dkim2","dkim3",
    "selector01","selector02","selector03","selector10",
    "alpha","beta","prod","stage","test",
    "x","y","z",
    local
  ]

  const numbered = []
  for (let i = 1; i <= 40; i++) {
    numbered.push(`s${i}`)
    numbered.push(`k${i}`)
  }

  return uniq([...common, ...numbered]).slice(0, 100)
}

async function findDkim(domain) {
  const selectors = buildSelectorList(domain)

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
          return {
            found: true,
            selector: s,
            host,
            record: joined,
            tags: parseTags(joined),
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
    triedCount: selectors.length
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

function scoreMailSecurity(data) {
  let score = 0
  const notes = []

  if (data.spf) score += 15
  else notes.push("SPF missing")

  if (data.dkim) score += 20
  else notes.push("DKIM missing")

  if (data.dmarc) score += 20
  else notes.push("DMARC missing")

  if (data.dmarc) {
    if (data.dmarcPolicy === "none") {
      score += 5
      notes.push("DMARC policy is monitoring only")
    } else if (data.dmarcPolicy === "quarantine") {
      score += 10
    } else if (data.dmarcPolicy === "reject") {
      score += 15
    }
  }

  if (data.spfRecursive?.found && !data.spfRecursive.warning) score += 10
  else if (data.spfRecursive?.warning) notes.push("SPF lookup count exceeds 10")

  if (data.dmarcAlignment?.overall) score += 10
  else notes.push("DMARC alignment not fully satisfied")

  if (data.mx) score += 5
  else notes.push("MX missing")

  if (data.tlsRpt) score += 5
  if (data.mtaSts) score += 5
  if (data.bimi) score += 5

  if (!data.blacklist) score += 5
  else notes.push("RBL listing detected on MX IP")

  if (data.smtpTls?.supported) score += 5
  else notes.push("SMTP TLS test not confirmed")

  if (score > 100) score = 100
  if (score < 0) score = 0

  let grade = "D"
  if (score >= 90) grade = "A"
  else if (score >= 75) grade = "B"
  else if (score >= 60) grade = "C"

  return { score, grade, notes }
}

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
    let dkimTriedCount = 0

    let dmarc = false
    let dmarcRecord = ""
    let dmarcPolicy = "none"
    let dmarcAlignment = {
      spfAligned: false,
      dkimAligned: false,
      overall: false,
      note: "strict validation requires actual mail header analysis"
    }

    let mx = false
    let mxHosts = []
    let mxResolved = []

    let bimi = false
    let bimiRecord = ""

    let tlsRpt = false
    let tlsRptRecord = ""

    let mtaSts = false
    let mtaStsRecord = ""
    const mtaStsPolicyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`

    let smtpTls = {
      checked: false,
      supported: false,
      mode: "dns-inferred",
      note: "live SMTP handshake is not reliable on Vercel serverless"
    }

    // SPF basic
    try {
      const txts = await getTxtRecords(domain)
      const rec = txts.find(r => r.toLowerCase().includes("v=spf1"))
      if (rec) {
        spf = true
        spfRecord = rec
        spfLookups = countDirectSpfLookups(rec)
      }
    } catch (e) {}

    // SPF recursive
    spfRecursive = await resolveSpfRecursive(domain)
    if (spfRecursive?.found) {
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
      }
    } catch (e) {}

    // MX
    try {
      const mxRecords = await dns.resolveMx(domain)
      if (mxRecords.length > 0) {
        mx = true
        mxHosts = mxRecords
          .sort((a, b) => a.priority - b.priority)
          .map(r => ({ exchange: r.exchange, priority: r.priority }))
      }
    } catch (e) {}

    // MX -> IP -> RBL
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

    // SMTP TLS inferred
    if (mtaSts || tlsRpt || mx) {
      smtpTls = {
        checked: true,
        supported: Boolean(mtaSts || tlsRpt),
        mode: "dns-inferred",
        note: mtaSts || tlsRpt
          ? "DNS signals indicate TLS mail transport policy/reporting is configured"
          : "MX exists but no DNS TLS policy/reporting detected"
      }
    }

    const gmailPass = spf && dmarc && (dkim || spf)
    const outlookPass = spf && dmarc && (dkim || spf)

    const scoreObj = scoreMailSecurity({
      spf,
      dkim,
      dmarc,
      dmarcPolicy,
      spfRecursive,
      dmarcAlignment,
      mx,
      tlsRpt,
      mtaSts,
      bimi,
      blacklist,
      smtpTls
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
      dkimTriedCount,

      dmarc,
      dmarcRecord,
      dmarcPolicy,
      dmarcAlignment,

      mx,
      mxHosts,
      mxResolved,

      bimi,
      bimiRecord,

      tlsRpt,
      tlsRptRecord,

      mtaSts,
      mtaStsRecord,
      mtaStsPolicyUrl,

      smtpTls,

      gmailPass,
      outlookPass,

      blacklist,

      securityScore: scoreObj.score,
      securityGrade: scoreObj.grade,
      securityNotes: scoreObj.notes
    })
  } catch (e) {
    return res.status(500).json({
      error: "internal error",
      detail: String(e?.message || e)
    })
  }
}
