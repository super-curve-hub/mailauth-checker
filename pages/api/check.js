import dns from "dns/promises"

function extractRootDomain(domain) {
  const parts = domain.split(".")
  if (parts.length <= 2) return domain
  return parts.slice(-2).join(".")
}

function countSpfLookups(record) {
  const patterns = [
    /include:/g,
    /a(?=[:\s]|$)/g,
    /mx(?=[:\s]|$)/g,
    /ptr(?=[:\s]|$)/g,
    /exists:/g,
    /redirect=/g
  ]

  let count = 0
  for (const p of patterns) {
    const matches = record.match(p)
    if (matches) count += matches.length
  }
  return count
}

function parseDkimTags(record) {
  const tags = {}
  const parts = record.split(";").map(v => v.trim()).filter(Boolean)

  for (const part of parts) {
    const idx = part.indexOf("=")
    if (idx > -1) {
      const key = part.slice(0, idx).trim()
      const value = part.slice(idx + 1).trim()
      tags[key] = value
    }
  }

  return tags
}

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method not allowed" })
    }

    const domain = (req.body?.domain || "").trim().toLowerCase()

    if (!domain) {
      return res.status(400).json({ error: "domain required" })
    }

    let spf = false
    let dmarc = false
    let dkim = false
    let mx = false

    let spfRecord = ""
    let spfLookups = 0
    let spfLookupWarning = false

    let dmarcRecord = ""
    let dmarcPolicy = "none"
    let dmarcAlignment = {
      spfAligned: false,
      dkimAligned: false,
      overall: false
    }

    let dkimSelector = null
    let dkimRecord = ""
    let dkimTags = null

    let bimi = false
    let bimiRecord = ""

    let tlsRpt = false
    let tlsRptRecord = ""

    let mtaSts = false
    let mtaStsRecord = ""
    let mtaStsPolicyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`

    let blacklist = false
    let blacklistNote = "not checked against live MX IP yet"

    let mxHosts = []

    // --------------------
    // SPF
    // --------------------
    try {
      const txt = await dns.resolveTxt(domain)

      for (const r of txt) {
        const record = r.join("")
        if (record.toLowerCase().includes("v=spf1")) {
          spf = true
          spfRecord = record
          spfLookups = countSpfLookups(record)
          spfLookupWarning = spfLookups > 10
          break
        }
      }
    } catch (e) {}

    // --------------------
    // DMARC
    // --------------------
    try {
      const txt = await dns.resolveTxt(`_dmarc.${domain}`)

      for (const r of txt) {
        const record = r.join("")
        if (record.toUpperCase().includes("V=DMARC1")) {
          dmarc = true
          dmarcRecord = record

          const p = record.match(/p=([^;]+)/i)
          if (p) dmarcPolicy = p[1].trim().toLowerCase()

          break
        }
      }
    } catch (e) {}

    // --------------------
    // DKIM selector search
    // --------------------
    const selectors = [
      "selector1",
      "selector2",
      "default",
      "google",
      "k1",
      "dkim",
      "mail",
      "smtp"
    ]

    for (const s of selectors) {
      try {
        const txt = await dns.resolveTxt(`${s}._domainkey.${domain}`)
        if (txt && txt.length > 0) {
          dkim = true
          dkimSelector = s
          dkimRecord = txt.map(x => x.join("")).join("")
          dkimTags = parseDkimTags(dkimRecord)
          break
        }
      } catch (e) {}
    }

    // --------------------
    // MX
    // --------------------
    try {
      const mxRecords = await dns.resolveMx(domain)
      if (mxRecords.length > 0) {
        mx = true
        mxHosts = mxRecords
          .sort((a, b) => a.priority - b.priority)
          .map(r => ({ exchange: r.exchange, priority: r.priority }))
      }
    } catch (e) {}

    // --------------------
    // DMARC alignment (DNS-based approximation)
    // --------------------
    // 厳密なalignmentは実メールのReturn-Path / DKIM d= が必要。
    // ここではDNS上の近似チェックを返す。
    const root = extractRootDomain(domain)

    let spfAligned = false
    let dkimAligned = false

    if (spf && spfRecord) {
      spfAligned = true
    }

    if (dkim && dkimRecord) {
      dkimAligned = true
    }

    dmarcAlignment = {
      spfAligned,
      dkimAligned,
      overall: dmarc && (spfAligned || dkimAligned),
      note: "strict validation requires actual mail header analysis"
    }

    // --------------------
    // BIMI
    // --------------------
    try {
      const txt = await dns.resolveTxt(`default._bimi.${domain}`)
      for (const r of txt) {
        const record = r.join("")
        if (record.toLowerCase().includes("v=bimi1")) {
          bimi = true
          bimiRecord = record
          break
        }
      }
    } catch (e) {}

    // --------------------
    // TLS-RPT
    // --------------------
    try {
      const txt = await dns.resolveTxt(`_smtp._tls.${domain}`)
      for (const r of txt) {
        const record = r.join("")
        if (record.toLowerCase().includes("v=tlsrptv1")) {
          tlsRpt = true
          tlsRptRecord = record
          break
        }
      }
    } catch (e) {}

    // --------------------
    // MTA-STS DNS
    // --------------------
    try {
      const txt = await dns.resolveTxt(`_mta-sts.${domain}`)
      for (const r of txt) {
        const record = r.join("")
        if (record.toLowerCase().includes("v=stsv1")) {
          mtaSts = true
          mtaStsRecord = record
          break
        }
      }
    } catch (e) {}

    // --------------------
    // Gmail / Outlook判定
    // 実務上の簡易判定
    // --------------------
    const gmailPass = spf && dmarc && (dkim || spf)
    const outlookPass = spf && dmarc && (dkim || spf)

    return res.status(200).json({
      domain,
      rootDomain: root,

      spf,
      spfRecord,
      spfLookups,
      spfLookupWarning,

      dkim,
      dkimSelector,
      dkimRecord,
      dkimTags,

      dmarc,
      dmarcRecord,
      dmarcPolicy,
      dmarcAlignment,

      mx,
      mxHosts,

      bimi,
      bimiRecord,

      tlsRpt,
      tlsRptRecord,

      mtaSts,
      mtaStsRecord,
      mtaStsPolicyUrl,

      gmailPass,
      outlookPass,

      blacklist,
      blacklistNote
    })
  } catch (e) {
    return res.status(500).json({
      error: "internal error",
      detail: String(e)
    })
  }
}
