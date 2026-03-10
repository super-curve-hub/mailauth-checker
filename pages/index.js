import { useState } from "react"

export default function Home() {
  const [domain, setDomain] = useState("")
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  async function check() {
    setLoading(true)
    setError("")
    setResult(null)

    try {
      const res = await fetch("/api/check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ domain })
      })

      const data = await res.json()

      if (!res.ok) {
        setError(data.error || "request failed")
      } else {
        setResult(data)
      }
    } catch (e) {
      setError("network error")
    } finally {
      setLoading(false)
    }
  }

  const box = {
    marginTop: 24,
    padding: 20,
    border: "1px solid #ddd",
    borderRadius: 8
  }

  const mono = {
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    wordBreak: "break-all",
    whiteSpace: "pre-wrap",
    background: "#f7f7f7",
    padding: 10,
    borderRadius: 6,
    marginTop: 8
  }

  const h3 = {
    marginTop: 24,
    marginBottom: 10
  }

  const pill = (text, good = true) => ({
    display: "inline-block",
    padding: "4px 10px",
    borderRadius: 999,
    background: good ? "#e8f7ec" : "#fdecec",
    color: good ? "#176b2c" : "#9f1d1d",
    fontWeight: 700
  })

  return (
    <div style={{ fontFamily: "sans-serif", padding: 24, maxWidth: 1000, margin: "0 auto" }}>
      <h1>MailAuth DNS Checker</h1>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 20 }}>
        <input
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          style={{
            padding: 12,
            fontSize: 18,
            width: 320,
            maxWidth: "100%"
          }}
        />
        <button
          onClick={check}
          style={{
            padding: "12px 20px",
            fontSize: 16,
            cursor: "pointer"
          }}
        >
          Check
        </button>
      </div>

      {loading && <p style={{ marginTop: 20 }}>Checking DNS...</p>}
      {error && <p style={{ marginTop: 20, color: "crimson" }}>Error: {error}</p>}

      {result && (
        <div style={box}>
          <h2>Summary</h2>

          <p><strong>Domain:</strong> {result.domain}</p>
          <p><strong>Root Domain:</strong> {result.rootDomain}</p>

          <p>
            <strong>Mail Security Score:</strong>{" "}
            <span style={pill(result.securityScore >= 75, result.securityScore >= 75)}>
              {result.securityScore} / 100 ({result.securityGrade})
            </span>
          </p>

          <p>
            <strong>Deliverability Score:</strong>{" "}
            <span style={pill(result.deliverabilityScore >= 70, result.deliverabilityScore >= 70)}>
              {result.deliverabilityScore} / 100 ({result.deliverabilityLabel})
            </span>
          </p>

          <h3 style={h3}>Provider Readiness</h3>
          <p>Gmail : {result.gmailPass ? "PASS" : "FAIL"}</p>
          <p>Outlook : {result.outlookPass ? "PASS" : "FAIL"}</p>

          <h3 style={h3}>SPF</h3>
          <p>SPF : {result.spf ? "OK" : "NG"}</p>
          <p>Recursive SPF Lookups : {result.spfRecursive?.totalLookups ?? result.spfLookups}</p>
          <p>SPF 10+ Warning : {result.spfLookupWarning ? "WARNING" : "OK"}</p>
          <div style={mono}>{result.spfRecord || "not found"}</div>

          <h4 style={{ marginTop: 12 }}>SPF Recursive Tree</h4>
          {result.spfRecursive?.tree?.length > 0 ? (
            <div style={mono}>
              {result.spfRecursive.tree.map((node, idx) => (
                <div key={`${node.domain}-${idx}`}>
                  [{idx + 1}] {node.domain} | directLookups={node.directLookups} | includes={node.includes.join(", ") || "-"}
                </div>
              ))}
            </div>
          ) : (
            <div style={mono}>not found</div>
          )}

          <h4 style={{ marginTop: 12 }}>SPF Flatten Candidate</h4>
          <div style={mono}>{result.spfRecursive?.flattenedCandidate || "not generated"}</div>

          <h3 style={h3}>DKIM</h3>
          <p>DKIM : {result.dkim ? "OK" : "NG"}</p>
          <p>Selector : {result.dkimSelector || "not found"}</p>
          <p>Host : {result.dkimHost || "not found"}</p>
          <p>Tried Selectors : {result.dkimTriedCount}</p>
          <p>
            Key Strength :{" "}
            {result.dkimKeyStrength?.bitsEstimate
              ? `${result.dkimKeyStrength.bitsEstimate} bit (${result.dkimKeyStrength.rating})`
              : result.dkimKeyStrength?.rating || "unknown"}
          </p>
          <div style={mono}>{result.dkimRecord || "not found"}</div>

          <h4 style={{ marginTop: 12 }}>DKIM TXT Parsed Tags</h4>
          {result.dkimTags ? (
            <div style={mono}>
              {Object.entries(result.dkimTags).map(([k, v]) => (
                <div key={k}>{k} = {v}</div>
              ))}
            </div>
          ) : (
            <div style={mono}>not found</div>
          )}

          <h3 style={h3}>DMARC</h3>
          <p>DMARC : {result.dmarc ? "OK" : "NG"}</p>
          <p>Policy : {result.dmarcPolicy}</p>
          <div style={mono}>{result.dmarcRecord || "not found"}</div>

          <h4 style={{ marginTop: 12 }}>DMARC rua / ruf</h4>
          <div style={mono}>
            rua: {result.rua?.length ? result.rua.join(", ") : "not found"}
            {"\n"}
            ruf: {result.ruf?.length ? result.ruf.join(", ") : "not found"}
          </div>

          <h4 style={{ marginTop: 12 }}>DMARC Alignment</h4>
          <p>SPF Aligned : {result.dmarcAlignment?.spfAligned ? "YES" : "NO"}</p>
          <p>DKIM Aligned : {result.dmarcAlignment?.dkimAligned ? "YES" : "NO"}</p>
          <p>Overall : {result.dmarcAlignment?.overall ? "PASS" : "FAIL"}</p>
          <div style={mono}>{result.dmarcAlignment?.note || ""}</div>

          <h3 style={h3}>MX</h3>
          <p>MX : {result.mx ? "OK" : "NG"}</p>
          <p>MX Found On : {result.mxFoundOn || "not found"}</p>
          {result.mxHosts?.length > 0 ? (
            <div style={mono}>
              {result.mxHosts.map((mx, idx) => (
                <div key={`${mx.exchange}-${idx}`}>
                  priority={mx.priority} exchange={mx.exchange}
                </div>
              ))}
            </div>
          ) : (
            <div style={mono}>not found</div>
          )}

          <h4 style={{ marginTop: 12 }}>MX → IP → RBL</h4>
          {result.mxResolved?.length > 0 ? (
            <div style={mono}>
              {result.mxResolved.map((mx, idx) => (
                <div key={`${mx.exchange}-${idx}`} style={{ marginBottom: 12 }}>
                  <div><strong>{mx.exchange}</strong> (priority={mx.priority})</div>
                  <div>IPv4: {mx.ipv4?.join(", ") || "-"}</div>
                  <div>IPv6: {mx.ipv6?.join(", ") || "-"}</div>
                  <div>RBL listed: {mx.rbl?.listed ? "YES" : "NO"}</div>
                  {mx.rbl?.results?.map((r, i) => (
                    <div key={i}>
                      - {r.ip || ""} {r.zone || ""} {r.listed ? `LISTED ${r.response || ""}` : "OK"}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          ) : (
            <div style={mono}>not found</div>
          )}

          <h3 style={h3}>BIMI</h3>
          <p>BIMI : {result.bimi ? "OK" : "NG"}</p>
          <div style={mono}>{result.bimiRecord || "not found"}</div>

          <h3 style={h3}>TLS-RPT</h3>
          <p>TLS-RPT : {result.tlsRpt ? "OK" : "NG"}</p>
          <div style={mono}>{result.tlsRptRecord || "not found"}</div>

          <h3 style={h3}>MTA-STS</h3>
          <p>MTA-STS DNS : {result.mtaSts ? "OK" : "NG"}</p>
          <div style={mono}>{result.mtaStsRecord || "not found"}</div>
          <p style={{ marginTop: 8 }}><strong>Policy URL</strong></p>
          <div style={mono}>{result.mtaStsPolicyUrl}</div>

          <h4 style={{ marginTop: 12 }}>MTA-STS Policy Fetch</h4>
          <div style={mono}>
            fetched: {result.mtaStsPolicy?.fetched ? "yes" : "no"}
            {"\n"}
            ok: {result.mtaStsPolicy?.ok ? "yes" : "no"}
            {"\n"}
            status: {result.mtaStsPolicy?.status}
            {"\n\n"}
            {result.mtaStsPolicy?.body || result.mtaStsPolicy?.error || "not fetched"}
          </div>

          <h3 style={h3}>SMTP TLS Handshake</h3>
          <p>Checked : {result.smtpTls?.checked ? "YES" : "NO"}</p>
          <p>Supported : {result.smtpTls?.supported ? "YES" : "NO"}</p>
          <p>Mode : {result.smtpTls?.mode}</p>
          <div style={mono}>{result.smtpTls?.note}</div>

          <h4 style={{ marginTop: 12 }}>SMTP TLS Probe Detail</h4>
          <div style={mono}>
            {result.smtpTls?.probes?.length
              ? result.smtpTls.probes.map((p, i) =>
                  `[${i + 1}] host=${p.host} port=${p.port} ok=${p.ok} protocol=${p.protocol || "-"} error=${p.error || "-"}`
                ).join("\n")
              : "no probe detail"}
          </div>

          <h3 style={h3}>Security</h3>
          <p>Blacklist : {result.blacklist ? "LISTED" : "CLEAR"}</p>

          <h4 style={{ marginTop: 12 }}>Security Notes</h4>
          <div style={mono}>
            {result.securityNotes?.length
              ? result.securityNotes.map(n => `- ${n}`).join("\n")
              : "no major issues"}
          </div>

          <h4 style={{ marginTop: 12 }}>Deliverability Reasons</h4>
          <div style={mono}>
            {result.deliverabilityReasons?.length
              ? result.deliverabilityReasons.map(n => `- ${n}`).join("\n")
              : "no major issues"}
          </div>
        </div>
      )}
    </div>
  )
}
