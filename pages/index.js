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

  const boxStyle = {
    marginTop: 30,
    padding: 20,
    border: "1px solid #ddd",
    borderRadius: 8
  }

  const sectionTitle = {
    marginTop: 24,
    marginBottom: 12
  }

  const mono = {
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    wordBreak: "break-all",
    background: "#f7f7f7",
    padding: 10,
    borderRadius: 6
  }

  return (
    <div style={{ fontFamily: "sans-serif", padding: 24, maxWidth: 900, margin: "0 auto" }}>
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
        <div style={boxStyle}>
          <h2>Result</h2>

          <p><strong>Domain:</strong> {result.domain}</p>
          <p><strong>Root Domain:</strong> {result.rootDomain}</p>

          <h3 style={sectionTitle}>SPF</h3>
          <p>SPF : {result.spf ? "OK" : "NG"}</p>
          <p>SPF Lookups : {result.spfLookups}</p>
          <p>SPF 10+ Warning : {result.spfLookupWarning ? "WARNING" : "OK"}</p>
          <div style={mono}>{result.spfRecord || "not found"}</div>

          <h3 style={sectionTitle}>DKIM</h3>
          <p>DKIM : {result.dkim ? "OK" : "NG"}</p>
          <p>DKIM Selector : {result.dkimSelector || "not found"}</p>
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

          <h3 style={sectionTitle}>DMARC</h3>
          <p>DMARC : {result.dmarc ? "OK" : "NG"}</p>
          <p>DMARC Policy : {result.dmarcPolicy}</p>
          <div style={mono}>{result.dmarcRecord || "not found"}</div>

          <h4 style={{ marginTop: 12 }}>DMARC Alignment</h4>
          <p>SPF Aligned : {result.dmarcAlignment?.spfAligned ? "YES" : "NO"}</p>
          <p>DKIM Aligned : {result.dmarcAlignment?.dkimAligned ? "YES" : "NO"}</p>
          <p>Overall : {result.dmarcAlignment?.overall ? "PASS" : "FAIL"}</p>
          <div style={mono}>{result.dmarcAlignment?.note || ""}</div>

          <h3 style={sectionTitle}>MX</h3>
          <p>MX : {result.mx ? "OK" : "NG"}</p>
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

          <h3 style={sectionTitle}>Mailbox Provider Check</h3>
          <p>Gmail : {result.gmailPass ? "PASS" : "FAIL"}</p>
          <p>Outlook : {result.outlookPass ? "PASS" : "FAIL"}</p>

          <h3 style={sectionTitle}>BIMI</h3>
          <p>BIMI : {result.bimi ? "OK" : "NG"}</p>
          <div style={mono}>{result.bimiRecord || "not found"}</div>

          <h3 style={sectionTitle}>TLS-RPT</h3>
          <p>TLS-RPT : {result.tlsRpt ? "OK" : "NG"}</p>
          <div style={mono}>{result.tlsRptRecord || "not found"}</div>

          <h3 style={sectionTitle}>MTA-STS</h3>
          <p>MTA-STS DNS : {result.mtaSts ? "OK" : "NG"}</p>
          <div style={mono}>{result.mtaStsRecord || "not found"}</div>
          <p>MTA-STS Policy URL :</p>
          <div style={mono}>{result.mtaStsPolicyUrl}</div>

          <h3 style={sectionTitle}>Security</h3>
          <p>Blacklist : {result.blacklist ? "LISTED" : "NOT LISTED / NOT CHECKED"}</p>
          <div style={mono}>{result.blacklistNote}</div>
        </div>
      )}
    </div>
  )
}
