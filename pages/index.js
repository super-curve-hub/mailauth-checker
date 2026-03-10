import { useState } from "react"

export default function Home() {

  const [domain,setDomain] = useState("")
  const [result,setResult] = useState(null)
  const [loading,setLoading] = useState(false)

  async function check(){

    setLoading(true)

    const res = await fetch("/api/check",{
      method:"POST",
      headers:{
        "Content-Type":"application/json"
      },
      body:JSON.stringify({domain})
    })

    const data = await res.json()

    setResult(data)
    setLoading(false)
  }

  return (

    <div style={{fontFamily:"sans-serif",padding:40,maxWidth:700}}>

      <h1>MailAuth DNS Checker</h1>

      <div style={{marginTop:20}}>

        <input
          placeholder="example.com"
          value={domain}
          onChange={(e)=>setDomain(e.target.value)}
          style={{
            padding:10,
            fontSize:18,
            width:250
          }}
        />

        <button
          onClick={check}
          style={{
            marginLeft:10,
            padding:"10px 20px",
            fontSize:16
          }}
        >
          Check
        </button>

      </div>

      {loading && (
        <p style={{marginTop:20}}>Checking DNS...</p>
      )}

      {result && (

        <div style={{
          marginTop:30,
          padding:20,
          border:"1px solid #ddd",
          borderRadius:8
        }}>

          <h2>Result</h2>

          <p>SPF : {result.spf ? "OK":"NG"}</p>
          <p>SPF Lookups : {result.spfLookups}</p>

          <p>DKIM : {result.dkim ? "OK":"NG"}</p>
          <p>DKIM Selector : {result.dkimSelector || "not found"}</p>

          <p>DMARC : {result.dmarc ? "OK":"NG"}</p>
          <p>DMARC Policy : {result.dmarcPolicy}</p>

          <p>MX : {result.mx ? "OK":"NG"}</p>

          <hr/>

          <h3>Mailbox Provider Check</h3>

          <p>Gmail : {result.gmailPass ? "PASS":"FAIL"}</p>
          <p>Outlook : {result.outlookPass ? "PASS":"FAIL"}</p>

          <hr/>

          <h3>Security</h3>

          <p>Blacklist : {result.blacklist ? "LISTED":"OK"}</p>

        </div>

      )}

    </div>

  )

}
