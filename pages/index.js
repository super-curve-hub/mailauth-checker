import { useState } from "react"

export default function Home() {

  const [domain,setDomain] = useState("")
  const [result,setResult] = useState(null)

  async function check(){

    const res = await fetch("/api/check",{
      method:"POST",
      headers:{
        "Content-Type":"application/json"
      },
      body:JSON.stringify({domain})
    })

    const data = await res.json()
    setResult(data)
  }

  return (

    <div style={{fontFamily:"sans-serif",padding:40}}>

      <h1>MailAuth DNS Checker</h1>

      <input
        placeholder="example.com"
        value={domain}
        onChange={(e)=>setDomain(e.target.value)}
        style={{padding:10,fontSize:18}}
      />

      <button
        onClick={check}
        style={{marginLeft:10,padding:10}}
      >
        Check
      </button>

      {result && (

        <div style={{marginTop:30}}>

          <p>SPF : {result.spf ? "OK":"NG"}</p>
          <p>DKIM : {result.dkim ? "OK":"NG"}</p>
          <p>DMARC : {result.dmarc ? "OK":"NG"}</p>
          <p>MX : {result.mx ? "OK":"NG"}</p>

        </div>

      )}

    </div>

  )

}
