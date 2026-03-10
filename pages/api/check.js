import dns from "dns/promises"

export default async function handler(req, res) {

  let domain = ""

  if (req.method === "POST") {
    domain = req.body?.domain || ""
  }

  if (!domain) {
    res.json({error:"domain required"})
    return
  }

  let spf=false
  let dmarc=false
  let dkim=false
  let mx=false

  let spfLookups=0
  let dmarcPolicy="none"
  let dkimSelector=null

  // --------------------
  // SPF
  // --------------------

  try{

    const txt = await dns.resolveTxt(domain)

    txt.forEach(r=>{

      const record = r.join("")

      if(record.includes("v=spf1")){

        spf=true

        const matches = record.match(/include:/g)

        if(matches){
          spfLookups = matches.length
        }

      }

    })

  }catch(e){}


  // --------------------
  // DMARC
  // --------------------

  try{

    const txt = await dns.resolveTxt("_dmarc."+domain)

    txt.forEach(r=>{

      const record = r.join("")

      if(record.includes("v=DMARC1")){

        dmarc=true

        const p = record.match(/p=([^;]+)/)

        if(p){
          dmarcPolicy=p[1]
        }

      }

    })

  }catch(e){}


  // --------------------
  // DKIM selector search
  // --------------------

  const selectors=[
    "selector1",
    "selector2",
    "google",
    "k1",
    "default"
  ]

  for(const s of selectors){

    try{

      await dns.resolveTxt(s+"._domainkey."+domain)

      dkim=true
      dkimSelector=s
      break

    }catch(e){}

  }


  // --------------------
  // MX
  // --------------------

  try{

    await dns.resolveMx(domain)
    mx=true

  }catch(e){}


  // --------------------
  // Blacklist check
  // --------------------

  let blacklist=false

  try{

    await dns.resolve4("127.0.0.2.zen.spamhaus.org")
    blacklist=true

  }catch(e){}


  // --------------------
  // Gmail / Outlook判定
  // --------------------

  const gmailPass = spf && dkim && dmarc
  const outlookPass = spf && dkim && dmarc


  res.json({

    spf,
    dkim,
    dmarc,
    mx,

    spfLookups,
    dmarcPolicy,
    dkimSelector,

    gmailPass,
    outlookPass,

    blacklist

  })

}
