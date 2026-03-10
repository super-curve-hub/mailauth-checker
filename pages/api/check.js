import dns from "dns/promises"

export default async function handler(req,res){

const {domain} = req.body

let spf=false
let dmarc=false
let dkim=false
let mx=false

try{

const txt = await dns.resolveTxt(domain)

txt.forEach(r=>{
if(r.join("").includes("v=spf1")) spf=true
})

}catch{}

try{

const txt = await dns.resolveTxt("_dmarc."+domain)

txt.forEach(r=>{
if(r.join("").includes("v=DMARC1")) dmarc=true
})

}catch{}

try{

await dns.resolveTxt("selector1._domainkey."+domain)

dkim=true

}catch{}

try{

await dns.resolveMx(domain)

mx=true

}catch{}

res.json({spf,dkim,dmarc,mx})

}
