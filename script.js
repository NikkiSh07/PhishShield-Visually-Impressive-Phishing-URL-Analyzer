const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const resultEl = document.getElementById('result');
const emptyResult = document.getElementById('emptyResult');
const scoreValue = document.getElementById('scoreValue');
const gaugeProgress = document.getElementById('gaugeProgress');
const riskLabel = document.getElementById('riskLabel');
const riskDesc = document.getElementById('riskDesc');
const reasonsList = document.getElementById('reasonsList');
const signalCount = document.getElementById('signalCount');
const breakdownGrid = document.getElementById('breakdownGrid');
const metaDomain = document.getElementById('metaDomain');
const metaTime = document.getElementById('metaTime');
const verdictBox = document.getElementById('verdictBox');
const BACKEND_URL = 'http://localhost:8000';
let backendAvailable = null; // null=unknown, true/false

async function checkBackend(){
  try{
    const r=await fetch(`${BACKEND_URL}/api/health`, {signal: AbortSignal.timeout(1500)});
    backendAvailable=r.ok;
  }catch{ backendAvailable=false; }
  const dot=document.querySelector('.dot');
  const statusText=document.querySelector('.shield-status');
  if(statusText){
    if(backendAvailable) { statusText.innerHTML='<span class="dot" style="background:#00E676;box-shadow:0 0 8px #00E676"></span> Backend Connected'; statusText.style.borderColor='rgba(0,230,118,0.3)'; }
    else if(backendAvailable===false) { statusText.innerHTML='<span class="dot" style="background:#8B949E;box-shadow:none"></span> Offline Mode (local)'; statusText.title='Backend not reachable — using local heuristics + WHOIS heuristic'; }
  }
}
checkBackend();
setInterval(checkBackend, 10000);

// Heuristics config
const SUSPICIOUS_TLDS = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work','.date','.party','.click','.country','.stream','.download','.review'];
const SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly','shorturl.at','tiny.cc','rebrand.ly','cutt.ly'];
const LOGIN_KEYWORDS = ['login','signin','sign-in','verify','verification','account','secure','banking','update','confirm','webscr','session','authenticate','password','credential'];
const POPULAR_DOMAINS = ['google','facebook','apple','paypal','amazon','microsoft','netflix','instagram','twitter','linkedin','github','yahoo','whatsapp','tiktok','adobe'];
const KNOWN_SAFE_TLDS = ['.com','.org','.net','.edu','.gov','.io','.co'];

function levenshtein(a,b){
  const m=a.length,n=b.length;
  const dp=Array.from({length:m+1},()=>Array(n+1).fill(0));
  for(let i=0;i<=m;i++)dp[i][0]=i;
  for(let j=0;j<=n;j++)dp[0][j]=j;
  for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)dp[i][j]=Math.min(dp[i-1][j]+1,dp[i][j-1]+1,dp[i-1][j-1]+(a[i-1]!==b[j-1]?1:0));
  return dp[m][n];
}

function getHostname(raw){
  try{
    let u = raw.trim();
    if(!/^https?:\/\//i.test(u)) u='http://'+u;
    return new URL(u);
  }catch{ return null; }
}

function analyze(urlRaw){
  const reasons=[];
  const breakdown=[];
  let score=0;

  let raw=urlRaw.trim();
  if(!raw) return null;
  if(!/^https?:\/\//i.test(raw)) raw='http://'+raw;
  let parsed;
  try{ parsed=new URL(raw); }catch{
    return {error:'Invalid URL format', score: 50, reasons:[{icon:'!',text:'Invalid URL structure — could not parse',points:0,type:'triggered'}]};
  }

  const hostname=parsed.hostname.toLowerCase();
  const pathname=(parsed.pathname+parsed.search).toLowerCase();
  const full=parsed.href.toLowerCase();
  const protocol=parsed.protocol;

  function addBreakdown(name, pts, maxPts){
    breakdown.push({name, pts, max: maxPts});
  }
  function addReason(text, points, type, icon){
    reasons.push({text, points, type, icon});
    if(type==='triggered') score+=points;
  }

  // 1. Protocol
  if(protocol==='http:'){
    addReason('<strong>Unencrypted HTTP</strong> — no TLS, credentials can be intercepted',10,'triggered','!');
    addBreakdown('Transport Security',10,10);
  } else {
    addReason('<strong>HTTPS enabled</strong> — encrypted transport',0,'safe','✓');
    addBreakdown('Transport Security',0,10);
  }

  // 2. IP address
  const isIP=/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || /^\[?[a-f0-9:]+\]?$/i.test(hostname) && hostname.includes(':');
  if(isIP){
    addReason('<strong>IP address as hostname</strong> — legitimate sites use domain names',25,'triggered','✕');
    addBreakdown('Host Identity',25,25);
  } else {
    addReason('<strong>Domain-based host</strong> — not a raw IP',0,'safe','✓');
    addBreakdown('Host Identity',0,25);
  }

  // 3. @ symbol
  if(raw.includes('@')){
    addReason('<strong>“@” in URL</strong> — can mask true destination (user@host trick)',18,'triggered','✕');
    addBreakdown('URL Obfuscation',18,30);
  } else {
    // will combine with other obfuscation checks later, but start neutral
    addBreakdown('URL Obfuscation',0,30);
  }

  // 4. Punycode
  if(hostname.includes('xn--')){
    addReason('<strong>Punycode / IDN homograph</strong> — possible visual spoofing (e.g., xn--pple-43d)',25,'triggered','✕');
    score+=0; // already added via addReason? punycode reason adds 25; need to avoid double
    // correction: addReason already added 25
    const b=breakdown.find(x=>x.name==='URL Obfuscation'); b.pts+=25;
  } else {
    addReason('<strong>No punycode</strong> — no IDN homograph detected',0,'safe','✓');
  }

  // 5. URL length
  if(raw.length>150){
    addReason(`<strong>Abnormal URL length (${raw.length} chars)</strong> — often hides malicious payload`,15,'triggered','!');
    breakdown.find(x=>x.name==='URL Obfuscation').pts+=15;
  } else if(raw.length>75){
    addReason(`<strong>Long URL (${raw.length} chars)</strong> — slightly abnormal`,7,'triggered','!');
    breakdown.find(x=>x.name==='URL Obfuscation').pts+=7;
  } else {
    addReason(`<strong>Normal URL length</strong> (${raw.length} chars)`,0,'safe','✓');
  }

  // 6. Subdomains / dots
  const dotCount=(hostname.match(/\./g)||[]).length;
  if(dotCount>=4){
    addReason(`<strong>Excessive subdomains (${dotCount} dots)</strong> — e.g., secure.login.example.com.evil.tk`,15,'triggered','!');
    addBreakdown('Subdomain Depth',15,15);
  } else if(dotCount===3){
    addReason(`<strong>Multiple subdomains</strong> (${dotCount} dots) — check carefully`,6,'triggered','!');
    addBreakdown('Subdomain Depth',6,15);
  } else {
    addReason('<strong>Normal subdomain depth</strong>',0,'safe','✓');
    addBreakdown('Subdomain Depth',0,15);
  }

  // 7. Hyphen in domain
  if(hostname.includes('-')){
    const hyphens=(hostname.match(/-/g)||[]).length;
    const pts=hyphens>=2?12:8;
    addReason(`<strong>Hyphens in domain (${hyphens})</strong> — rare for legitimate brands, common in phishing`,pts,'triggered','!');
    addBreakdown('Domain Pattern',pts,25);
  } else {
    addReason('<strong>No hyphens in domain</strong>',0,'safe','✓');
    addBreakdown('Domain Pattern',0,25);
  }

  // 8. Suspicious TLD
  const tld='.'+hostname.split('.').pop();
  if(SUSPICIOUS_TLDS.includes(tld)){
    addReason(`<strong>Suspicious TLD (${tld})</strong> — frequently abused for free malicious domains`,18,'triggered','✕');
    breakdown.find(x=>x.name==='Domain Pattern').pts+=18;
  } else {
    addReason(`<strong>TLD (${tld})</strong> — not in high-risk list`,0,'safe','✓');
  }

  // 9. Shortener
  if(SHORTENERS.some(d=>hostname.includes(d))){
    addReason('<strong>URL shortener</strong> — hides final destination',20,'triggered','!');
    addBreakdown('Redirection Risk',20,20);
  } else {
    addBreakdown('Redirection Risk',0,20);
    addReason('<strong>No shortener detected</strong>',0,'safe','✓');
  }

  // 10. Login keywords
  const foundKeywords=LOGIN_KEYWORDS.filter(k=>full.includes(k));
  if(foundKeywords.length){
    const pts=Math.min(15, 8+foundKeywords.length*3);
    addReason(`<strong>Login-related keywords</strong> — ${foundKeywords.slice(0,4).join(', ')}`,pts,'triggered','!');
    addBreakdown('Keyword Trap',pts,15);
  } else {
    addReason('<strong>No login bait keywords</strong>',0,'safe','✓');
    addBreakdown('Keyword Trap',0,15);
  }

  // 11. Typosquat
  let typosquat=null;
  const domainPart=hostname.split('.')[0];
  for(const pop of POPULAR_DOMAINS){
    const d=levenshtein(domainPart, pop);
    if(d<=2 && domainPart!==pop){
      typosquat=pop;
      break;
    }
    if(full.includes(pop) && !hostname.endsWith(pop+'.com') && !hostname.endsWith(pop+'.net') && hostname!==pop+'.com'){
      // e.g., amazon.com-signin.suspicious.ga contains amazon but not legitimate
      if(hostname.includes(pop)){
        // check if it's subdomain trick: paypal.com.evil.tk -> contains paypal but not at end
        const base=hostname.split('.').slice(-2).join('.');
        if(base!==pop+'.com' && base!==pop+'.net'){
          typosquat=pop;
          break;
        }
      }
    }
  }
  if(typosquat){
    addReason(`<strong>Possible typosquat of ${typosquat}</strong> — domain closely resembles a popular brand`,22,'triggered','✕');
    addBreakdown('Brand Impersonation',22,25);
  } else {
    // second check: hyphenated brand
    const hyphenBrand=POPULAR_DOMAINS.find(p=>hostname.includes(p+'-')||hostname.includes('-'+p));
    if(hyphenBrand){
      addReason(`<strong>Brand + hyphen combo (${hyphenBrand})</strong> — e.g., paypal-secure-login`,14,'triggered','!');
      addBreakdown('Brand Impersonation',14,25);
    } else {
      addReason('<strong>No typosquat detected</strong>',0,'safe','✓');
      addBreakdown('Brand Impersonation',0,25);
    }
  }

  // 12. Excessive encoding / %
  const pctCount=(raw.match(/%/g)||[]).length;
  if(pctCount>=5){
    addReason(`<strong>Heavy URL encoding (${pctCount} % sequences)</strong> — may hide payload`,12,'triggered','!');
    breakdown.find(x=>x.name==='URL Obfuscation').pts+=12;
  } else if(pctCount>=2){
    addReason(`<strong>Encoded characters</strong> (${pctCount} % sequences)`,5,'triggered','!');
    breakdown.find(x=>x.name==='URL Obfuscation').pts+=5;
  } else {
    addReason('<strong>No suspicious encoding</strong>',0,'neutral','—');
  }

  // 13. Port
  if(parsed.port && parsed.port!=='80' && parsed.port!=='443'){
    addReason(`<strong>Non-standard port :${parsed.port}</strong> — uncommon for public sites`,10,'triggered','!');
    addBreakdown('Network Anomaly',10,10);
  } else {
    addBreakdown('Network Anomaly',0,10);
    addReason('<strong>Standard port</strong>',0,'neutral','—');
  }

  // 14. Recently registered heuristic (simulate)
  // Heuristic: many numbers or hyphens or long random string => likely young
  const hasNumbers=/\d/.test(hostname);
  const entropySim=hostname.length>20 || (hasNumbers && hostname.includes('-'));
  if(entropySim){
    addReason('<strong>Recently registered pattern</strong> — domain looks algorithmically generated / young',10,'triggered','!');
    addBreakdown('Domain Age Heuristic',10,15);
  } else {
    addReason('<strong>Domain age pattern normal</strong> (heuristic)',0,'safe','✓');
    addBreakdown('Domain Age Heuristic',0,15);
  }

  // 15. Path depth / abnormal structure
  const pathDepth=parsed.pathname.split('/').filter(Boolean).length;
  const hasQuery=parsed.search.length>0;
  if(pathDepth>=4 || (hasQuery && raw.length>80)){
    addReason('<strong>Abnormal URL structure</strong> — deep path / complex query',8,'triggered','!');
    addBreakdown('Structure Anomaly',8,10);
  } else {
    addReason('<strong>Normal URL structure</strong>',0,'safe','✓');
    addBreakdown('Structure Anomaly',8>0?0:0,10); // placeholder
    // fix breakdown for structure
    const idx=breakdown.findIndex(x=>x.name==='Structure Anomaly');
    if(!breakdown[idx] || breakdown[idx].name!=='Structure Anomaly'){
      // ensure it exists
    } else {
      // if not triggered, pts stays 0
    }
  }
  // ensure Structure Anomaly breakdown exists
  if(!breakdown.find(x=>x.name==='Structure Anomaly')){
    addBreakdown('Structure Anomaly',0,10);
  }

  score=Math.max(0,Math.min(100, score));
  // Clamp breakdown pts to max
  breakdown.forEach(b=>{ if(b.pts>b.max) b.pts=b.max; });

  // Determine level
  let level, desc, color;
  if(score>=70){ level='HIGH RISK'; desc='Strong phishing indicators. Do not enter credentials. Block and report.'; color='#FF3B30';}
  else if(score>=35){ level='MEDIUM RISK'; desc='Suspicious patterns detected. Verify sender and domain before proceeding.'; color='#FFAB00';}
  else { level='LOW RISK'; desc='No significant threats detected. Still verify the sender before entering credentials.'; color='#00E676';}

  return {score, level, desc, color, reasons, breakdown, hostname, parsed, raw};
}

function render(result){
  if(!result) return;
  if(result.error){
    resultEl.classList.remove('hidden'); emptyResult.style.display='none';
    scoreValue.textContent='—'; gaugeProgress.style.stroke='#FFAB00';
    riskLabel.textContent='INVALID'; riskLabel.className='gauge-risk risk-medium';
    riskDesc.textContent=result.error; return;
  }
  resultEl.classList.remove('hidden');
  emptyResult.style.display='none';

  // animate gauge
  const circumference=2*Math.PI*70;
  const offset=circumference - (result.score/100)*circumference;
  gaugeProgress.style.transition='none';
  gaugeProgress.style.strokeDashoffset=circumference;
  gaugeProgress.style.stroke=result.color;
  // force reflow
  void gaugeProgress.getBoundingClientRect();
  gaugeProgress.style.transition='stroke-dashoffset 1s cubic-bezier(0.34,1.56,0.64,1), stroke 0.3s';
  gaugeProgress.style.strokeDashoffset=offset;

  // count up
  let cur=0;
  const target=result.score;
  const step=Math.max(1, Math.ceil(target/30));
  clearInterval(render._timer);
  render._timer=setInterval(()=>{
    cur=Math.min(target, cur+step);
    scoreValue.textContent=cur;
    scoreValue.style.color=result.color;
    if(cur>=target) clearInterval(render._timer);
  }, 18);

  riskLabel.textContent=result.level;
  riskLabel.className='gauge-risk '+(result.score>=70?'risk-high':result.score>=35?'risk-medium':'risk-low');
  riskDesc.textContent=result.desc;
  metaDomain.textContent='◉ '+result.hostname;
  metaTime.textContent=new Date().toLocaleTimeString();

  const triggered=result.reasons.filter(r=>r.type==='triggered').length;
  signalCount.textContent=`${triggered}/${result.reasons.length} signals`;

  reasonsList.innerHTML=result.reasons.map(r=>`
    <li class="${r.type}">
      <span class="reason-icon">${r.icon}</span>
      <span class="reason-text">${r.text}</span>
      ${r.points?`<span class="reason-points">+${r.points}</span>`:''}
    </li>
  `).join('');

  breakdownGrid.innerHTML=result.breakdown.map(b=>{
    const pct=b.max? (b.pts/b.max*100):0;
    const col=b.pts===0?'#00E676': b.pts/b.max>=0.6?'#FF3B30':'#FFAB00';
    return `<div class="breakdown-item">
      <div class="breakdown-item-head"><span>${b.name}</span><span class="badge-points" style="background:${col}22;color:${col};border:1px solid ${col}33">${b.pts}/${b.max}</span></div>
      <div class="breakdown-bar"><div class="breakdown-fill" style="width:${pct}%;background:${col}"></div></div>
    </div>`;
  }).join('');

  if(result.score>=70){
    verdictBox.className='verdict danger';
    verdictBox.textContent='⛔ HIGH RISK — Do not visit. Close the tab and report the link. If you clicked, change passwords immediately.';
  } else if(result.score>=35){
    verdictBox.className='verdict warn';
    verdictBox.textContent='⚠️ MEDIUM RISK — Suspicious. Verify the domain letter-by-letter and confirm via official site before logging in.';
  } else {
    verdictBox.className='verdict safe';
    verdictBox.textContent='✓ LOW RISK — No strong phishing signals. Still verify the sender and avoid entering sensitive data from email links.';
  }
}

async function doAnalyze(){
  const val=urlInput.value.trim();
  if(!val){
    urlInput.focus();
    urlInput.parentElement.style.borderColor='#FF3B30';
    setTimeout(()=>urlInput.parentElement.style.borderColor='',1200);
    return;
  }
  analyzeBtn.innerHTML='<span>Analyzing…</span>';
  analyzeBtn.disabled=true;

  // Try backend first if available (or unknown on first run)
  if(backendAvailable!==false){
    try{
      const controller=new AbortController();
      const t=setTimeout(()=>controller.abort(), 2500);
      const resp=await fetch(`${BACKEND_URL}/api/analyze`,{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({url: val}),
        signal: controller.signal
      });
      clearTimeout(t);
      if(resp.ok){
        const data=await resp.json();
        // adapt backend reason text already HTML
        render(data);
        backendAvailable=true;
        analyzeBtn.innerHTML='<span>Analyze</span><span class="btn-arrow">→</span>';
        analyzeBtn.disabled=false;
        return;
      }
    }catch(e){
      // fallback to local
      backendAvailable=false;
    }
  }
  // Local fallback with slight delay for UX
  setTimeout(()=>{
    const res=analyze(val);
    render(res);
    analyzeBtn.innerHTML='<span>Analyze</span><span class="btn-arrow">→</span>';
    analyzeBtn.disabled=false;
  }, 420);
}

analyzeBtn.addEventListener('click', doAnalyze);
urlInput.addEventListener('keydown', e=>{ if(e.key==='Enter') doAnalyze(); });
urlInput.addEventListener('input', ()=>{
  clearBtn.classList.toggle('visible', urlInput.value.length>0);
  if(urlInput.value.length===0){
    resultEl.classList.add('hidden');
    emptyResult.style.display='';
  }
});
clearBtn.addEventListener('click', ()=>{
  urlInput.value=''; clearBtn.classList.remove('visible');
  resultEl.classList.add('hidden'); emptyResult.style.display=''; urlInput.focus();
});
document.querySelectorAll('.chip').forEach(c=>{
  c.addEventListener('click', ()=>{
    urlInput.value=c.dataset.url;
    clearBtn.classList.add('visible');
    doAnalyze();
  });
});
document.getElementById('copyBtn').addEventListener('click', ()=>{
  const res=analyze(urlInput.value);
  if(!res) return;
  const txt=`PhishShield Report — ${res.hostname}\nRisk Score: ${res.score}/100 (${res.level})\n${res.desc}\n\nSignals:\n${res.reasons.filter(r=>r.type==='triggered').map(r=>'- '+r.text.replace(/<[^>]*>/g,'')).join('\n') || '- No triggers'}\n\nAnalyzed: ${new Date().toLocaleString()}`;
  navigator.clipboard.writeText(txt).then(()=>{
    const b=document.getElementById('copyBtn');
    const old=b.textContent; b.textContent='Copied!'; setTimeout(()=>b.textContent=old,1500);
  });
});

// demo load
urlInput.value='https://example.com/login';
