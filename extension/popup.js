// PhishShield Popup - standalone heuristics (same as frontend) + optional backend
const SUSPICIOUS_TLDS=['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work','.date','.party','.click','.country','.stream','.download','.review'];
const SHORTENERS=['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly','shorturl.at','tiny.cc','rebrand.ly','cutt.ly'];
const LOGIN_KW=['login','signin','sign-in','verify','verification','account','secure','banking','update','confirm','webscr','session','authenticate','password','credential'];
const POPULAR=['google','facebook','apple','paypal','amazon','microsoft','netflix','instagram','twitter','linkedin','github','yahoo','whatsapp','tiktok','adobe'];
function lev(a,b){const m=a.length,n=b.length,dp=Array.from({length:m+1},()=>Array(n+1).fill(0));for(let i=0;i<=m;i++)dp[i][0]=i;for(let j=0;j<=n;j++)dp[0][j]=j;for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)dp[i][j]=Math.min(dp[i-1][j]+1,dp[i][j-1]+1,dp[i-1][j-1]+(a[i-1]!==b[j-1]?1:0));return dp[m][n];}

function analyze(rawInput){
  let raw=rawInput.trim(); if(!raw) return null; if(!/^https?:\/\//i.test(raw)) raw='http://'+raw;
  let p; try{p=new URL(raw);}catch{return {score:50,level:'INVALID',desc:'Invalid URL',reasons:[{text:'Invalid URL',type:'triggered',icon:'!'}]}};
  const host=p.hostname.toLowerCase(), full=p.href.toLowerCase();
  let score=0; const reasons=[];
  const add=(text,pts,type,icon)=>{reasons.push({text,pts,type,icon}); if(type==='triggered') score+=pts;};
  if(p.protocol==='http:') add('<strong>Unencrypted HTTP</strong>',10,'triggered','!'); else add('<strong>HTTPS</strong>',0,'safe','✓');
  const isIP=/^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if(isIP) add('<strong>IP as host</strong>',25,'triggered','✕'); else add('<strong>Domain host</strong>',0,'safe','✓');
  if(raw.includes('@')) add('<strong>“@” trick</strong>',18,'triggered','✕');
  if(host.includes('xn--')) add('<strong>Punycode</strong>',25,'triggered','✕'); else add('<strong>No punycode</strong>',0,'safe','✓');
  if(raw.length>150) add(`<strong>Long URL (${raw.length})</strong>`,15,'triggered','!'); else if(raw.length>75) add(`<strong>Long URL (${raw.length})</strong>`,7,'triggered','!'); else add('<strong>Normal length</strong>',0,'safe','✓');
  if((host.match(/\./g)||[]).length>=4) add('<strong>Excessive subdomains</strong>',15,'triggered','!'); else add('<strong>Normal subdomains</strong>',0,'safe','✓');
  if(host.includes('-')) add(`<strong>Hyphens (${(host.match(/-/g)||[]).length})</strong>`,host.split('-').length>2?12:8,'triggered','!'); else add('<strong>No hyphens</strong>',0,'safe','✓');
  const tld='.'+host.split('.').pop();
  if(SUSPICIOUS_TLDS.includes(tld)) add(`<strong>Suspicious TLD (${tld})</strong>`,18,'triggered','✕'); else add(`<strong>TLD ${tld}</strong>`,0,'safe','✓');
  if(SHORTENERS.some(s=>host.includes(s))) add('<strong>URL shortener</strong>',20,'triggered','!'); else add('<strong>No shortener</strong>',0,'safe','✓');
  const found=LOGIN_KW.filter(k=>full.includes(k));
  if(found.length) add(`<strong>Login keywords: ${found.slice(0,3).join(', ')}</strong>`,Math.min(15,8+found.length*3),'triggered','!'); else add('<strong>No login keywords</strong>',0,'safe','✓');
  let typo=null; const part=host.split('.')[0];
  for(const pop of POPULAR){ if(lev(part,pop)<=2 && part!==pop){typo=pop;break;} if(host.includes(pop) && !host.endsWith(pop+'.com')){const base=host.split('.').slice(-2).join('.'); if(base!==pop+'.com'){typo=pop;break;}}}
  if(typo) add(`<strong>Typosquat ${typo}</strong>`,22,'triggered','✕'); else {
    const hb=POPULAR.find(p=>host.includes(p+'-')||host.includes('-'+p));
    if(hb) add(`<strong>Brand+hyphen ${hb}</strong>`,14,'triggered','!'); else add('<strong>No typosquat</strong>',0,'safe','✓');
  }
  if((raw.match(/%/g)||[]).length>=5) add('<strong>Heavy encoding</strong>',12,'triggered','!'); else add('<strong>No encoding trick</strong>',0,'safe','✓');
  if(p.port && !['80','443'].includes(p.port)) add(`<strong>Port :${p.port}</strong>`,10,'triggered','!');
  const hasNum=/\d/.test(host), young=host.length>20||(hasNum&&host.includes('-'));
  if(young) add('<strong>Young domain pattern</strong>',10,'triggered','!');
  const depth=p.pathname.split('/').filter(Boolean).length;
  if(depth>=4) add('<strong>Deep path</strong>',8,'triggered','!');
  score=Math.max(0,Math.min(100,score));
  let level,desc; if(score>=70){level='HIGH RISK';desc='Do not enter credentials.';} else if(score>=35){level='MEDIUM RISK';desc='Verify domain carefully.';} else {level='LOW RISK';desc='No strong signals.';}
  return {score,level,desc,reasons,host,raw};
}

const $=id=>document.getElementById(id);
function render(r){
  if(!r) return;
  const g=$('gauge'); g.textContent=r.score;
  g.className='gauge '+(r.score>=70?'high':r.score>=35?'med':'low');
  $('scoreText').textContent=r.score+' / 100 — '+r.level;
  $('descText').textContent=r.desc;
  $('riskBadge').textContent=r.level;
  $('riskBadge').style.background=r.score>=70?'rgba(255,59,48,0.12)':r.score>=35?'rgba(255,171,0,0.12)':'rgba(0,230,118,0.12)';
  $('riskBadge').style.color=r.score>=70?'#FF3B30':r.score>=35?'#FFAB00':'#00E676';
  $('riskBadge').style.borderColor=r.score>=70?'rgba(255,59,48,0.2)':r.score>=35?'rgba(255,171,0,0.2)':'rgba(0,230,118,0.2)';
  const trig=r.reasons.filter(x=>x.type==='triggered').length;
  $('signalCount').textContent=trig+'/'+r.reasons.length;
  $('reasonsList').innerHTML=r.reasons.map(x=>`<li class="${x.type}"><span class="dot">${x.icon}</span><span>${x.text}</span>${x.pts?`<span style="margin-left:auto;font-family:monospace;font-size:10px;opacity:0.7">+${x.pts}</span>`:''}</li>`).join('');
  $('currentUrl').textContent='◉ '+r.host;
}

// try to get active tab URL
try{
  if(chrome && chrome.tabs){
    chrome.tabs.query({active:true,currentWindow:true}, tabs=>{
      if(tabs && tabs[0] && tabs[0].url){
        $('currentUrl').textContent=tabs[0].url;
        $('urlInput').value=tabs[0].url;
        const r=analyze(tabs[0].url); render(r);
      }
    });
  }
}catch(e){}

$('analyzeBtn').addEventListener('click', ()=>{
  const v=$('urlInput').value.trim()||$('currentUrl').textContent;
  // try backend first
  fetch('http://localhost:8000/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:v})})
    .then(r=>r.ok?r.json():Promise.reject())
    .then(data=>{ render({score:data.score,level:data.level,desc:data.desc,reasons:data.reasons,host:data.hostname}); })
    .catch(()=>{ const r=analyze(v); render(r); });
});
$('urlInput').addEventListener('keydown',e=>{if(e.key==='Enter') $('analyzeBtn').click();});
$('fullReport').addEventListener('click',e=>{
  e.preventDefault();
  if(chrome && chrome.tabs) chrome.tabs.create({url: chrome.runtime.getURL('popup.html')});
  else window.open('../index.html','_blank');
});
