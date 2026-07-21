"""Control plane for the demo generator.

Exposes a small REST API and a phone-friendly panel so you can trigger
scenarios mid-presentation without alt-tabbing to a terminal.
"""
import logging
import sys

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from .config import cfg
from .engine import engine
from .scenarios import SCENARIOS
from . import webhook

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("main")

if not cfg.API_TOKEN:
    log.error("API_TOKEN is not set. Refusing to start an unauthenticated "
              "control plane on a public host. Set API_TOKEN in .env")
    sys.exit(1)

app = FastAPI(title="Kahu Demo Generator", version="1.0")


def auth(x_demo_token: str = Header(default="")) -> None:
    if x_demo_token != cfg.API_TOKEN:
        raise HTTPException(status_code=401, detail="bad or missing X-Demo-Token")


@app.on_event("startup")
def _startup() -> None:
    log.info("target=%s dry_run=%s intensity=%s",
             cfg.TARGET_HOST, cfg.DRY_RUN, cfg.INTENSITY)
    webhook.start()
    if cfg.AUTOSTART:
        engine.start_baseline()


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/api/status", dependencies=[Depends(auth)])
def status() -> dict:
    return engine.status()


@app.get("/api/scenarios", dependencies=[Depends(auth)])
def scenarios() -> dict:
    return {k: {"title": v["title"], "desc": v["desc"], "duration": v["duration"]}
            for k, v in SCENARIOS.items()}


@app.post("/api/scenarios/{name}/fire", dependencies=[Depends(auth)])
def fire(name: str) -> dict:
    try:
        return engine.fire(name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown scenario: {name}")


@app.post("/api/baseline/start", dependencies=[Depends(auth)])
def baseline_start() -> dict:
    engine.start_baseline()
    return {"baseline": True}


@app.post("/api/baseline/stop", dependencies=[Depends(auth)])
def baseline_stop() -> dict:
    engine.stop_baseline()
    return {"baseline": False}


PANEL = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kahu Demo Control</title>
<style>
 :root{--bg:#0B1622;--card:#152638;--card2:#1C3149;--gold:#E8A33D;
       --teal:#3FB8AF;--text:#F2F6FA;--muted:#8FA3B8;--red:#E05A4E}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);
   font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
   padding:16px;max-width:760px;margin:0 auto}
 h1{font-size:20px;margin:4px 0 2px} .sub{color:var(--muted);font-size:13px;
   margin-bottom:16px}
 .tok{width:100%;padding:12px;border-radius:10px;border:1px solid var(--card2);
   background:var(--card);color:var(--text);font-size:15px;margin-bottom:14px}
 .bar{display:flex;gap:8px;margin-bottom:14px}
 .bar button{flex:1;padding:12px;border:0;border-radius:10px;font-weight:600;
   font-size:14px}
 .on{background:var(--teal);color:var(--bg)} .off{background:var(--card2);
   color:var(--text)}
 .stat{background:var(--card);border-radius:12px;padding:12px 14px;
   margin-bottom:14px;font-size:13px;color:var(--muted)}
 .stat b{color:var(--text)} .stat .k{color:var(--gold)}
 .s{background:var(--card);border-radius:12px;padding:14px;margin-bottom:10px;
   display:flex;align-items:center;gap:12px}
 .s .m{flex:1;min-width:0} .s .t{font-weight:700;font-size:15px}
 .s .d{color:var(--muted);font-size:12.5px;margin-top:2px}
 .s button{background:var(--gold);color:var(--bg);border:0;border-radius:10px;
   padding:12px 16px;font-weight:700;font-size:14px;white-space:nowrap}
 .s button:disabled{background:var(--card2);color:var(--muted)}
 .hist{font-size:12.5px;color:var(--muted);margin-top:4px}
 .hist div{padding:3px 0}
</style></head><body>
<h1>Kahu &mdash; Demo Control</h1>
<div class="sub">Baseline noise plus on-demand scenarios. Keep this on your phone.</div>
<input class="tok" id="tok" type="password" placeholder="Demo token"
  onchange="save()" oninput="save()">
<div class="bar">
  <button class="on" onclick="post('/api/baseline/start')">Baseline ON</button>
  <button class="off" onclick="post('/api/baseline/stop')">Baseline OFF</button>
</div>
<div class="stat" id="stat">Enter token to connect&hellip;</div>
<div id="list"></div>
<script>
const tokEl=document.getElementById('tok');
tokEl.value=localStorage.getItem('kdtok')||'';
function save(){localStorage.setItem('kdtok',tokEl.value);refresh()}
function H(){return{'X-Demo-Token':tokEl.value}}
async function post(u){await fetch(u,{method:'POST',headers:H()});refresh()}
async function fire(n,btn){btn.disabled=true;btn.textContent='Firing';
  await post('/api/scenarios/'+n+'/fire');
  setTimeout(()=>{btn.disabled=false;btn.textContent='Fire'},2500)}
async function refresh(){
  if(!tokEl.value)return;
  try{
    const s=await(await fetch('/api/status',{headers:H()})).json();
    const c=s.sent||{};
    document.getElementById('stat').innerHTML=
      'Baseline <b>'+(s.baseline?'running':'stopped')+'</b> &middot; local <b>'+
      s.local_time+'</b> &middot; activity <b>'+s.activity_factor+'x</b><br>'+
      'target <b>'+s.target+'</b>'+(s.dry_run?' <span class="k">(DRY RUN)</span>':'')+
      '<br>sent &mdash; syslog <span class="k">'+(c.syslog||0)+
      '</span> &middot; netflow <span class="k">'+(c.netflow||0)+
      '</span> &middot; snmp <span class="k">'+(c.snmp||0)+
      '</span> &middot; errors <span class="k">'+(c.errors||0)+'</span>'+
      (s.history&&s.history.length?'<div class="hist">'+s.history.slice(0,4)
        .map(h=>'<div>'+h.at+' &mdash; '+h.title+' ('+h.steps+' events, '+
        h.seconds+'s)</div>').join('')+'</div>':'');
    if(!window._built){
      const sc=await(await fetch('/api/scenarios',{headers:H()})).json();
      document.getElementById('list').innerHTML=Object.entries(sc).map(([k,v])=>
        '<div class="s"><div class="m"><div class="t">'+v.title+'</div>'+
        '<div class="d">'+v.desc+' &middot; '+v.duration+'</div></div>'+
        '<button onclick="fire(\\''+k+'\\',this)">Fire</button></div>').join('');
      window._built=true;
    }
  }catch(e){document.getElementById('stat').textContent='Not connected.'}
}
refresh();setInterval(refresh,3000);
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def panel() -> str:
    return PANEL
