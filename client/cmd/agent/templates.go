package main
const agentHomeHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="csrf-token" content="{{.CSRFToken}}" />
	<title>Tunnel Agent</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--bg3:#1e2230;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--orange:#d29922;--orangeDim:rgba(210,153,34,.12);--orangeBorder:rgba(210,153,34,.4);--purple:#a371f7;--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--bg3:#e2e4ee;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);--orangeDim:rgba(210,153,34,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);line-height:1.5}
		a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
		code{font-family:var(--mono);font-size:.8em;background:var(--surface);padding:2px 6px;border-radius:4px}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 60px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{font-size:18px;font-weight:700;margin:0}
		.topbar .subtitle{font-size:12px;color:var(--textMuted);margin-top:2px}
		.nav{display:flex;gap:4px}
		.nav a{font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);transition:all .15s;text-decoration:none}
		.nav a:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.statusGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:20px}
		.sCard{padding:12px;border-radius:var(--radiusLg);border:1px solid var(--border);background:var(--surface);text-align:center}
		.sCard .label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted);margin-bottom:4px}
		.sCard .val{font-size:15px;font-weight:600}
		.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
		.pill::before{content:'';width:6px;height:6px;border-radius:50%}
		.pill.ok{color:var(--green);border-color:var(--greenBorder);background:var(--greenDim)}.pill.ok::before{background:var(--green)}
		.pill.bad{color:var(--red);border-color:var(--redBorder);background:var(--redDim)}.pill.bad::before{background:var(--red)}
		.pill.warn{color:var(--orange);border-color:var(--orangeBorder);background:var(--orangeDim)}.pill.warn::before{background:var(--orange)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
		@media(max-width:720px){.grid2{grid-template-columns:1fr}}
		.secHead{margin:20px 0 10px}
		.secHead h2{font-size:14px;font-weight:600;margin:0;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		label{font-size:12px;font-weight:600;display:block;margin:0 0 4px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		.help{font-size:11px;color:var(--textMuted);margin:0 0 6px;line-height:1.4}
		input[type="text"],input:not([type]){width:100%;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:var(--font);font-size:14px;transition:border-color .15s}
		input:focus{outline:none;border-color:var(--accent)}
		.btn{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
		.btn:hover{background:var(--surfaceHover);border-color:var(--borderHover)}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn.warn{background:var(--redDim);border-color:var(--redBorder);color:var(--red)}
		.btn.sm{font-size:12px;padding:5px 10px}
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.muted{color:var(--textMuted)}
		.flash{padding:10px 14px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--greenDim);border:1px solid var(--greenBorder);color:var(--green)}
		.errBox{font-size:12px;padding:8px 10px;margin-top:8px;border-radius:8px;background:var(--redDim);border:1px solid var(--redBorder);color:var(--red);word-break:break-all}
		.routeRow{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)}
		.routeRow:last-child{border-bottom:none}
		.routeRow .rName{font-weight:600;min-width:80px}
		.routeRow .rProto{font-size:11px;padding:2px 6px;border-radius:4px;text-transform:uppercase;font-weight:500}
		.routeRow .rProto.tcp{background:var(--accentDim);color:var(--accent)}
		.routeRow .rProto.udp{background:rgba(163,113,247,.14);color:var(--purple)}
		.routeRow .rAddrs{font-size:12px;color:var(--textMuted)}
		.dkimBox{margin-top:8px;padding:10px;border-radius:10px;background:var(--bg2);border:1px solid var(--border)}
		.dkimTop{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:8px}
		.dkimText{width:100%;min-height:108px;max-width:100%;resize:vertical;padding:10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-family:var(--mono);font-size:11px;line-height:1.45;overflow:auto;white-space:pre-wrap;word-break:break-word}
		.updatePopup{position:fixed;right:16px;bottom:16px;max-width:460px;width:calc(100% - 32px);z-index:1000;display:none;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
		.updatePopup pre{font-family:var(--mono);font-size:11px;white-space:pre-wrap;margin:8px 0 0;padding:10px;border-radius:8px;background:var(--bg);border:1px solid var(--border);max-height:180px;overflow:auto}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Agent</h1>
				<div class="subtitle">Connects to your tunnel server and forwards traffic locally</div>
			</div>
			<div class="nav">
				<a class="active" href="/">Home</a>
				<a href="/controls">Controls</a>
				<a href="/apps">Apps</a>
				<a href="/mail">Mail</a>
			</div>
		</div>

		{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}

		<div class="statusGrid">
			<div class="sCard">
				<div class="label">Service</div>
				<div class="val"><span id="svcPill" class="pill {{if .Running}}ok{{else}}bad{{end}}">{{if .Running}}Running{{else}}Stopped{{end}}</span></div>
			</div>
			<div class="sCard">
				<div class="label">Connection</div>
				<div class="val"><span id="ctlPill" class="pill {{if .Connected}}ok{{else}}bad{{end}}">{{if .Connected}}Connected{{else}}Disconnected{{end}}</span></div>
			</div>
			<div class="sCard">
				<div class="label">Token</div>
				<div class="val"><span id="tokenPill" class="pill {{if .HasToken}}ok{{else}}bad{{end}}">{{if .HasToken}}Set{{else}}Missing{{end}}</span></div>
			</div>
			<div class="sCard">
				<div class="label">Server</div>
				<div class="val" style="font-size:12px"><code id="serverVal">{{.Cfg.Server}}</code></div>
			</div>
			<div class="sCard">
				<div class="label">Email</div>
				<div class="val"><span id="emailPill" class="pill {{with .EmailStatus}}{{if .Running}}ok{{else if .Enabled}}warn{{else}}bad{{end}}{{else}}bad{{end}}">{{with .EmailStatus}}{{if .Running}}Running{{else if .Enabled}}Configured{{else}}Disabled{{end}}{{else}}Disabled{{end}}</span></div>
			</div>
		</div>

		<div class="flex" style="margin-bottom:16px">
			<button class="btn sm primary" id="btnStart">Start</button>
			<button class="btn sm warn" id="btnStop">Stop</button>
			<button class="btn sm" id="btnRestart">Restart</button>
			<span class="muted" style="font-size:11px" id="liveText">Updating…</span>
		</div>
		<div id="errRow" style="display:none" class="errBox"><b>Last error:</b> <span id="errText"></span></div>

		<div class="secHead"><h2>Connection</h2></div>
		<form method="post" action="/save" class="card">
			<input type="hidden" name="csrf_token" value="{{.CSRFToken}}" />
			<div class="grid2">
				<div>
					<label>Server</label>
					<div class="help">Tunnel server host/IP (defaults to ports 7000/7001).</div>
					<input name="server" value="{{.Cfg.Server}}" />
				</div>
				<div>
					<label>Token</label>
					<div class="help">Required. Must match the server token. Leave blank to keep the current token.</div>
					<input type="text" id="tokenInput" name="token" value="" placeholder="{{.TokenPlaceholder}}" autocomplete="off" />
				</div>
				<div>
					<label>TLS Pin (SHA256)</label>
					<div class="help">Optional. Hex fingerprint of the server's certificate to prevent MITM.</div>
					<input name="tls_pin_sha256" value="{{.Cfg.TLSPinSHA256}}" placeholder="e.g. a1b2c3d4..." />
				</div>
			</div>
			<div style="margin-top:10px" class="muted" style="font-size:12px">Routes come from the server. Each route forwards to its configured local target, or defaults to <code>127.0.0.1:&lt;publicPort&gt;</code>.</div>
			<div class="flex" style="margin-top:12px">
				<button type="submit" class="btn primary">Save &amp; restart</button>
			</div>
		</form>

		<div class="secHead"><h2>Routes</h2></div>
		<div class="card">
			<div id="routesEmpty" class="muted" {{if .Connected}}style="display:none"{{end}}>Routes appear after the agent connects to the server.</div>
			<div id="routesList">
				{{range .RoutesView}}
				<div class="routeRow">
					<span class="rName">{{.Name}}</span>
					<span class="rProto {{.Proto}}">{{.Proto}}</span>
					<span class="rAddrs"><code>{{.PublicAddr}}</code> &rarr; <code>{{.LocalTarget}}</code></span>
				</div>
				{{end}}
			</div>
		</div>

		<div class="secHead"><h2>Email</h2></div>
		<div class="card">
			<div id="emailInfo" class="muted">{{with .EmailStatus}}{{if .Enabled}}Mail host <code>{{.MailHost}}</code> · TLS {{if .TLSReady}}{{.TLSCertSource}}{{else}}unavailable{{end}} · DKIM {{if .DKIMReady}}{{.DKIMSelector}}{{else}}unavailable{{end}} · SMTP <code>{{.SubmissionAddr}}</code> / SMTPS <code>{{.SubmissionTLSAddr}}</code> · IMAP <code>{{.IMAPAddr}}</code> / IMAPS <code>{{.IMAPTLSAddr}}</code> · Max {{.MaxMessageBytes}} bytes / {{.MaxRecipients}} recipients per email · Storage {{.StorageUsedText}}{{if .StorageUnlimited}} / unlimited{{else}} / {{.StorageLimitText}}{{end}} · Accounts {{.AccountCount}} · Messages {{.MessageCount}}{{else}}Email is not enabled on the server.{{end}}{{else}}Email service unavailable.{{end}}</div>
			<div id="emailDNS" class="muted" style="margin-top:10px">{{with .EmailStatus}}{{if .DKIMReady}}<div>DKIM DNS name <code>{{.DKIMDNSName}}</code></div><div class="dkimBox"><div class="dkimTop"><span class="muted">TXT value</span><button type="button" class="btn sm" id="copyDkimBtn">Copy</button></div><textarea id="dkimTxtValue" class="dkimText" readonly>{{.DKIMTXTValue}}</textarea></div>{{else if .Enabled}}DKIM record will appear here after the mail service starts.{{end}}{{end}}</div>
		</div>
	</div>

	<div id="updatePopup" class="updatePopup">
		<div style="margin-bottom:8px"><b>Update available</b> <span class="muted" id="updVer">—</span></div>
		<div class="muted" style="font-size:12px;margin-bottom:8px" id="updInfo">Current: <code>{{.Version}}</code></div>
		<div class="flex">
			<button type="button" class="btn sm" id="updRemind">Later</button>
			<button type="button" class="btn sm" id="updSkip">Skip</button>
			<button type="button" class="btn sm primary" id="updApply">Update</button>
		</div>
		<pre id="updSteps" style="display:none"></pre>
		<pre id="updLog" style="display:none"></pre>
	</div>

	<script>
	(function(){
		var csrfMeta=document.querySelector('meta[name="csrf-token"]');
		var csrfToken=csrfMeta?csrfMeta.content:'';
		var origFetch=window.fetch;
		window.fetch=function(url,opts){opts=opts||{};if(opts.method&&opts.method.toUpperCase()!=='GET'&&opts.method.toUpperCase()!=='HEAD'){opts.headers=opts.headers||{};if(typeof opts.headers==='object'&&!opts.headers['X-CSRF-Token']){opts.headers['X-CSRF-Token']=csrfToken;}}return origFetch(url,opts);};
		function apiData(payload){return payload&&payload.status==='ok'&&Object.prototype.hasOwnProperty.call(payload,'data')?payload.data:payload;}
		async function readAPI(res){return apiData(await res.json());}
		var reloadScheduled=false;
		function scheduleReload(){if(reloadScheduled)return;reloadScheduled=true;setTimeout(function(){location.reload();},1500);}
		async function fetchJSON(url){var ctl=new AbortController();var timer=setTimeout(function(){ctl.abort();},5000);try{var res=await fetch(url,{cache:'no-store',headers:{'Accept':'application/json'},signal:ctl.signal});var ct=res.headers.get('content-type')||'';if(res.redirected||ct.indexOf('application/json')<0){scheduleReload();throw new Error('dashboard response changed');}if(!res.ok)throw new Error('http '+res.status);return await readAPI(res);}finally{clearTimeout(timer);}}

		var updPopup=document.getElementById('updatePopup');
		var updVer=document.getElementById('updVer');
		var updInfo=document.getElementById('updInfo');
		var updSteps=document.getElementById('updSteps');
		var updLog=document.getElementById('updLog');
		function sleep(ms){return new Promise(function(r){setTimeout(r,ms)});}
		async function postU(p){try{await fetch(p,{method:'POST'});}catch(_){}}
		async function fetchUpd(){try{return await fetchJSON('/api/update/status');}catch(e){return null;}}
		function setVis(v){if(updPopup)updPopup.style.display=v?'':'none';}
		function renderSteps(st){
			if(!updSteps)return;
			var running=!!(st&&st.job&&st.job.state==='running');
			var log=(st&&st.job&&st.job.log)?String(st.job.log):'';
			if(!running){updSteps.style.display='none';return;}
			var has=function(re){try{return re.test(log);}catch(e){return false;}};
			var s1=has(/Downloading:/)&&has(/Downloaded\s+\d+\s+bytes/);
			var s2=has(/Extracted source:/)&&has(/Applying into:/);
			var s3=has(/Running build\.sh/);
			var s4=has(/Build succeeded/)||has(/Build failed/);
			var s5=!!(st&&st.job&&st.job.restarting);
			var fmt=function(d,l){return(d?'[x] ':'[ ] ')+l;};
			updSteps.textContent=[fmt(s1,'Download'),fmt(s2,'Apply files'),fmt(s3,'Build'),fmt(s4,'Build finished'),fmt(s5,'Restart')].join('\n');
			updSteps.style.display='';
		}
		function renderUpd(st){
			if(!st)return;
			var show=!!st.showPopup||(st.job&&st.job.state&&st.job.state!=='idle');
			setVis(show);if(!show)return;
			if(updVer)updVer.textContent=st.availableVersion?('v'+st.availableVersion):'';
			if(updInfo){
				var s='Current: {{.Version}}';
				if(st.job&&st.job.state==='running')s='Updating…';
				if(st.job&&st.job.state==='success')s='Done. Restarting…';
				if(st.job&&st.job.state==='failed')s='Update failed.';
				updInfo.textContent=s;
			}
			renderSteps(st);
			if(updLog){
				var l=(st.job&&st.job.log)?String(st.job.log):'';
				if(st.job&&(st.job.state==='failed'||st.job.state==='success'||st.job.state==='running')){updLog.style.display='';updLog.textContent=l||'(no log)';}
				else{updLog.style.display='none';}
			}
			var busy=st.job&&st.job.state==='running';
			var a=document.getElementById('updApply');if(a)a.disabled=busy;
		}
		async function pollDone(){
			for(;;){var st=await fetchUpd();if(st){renderUpd(st);if(st.job&&st.job.state&&st.job.state!=='running')break;}await sleep(500);}
			for(var i=0;i<90;i++){var s=await fetchUpd();if(s){location.replace('/?r='+Date.now());return;}await sleep(1000);}
		}
		document.getElementById('updRemind').onclick=async function(){await postU('/api/update/remind');setVis(false);};
		document.getElementById('updSkip').onclick=async function(){await postU('/api/update/skip');setVis(false);};
		document.getElementById('updApply').onclick=async function(){await postU('/api/update/apply');pollDone();};
		fetchUpd().then(renderUpd);
		setInterval(function(){fetchUpd().then(renderUpd);},30000);

		function setPill(el,ok,t){if(!el)return;el.classList.remove('ok','bad','warn');el.classList.add(ok==='warn'?'warn':(ok?'ok':'bad'));el.textContent=t;}
		function esc(s){return s==null?'':String(s);}
		var svcPill=document.getElementById('svcPill');
		var ctlPill=document.getElementById('ctlPill');
		var tokenPill=document.getElementById('tokenPill');
		var emailPill=document.getElementById('emailPill');
		var serverVal=document.getElementById('serverVal');
		var emailInfo=document.getElementById('emailInfo');
		var emailDNS=document.getElementById('emailDNS');
		function bindDKIMCopy(){
			var btn=document.getElementById('copyDkimBtn');
			var field=document.getElementById('dkimTxtValue');
			if(!btn||!field)return;
			btn.onclick=async function(){
				try{
					field.select();
					field.setSelectionRange(0, field.value.length);
					if(navigator.clipboard&&navigator.clipboard.writeText){
						await navigator.clipboard.writeText(field.value);
					}else{
						document.execCommand('copy');
					}
					btn.textContent='Copied';
					setTimeout(function(){btn.textContent='Copy';},1500);
				}catch(_){
					btn.textContent='Copy failed';
					setTimeout(function(){btn.textContent='Copy';},1500);
				}
			};
		}
		var liveText=document.getElementById('liveText');
		var errRow=document.getElementById('errRow');
		var errText=document.getElementById('errText');
		var routesEmpty=document.getElementById('routesEmpty');
		var routesList=document.getElementById('routesList');

		async function post(p){try{await fetch(p,{method:'POST'});}catch(_){}await pollOnce();}
		document.getElementById('btnStart').onclick=function(){post('/start');};
		document.getElementById('btnStop').onclick=function(){post('/stop');};
		document.getElementById('btnRestart').onclick=function(){post('/restart');};

		function renderRoutes(routes){
			if(!routesList)return;
			routesList.innerHTML='';
			if(!routes||!routes.length){if(routesEmpty)routesEmpty.style.display='';return;}
			if(routesEmpty)routesEmpty.style.display='none';
			for(var i=0;i<routes.length;i++){
				var rt=routes[i]||{};
				var row=document.createElement('div');row.className='routeRow';
				var nm=document.createElement('span');nm.className='rName';nm.textContent=esc(rt.name);row.appendChild(nm);
				var pr=document.createElement('span');pr.className='rProto '+(esc(rt.proto).toLowerCase());pr.textContent=esc(rt.proto);row.appendChild(pr);
				var ad=document.createElement('span');ad.className='rAddrs';
				var c1=document.createElement('code');c1.textContent=esc(rt.publicAddr);ad.appendChild(c1);
				ad.appendChild(document.createTextNode(' \u2192 '));
				var c2=document.createElement('code');c2.textContent=esc(rt.localTarget);ad.appendChild(c2);
				row.appendChild(ad);
				routesList.appendChild(row);
			}
		}

		async function pollOnce(){
			try{
				var j=await fetchJSON('/api/status');
				setPill(svcPill,!!j.running,j.running?'Running':'Stopped');
				setPill(ctlPill,!!j.connected,j.connected?'Connected':'Disconnected');
				setPill(tokenPill,!!j.tokenSet,j.tokenSet?'Set':'Missing');
				if(emailPill){
					var em=j.email||{};
					var txt=em.running?'Running':(em.enabled?'Configured':'Disabled');
					emailPill.classList.remove('ok','bad','warn');
					emailPill.classList.add(em.running?'ok':(em.enabled?'warn':'bad'));
					emailPill.textContent=txt;
				}
				if(serverVal)serverVal.textContent=esc(j.server);
				if(emailInfo){
					var ems=j.email||{};
					if(ems.enabled){var storageText=(ems.storageUsedText||'0B')+' / '+(ems.storageUnlimited?'unlimited':(ems.storageLimitText||'0B'));emailInfo.innerHTML='Mail host <code>'+esc(ems.mailHost)+'</code> · TLS '+esc(ems.tlsReady?(ems.tlsCertSource||'ready'):'unavailable')+' · DKIM '+esc(ems.dkimReady?(ems.dkimSelector||'ready'):'unavailable')+' · SMTP <code>'+esc(ems.submissionAddr)+'</code> / SMTPS <code>'+esc(ems.submissionTlsAddr)+'</code> · IMAP <code>'+esc(ems.imapAddr)+'</code> / IMAPS <code>'+esc(ems.imapTlsAddr)+'</code> · Max '+esc(ems.maxMessageBytes)+' bytes / '+esc(ems.maxRecipients)+' recipients per email · Storage '+esc(storageText)+' · Accounts '+esc(ems.accountCount)+' · Messages '+esc(ems.messageCount);}else{emailInfo.textContent='Email is not enabled on the server.';}
				}
				if(emailDNS){
					var emd=j.email||{};
					if(emd.dkimReady){emailDNS.innerHTML='<div>DKIM DNS name <code>'+esc(emd.dkimDNSName)+'</code></div><div class="dkimBox"><div class="dkimTop"><span class="muted">TXT value</span><button type="button" class="btn sm" id="copyDkimBtn">Copy</button></div><textarea id="dkimTxtValue" class="dkimText" readonly></textarea></div>';var field=document.getElementById('dkimTxtValue');if(field)field.value=esc(emd.dkimTXTValue);bindDKIMCopy();}else if(emd.enabled){emailDNS.textContent='DKIM record will appear here after the mail service starts.';}else{emailDNS.textContent='';}
				}
				if(errRow&&errText){if(j.lastErr){errRow.style.display='';errText.textContent=esc(j.lastErr);}else{errRow.style.display='none';}}
				renderRoutes(j.routes);
				if(liveText)liveText.textContent='Updated '+new Date().toLocaleTimeString();
			}catch(e){setPill(svcPill,'warn','Syncing');setPill(ctlPill,'warn','Syncing');if(liveText)liveText.textContent='Syncing with agent...';}
		}
		bindDKIMCopy();
		pollOnce();setInterval(pollOnce,2000);
	})();
	</script>
</body>
</html>`

const agentControlsHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="csrf-token" content="{{.CSRFToken}}" />
	<title>Tunnel Agent — Controls</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--bg3:#1e2230;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--bg3:#e2e4ee;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);line-height:1.5}
		a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
		code{font-family:var(--mono);font-size:.8em;background:var(--surface);padding:2px 6px;border-radius:4px}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 60px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{font-size:18px;font-weight:700;margin:0}
		.topbar .subtitle{font-size:12px;color:var(--textMuted);margin-top:2px}
		.nav{display:flex;gap:4px}
		.nav a{font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);transition:all .15s;text-decoration:none}
		.nav a:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
		.pill::before{content:'';width:6px;height:6px;border-radius:50%}
		.pill.ok{color:var(--green);border-color:var(--greenBorder);background:var(--greenDim)}.pill.ok::before{background:var(--green)}
		.pill.bad{color:var(--red);border-color:var(--redBorder);background:var(--redDim)}.pill.bad::before{background:var(--red)}
		.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
		@media(max-width:720px){.grid2{grid-template-columns:1fr}}
		.secHead{margin:24px 0 10px}
		.secHead h2{font-size:14px;font-weight:600;margin:0;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		.btn{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
		.btn:hover{background:var(--surfaceHover);border-color:var(--borderHover)}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn[disabled]{opacity:.4;cursor:not-allowed}
		.btn.sm{font-size:12px;padding:5px 10px}
		.btn.warn{background:var(--redDim);border-color:var(--redBorder);color:var(--red)}
		.select{font-family:var(--font);font-size:13px;padding:7px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg2);color:var(--text)}
		.row{margin-bottom:8px}
		.muted{color:var(--textMuted)}
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.flash{padding:10px 14px;border-radius:var(--radius);font-size:13px;margin-bottom:16px;background:var(--greenDim);border:1px solid var(--greenBorder);color:var(--green)}
		pre{font-family:var(--mono);font-size:11px;white-space:pre-wrap;margin:8px 0 0;padding:10px;border-radius:8px;background:var(--bg);border:1px solid var(--border);max-height:200px;overflow:auto}
		.logCard{margin-top:24px}
		.logToolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin-bottom:10px}
		.logToolbarLeft{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.logList{display:grid;gap:8px;max-height:520px;overflow:auto}
		.logEmpty{padding:18px;border:1px dashed var(--border);border-radius:var(--radius);text-align:center;color:var(--textMuted)}
		.logRow{display:grid;grid-template-columns:150px 72px 120px minmax(0,1fr);gap:10px;align-items:start;padding:10px;border-radius:10px;background:var(--bg);border:1px solid var(--border)}
		.logTime,.logLevel,.logSource,.logMessage{font-family:var(--mono);font-size:12px;min-width:0;overflow-wrap:anywhere}
		.logLevel{font-weight:700}
		.logLevel.info{color:var(--accent)}
		.logLevel.warn{color:#d29922}
		.logLevel.error{color:var(--red)}
		.logLevel.debug,.logLevel.trace{color:var(--textMuted)}
		@media(max-width:860px){.logRow{grid-template-columns:1fr}}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Agent</h1>
				<div class="subtitle">Agent Controls</div>
			</div>
			<div class="nav">
				<a href="/">Home</a>
				<a class="active" href="/controls">Controls</a>
				<a href="/apps">Apps</a>
				<a href="/mail">Mail</a>
			</div>
		</div>

		{{if .Msg}}<div class="flash">{{.Msg}}</div>{{end}}

		<div class="grid2">
			<div>
				<div class="secHead"><h2>Updates</h2></div>
				<div class="card">
					<div class="row"><b>Current:</b> <code>{{.Version}}</code></div>
					<div class="row"><b>Available:</b> <code id="availableVersion">—</code></div>
					<div class="row muted" id="updateState">—</div>
					<div class="flex" style="margin-top:8px">
						<button class="btn sm" id="checkNowBtn">Check now</button>
						<button class="btn sm primary" id="applyBtn" disabled>Update</button>
					</div>
					<div style="margin-top:10px">
						<div class="muted" style="font-size:12px;margin-bottom:6px">Local update (.zip)</div>
						<div class="grid2" style="gap:8px">
							<input type="file" id="localComponentZip" accept=".zip" />
							<input type="file" id="localSharedZip" accept=".zip" />
						</div>
						<div class="muted" style="font-size:11px;margin-top:4px">Left: client.zip (required), right: shared.zip (optional).</div>
						<div class="flex" style="margin-top:8px">
							<button class="btn sm" id="applyLocalBtn">Apply local update</button>
						</div>
					</div>
					<pre id="updateLog" style="display:none"></pre>
				</div>
			</div>
			<div>
				<div class="secHead"><h2>systemd</h2></div>
				<div class="card">
					<div class="row"><b>Service:</b> <code>hostit-agent.service</code></div>
					<div class="row"><b>State:</b> <code id="systemdState">—</code></div>
					<div class="row muted" id="systemdMsg">—</div>
					<div class="flex" style="margin-top:8px">
						<button class="btn sm" id="svcRestartBtn">Restart</button>
						<button class="btn sm warn" id="svcStopBtn">Stop</button>
					</div>
				</div>

				<div class="secHead"><h2>Process</h2></div>
				<div class="card">
					<div class="muted" style="margin-bottom:8px;font-size:12px">Direct process control. Under systemd it will restart automatically.</div>
					<div class="flex">
						<button class="btn sm" id="procRestart">Restart process</button>
						<button class="btn sm warn" id="procExit">Exit process</button>
					</div>
				</div>
			</div>
		</div>

		<div class="secHead"><h2>Logs</h2></div>
		<div class="card logCard">
			<div class="logToolbar">
				<div class="logToolbarLeft">
					<label class="muted" for="logLevel">Log level</label>
					<select id="logLevel" class="select">
						<option value="all">All</option>
						<option value="warning">Warnings</option>
						<option value="error">Errors</option>
					</select>
					<button class="btn sm" id="refreshLogsBtn">Refresh</button>
				</div>
				<div id="logStats" class="muted">—</div>
			</div>
			<div id="logState" class="muted" style="margin-bottom:10px">Loading logs…</div>
			<div id="logList" class="logList"><div class="logEmpty">No logs yet.</div></div>
		</div>
	</div>

	<script>
	(function(){
		var csrfMeta=document.querySelector('meta[name="csrf-token"]');
		var csrfToken=csrfMeta?csrfMeta.content:'';
		var origFetch=window.fetch;
		window.fetch=function(url,opts){opts=opts||{};if(opts.method&&opts.method.toUpperCase()!=='GET'&&opts.method.toUpperCase()!=='HEAD'){opts.headers=opts.headers||{};if(typeof opts.headers==='object'&&!opts.headers['X-CSRF-Token']){opts.headers['X-CSRF-Token']=csrfToken;}}return origFetch(url,opts);};
	})();
	function apiData(payload){return payload&&payload.status==='ok'&&Object.prototype.hasOwnProperty.call(payload,'data')?payload.data:payload;}
	async function readAPI(res){return apiData(await res.json());}
	function esc(v){return String(v||'').replace(/[&<>"']/g,function(ch){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[ch];});}
	function fmtUnix(ts){if(!ts)return '—'; try{return new Date(ts*1000).toLocaleString();}catch(e){return String(ts);}}
	function logClass(level){level=String(level||'').toLowerCase(); if(level==='warn')return 'warn'; if(level==='error'||level==='fatal')return 'error'; if(level==='debug')return 'debug'; if(level==='trace')return 'trace'; return 'info';}
	function renderLogs(payload){
		var list=document.getElementById('logList');
		var stats=document.getElementById('logStats');
		if(!list)return;
		var entries=(payload&&payload.entries)||[];
		var st=(payload&&payload.stats)||{};
		if(stats)stats.textContent='All '+(st.all||0)+' · Warnings '+(st.warning||0)+' · Errors '+(st.error||0);
		if(!entries.length){list.innerHTML='<div class="logEmpty">No matching logs.</div>';return;}
		list.innerHTML=entries.map(function(entry){
			var level=String(entry.level||'INFO').toUpperCase();
			return '<div class="logRow">'
				+'<div class="logTime">'+esc(fmtUnix(entry.timeUnix))+'</div>'
				+'<div class="logLevel '+esc(logClass(level))+'">'+esc(level)+'</div>'
				+'<div class="logSource">'+esc(entry.source||'agent')+'</div>'
				+'<div class="logMessage">'+esc(entry.message||'')+'</div>'
				+'</div>';
		}).join('');
	}
	async function refreshLogs(){
		var levelSel=document.getElementById('logLevel');
		var state=document.getElementById('logState');
		var level=levelSel?levelSel.value:'all';
		if(state)state.textContent='Loading logs…';
		try{
			var r=await fetch('/api/logs?level='+encodeURIComponent(level)+'&limit=300',{cache:'no-store'});
			if(!r.ok){throw new Error(await r.text()||('http '+r.status));}
			var payload=await readAPI(r);
			renderLogs(payload);
			if(state)state.textContent='Showing '+(((payload&&payload.entries)||[]).length)+' log entries.';
		}catch(e){
			if(state)state.textContent='Failed to load logs: '+(e&&e.message?e.message:'unknown');
		}
	}
	function setUpd(st){
		if(!st)return;
		document.getElementById('availableVersion').textContent=st.availableVersion||'—';
		document.getElementById('applyBtn').disabled=!st.updateAvailable;
		document.getElementById('updateState').textContent=st.updateAvailable?'Update available':'Up to date';
		var log=document.getElementById('updateLog');
		if(st.job&&st.job.log){log.style.display='block';log.textContent=st.job.log;}else{log.style.display='none';}
	}
	async function refreshUpd(){var r=await fetch('/api/update/status',{cache:'no-store'});if(r.ok)setUpd(await readAPI(r));}
	async function checkNow(){
		document.getElementById('updateState').textContent='Checking…';
		var r=await fetch('/api/update/check-now',{method:'POST'});
		if(!r.ok){try{var t=await r.text();document.getElementById('updateState').textContent='Failed: '+t;}catch(e){}return;}
		setUpd(await readAPI(r));
	}
	async function applyUpd(){
		document.getElementById('updateState').textContent='Starting…';
		await fetch('/api/update/apply',{method:'POST'});
		document.getElementById('updateState').textContent='Updating…';
		await refreshUpd();
	}
	async function applyLocalUpd(){
		var comp=document.getElementById('localComponentZip');
		var shared=document.getElementById('localSharedZip');
		if(!comp||!comp.files||!comp.files.length){document.getElementById('updateState').textContent='Pick client.zip first';return;}
		var fd=new FormData();
		fd.append('componentZip', comp.files[0]);
		if(shared&&shared.files&&shared.files.length){fd.append('sharedZip', shared.files[0]);}
		document.getElementById('updateState').textContent='Uploading…';
		var r=await fetch('/api/update/apply-local',{method:'POST',body:fd});
		if(!r.ok){try{var t=await r.text();document.getElementById('updateState').textContent='Failed: '+t;}catch(e){document.getElementById('updateState').textContent='Failed';}return;}
		document.getElementById('updateState').textContent='Updating…';
		await refreshUpd();
	}
	function setSys(st){
		if(!st)return;
		document.getElementById('systemdState').textContent=st.available?(st.active||'unknown'):'unavailable';
		document.getElementById('systemdMsg').textContent=st.error||'—';
	}
	async function refreshSys(){var r=await fetch('/api/systemd/status',{cache:'no-store'});if(r.ok)setSys(await readAPI(r));}
	async function sysAction(p,t){
		document.getElementById('systemdMsg').textContent=t;
		var r=await fetch(p,{method:'POST'});
		if(!r.ok){try{var txt=await r.text();document.getElementById('systemdMsg').textContent=txt;}catch(e){}return;}
		document.getElementById('systemdMsg').textContent='OK';
		await refreshSys();
	}
	document.getElementById('checkNowBtn').onclick=checkNow;
	document.getElementById('applyBtn').onclick=applyUpd;
	document.getElementById('applyLocalBtn').onclick=applyLocalUpd;
	document.getElementById('svcRestartBtn').onclick=function(){sysAction('/api/systemd/restart','Restarting…');};
	document.getElementById('svcStopBtn').onclick=function(){sysAction('/api/systemd/stop','Stopping…');};
	document.getElementById('refreshLogsBtn').onclick=refreshLogs;
	document.getElementById('logLevel').onchange=refreshLogs;
	document.getElementById('procRestart').onclick=async function(){
		await fetch('/api/process/restart',{method:'POST'});
		setTimeout(function(){location.reload();},1000);
	};
	document.getElementById('procExit').onclick=async function(){
		await fetch('/api/process/exit',{method:'POST'});
		setTimeout(function(){location.reload();},1000);
	};
	refreshUpd();refreshSys();refreshLogs();setInterval(refreshLogs,2500);
	</script>
</body>
</html>`

const agentMailHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="csrf-token" content="{{.CSRFToken}}" />
	<title>Tunnel Agent – Mail</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--bg3:#1e2230;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--orange:#d29922;--orangeDim:rgba(210,153,34,.12);--orangeBorder:rgba(210,153,34,.4);--purple:#a371f7;--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--bg3:#e2e4ee;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);--orangeDim:rgba(210,153,34,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);line-height:1.5}
		a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 60px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{font-size:18px;font-weight:700;margin:0}
		.topbar .subtitle{font-size:12px;color:var(--textMuted);margin-top:2px}
		.nav{display:flex;gap:4px}
		.nav a{font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);transition:all .15s;text-decoration:none}
		.nav a:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.secHead{margin:20px 0 10px}
		.secHead h2{font-size:14px;font-weight:600;margin:0;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		label{font-size:12px;font-weight:600;display:block;margin:0 0 4px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		select,input[type="password"]{width:100%;padding:9px 10px;border-radius:var(--radius);border:1px solid var(--border);background:var(--bg2);color:var(--text);font-family:var(--font);font-size:14px;transition:border-color .15s}
		select:focus,input:focus{outline:none;border-color:var(--accent)}
		.btn{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
		.btn:hover{background:var(--surfaceHover);border-color:var(--borderHover)}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn.warn{background:var(--redDim);border-color:var(--redBorder);color:var(--red)}
		.btn.sm{font-size:12px;padding:5px 10px}
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.muted{color:var(--textMuted)}
		.errBox{font-size:12px;padding:8px 10px;margin-top:8px;border-radius:8px;background:var(--redDim);border:1px solid var(--redBorder);color:var(--red);word-break:break-all}

		/* login form */
		.loginForm{max-width:380px}
		.loginForm .field{margin-bottom:12px}

		/* inbox table */
		table.inbox{width:100%;border-collapse:collapse;font-size:13px}
		table.inbox th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted);padding:6px 8px;border-bottom:1px solid var(--border)}
		table.inbox th.sortable{padding:0}
		table.inbox th.sortable button{width:100%;display:flex;align-items:center;justify-content:flex-start;gap:6px;padding:6px 8px;border:0;background:transparent;color:inherit;font:inherit;text-transform:inherit;letter-spacing:inherit;cursor:pointer}
		table.inbox th.sortable button:hover{color:var(--text)}
		table.inbox th.sortable button:focus{outline:none;color:var(--text)}
		.sortArrow{display:inline-block;min-width:1em;color:var(--accent);font-size:12px;line-height:1}
		table.inbox td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top}
		table.inbox tr{cursor:pointer;transition:background .12s}
		table.inbox tbody tr:hover{background:var(--surfaceHover)}
		table.inbox .from{font-weight:500;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
		table.inbox .subj{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
		table.inbox .date{white-space:nowrap;font-size:12px;color:var(--textMuted)}

		/* message view */
		.msgView{display:none}
		.msgMeta{font-size:13px;margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)}
		.msgMeta span{display:block;margin-bottom:2px}
		.msgMeta .lbl{font-weight:600;color:var(--textMuted);display:inline;margin-right:6px;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
		.msgBody{font-family:var(--mono);font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:14px;max-height:600px;overflow:auto}
		.msgActions{margin-top:12px;display:flex;gap:8px}

		.noMail{text-align:center;padding:40px 20px;color:var(--textMuted);font-size:14px}
		.hidden{display:none}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Agent</h1>
				<div class="subtitle">Email Viewer</div>
			</div>
			<div class="nav">
				<a href="/">Home</a>
				<a href="/controls">Controls</a>
				<a href="/apps">Apps</a>
				<a class="active" href="/mail">Mail</a>
			</div>
		</div>

		<!-- Login -->
		<div id="loginSection">
			<div class="secHead"><h2>Sign In</h2></div>
			<div class="card loginForm">
				<div class="field">
					<label for="acctSelect">Account</label>
					<select id="acctSelect"><option value="">Loading…</option></select>
				</div>
				<div class="field">
					<label for="passInput">Password</label>
					<input type="password" id="passInput" placeholder="Enter password" />
				</div>
				<div class="flex" style="margin-top:14px">
					<button class="btn primary" id="loginBtn">Sign In</button>
				</div>
				<div id="loginErr" class="errBox hidden"></div>
			</div>
		</div>

		<!-- Inbox -->
		<div id="inboxSection" class="hidden">
			<div class="secHead" style="display:flex;align-items:center;justify-content:space-between">
				<h2 id="inboxTitle">Inbox</h2>
				<div class="flex">
					<button class="btn sm" id="refreshBtn">Refresh</button>
					<button class="btn sm" id="logoutBtn">Sign Out</button>
				</div>
			</div>
			<div class="card" style="padding:0;overflow:auto">
				<table class="inbox">
					<thead><tr><th>From</th><th>Subject</th><th class="sortable"><button type="button" id="dateSortBtn" aria-label="Sort emails by date">Date <span class="sortArrow" id="dateSortArrow">↓</span></button></th></tr></thead>
					<tbody id="inboxBody"></tbody>
				</table>
				<div id="noMessages" class="noMail hidden">No messages</div>
			</div>
		</div>

		<!-- Message view -->
		<div id="msgSection" class="hidden">
			<div class="secHead" style="display:flex;align-items:center;justify-content:space-between">
				<h2>Message</h2>
				<button class="btn sm" id="backBtn">&larr; Back to Inbox</button>
			</div>
			<div class="card">
				<div class="msgMeta">
					<span><span class="lbl">From</span><span id="msgFrom"></span></span>
					<span><span class="lbl">To</span><span id="msgTo"></span></span>
					<span><span class="lbl">Subject</span><span id="msgSubject"></span></span>
					<span><span class="lbl">Date</span><span id="msgDate"></span></span>
				</div>
				<div class="msgBody" id="msgBody"></div>
				<div class="msgActions">
					<button class="btn warn sm" id="deleteBtn">Delete</button>
				</div>
			</div>
		</div>
	</div>

	<script>
	(function(){
		var csrfMeta=document.querySelector('meta[name="csrf-token"]');
		var csrfToken=csrfMeta?csrfMeta.content:'';
		var origFetch=window.fetch;
		window.fetch=function(url,opts){opts=opts||{};if(opts.method&&opts.method.toUpperCase()!=='GET'&&opts.method.toUpperCase()!=='HEAD'){opts.headers=opts.headers||{};if(typeof opts.headers==='object'&&!opts.headers['X-CSRF-Token']){opts.headers['X-CSRF-Token']=csrfToken;}}return origFetch(url,opts);};
		function apiData(payload){return payload&&payload.status==='ok'&&Object.prototype.hasOwnProperty.call(payload,'data')?payload.data:payload;}
		async function readAPI(res){return apiData(await res.json());}

		var creds = null; // {username, password}
		var currentAddress = '';

		var loginSection  = document.getElementById('loginSection');
		var inboxSection  = document.getElementById('inboxSection');
		var msgSection    = document.getElementById('msgSection');
		var acctSelect    = document.getElementById('acctSelect');
		var passInput     = document.getElementById('passInput');
		var loginBtn      = document.getElementById('loginBtn');
		var loginErr      = document.getElementById('loginErr');
		var inboxTitle    = document.getElementById('inboxTitle');
		var inboxBody     = document.getElementById('inboxBody');
		var noMessages    = document.getElementById('noMessages');
		var dateSortBtn   = document.getElementById('dateSortBtn');
		var dateSortArrow = document.getElementById('dateSortArrow');
		var refreshBtn    = document.getElementById('refreshBtn');
		var logoutBtn     = document.getElementById('logoutBtn');
		var backBtn       = document.getElementById('backBtn');
		var deleteBtn     = document.getElementById('deleteBtn');
		var currentMessages = [];
		var sortDirection = 'desc';

		function show(el){el.classList.remove('hidden')}
		function hide(el){el.classList.add('hidden')}

		function escHtml(s){
			var d=document.createElement('div');d.textContent=s;return d.innerHTML;
		}

		function parseMsgTime(msg){
			if(!msg||!msg.date)return 0;
			var ts=Date.parse(msg.date);
			return isNaN(ts)?0:ts;
		}

		function formatMsgDate(raw){
			if(!raw)return '—';
			var ts=Date.parse(raw);
			if(isNaN(ts))return String(raw);
			try{return new Date(ts).toLocaleString();}catch(_){return String(raw);}
		}

		function sortMessages(msgs){
			var out=(msgs||[]).slice();
			out.sort(function(a,b){
				var diff=parseMsgTime(a)-parseMsgTime(b);
				if(diff===0){
					var aid=a&&typeof a.id==='number'?a.id:0;
					var bid=b&&typeof b.id==='number'?b.id:0;
					diff=aid-bid;
				}
				return sortDirection==='asc'?diff:-diff;
			});
			return out;
		}

		function renderSortArrow(){
			if(dateSortArrow)dateSortArrow.textContent=sortDirection==='asc'?'↑':'↓';
			if(dateSortBtn)dateSortBtn.title=sortDirection==='asc'?'Sorting oldest first':'Sorting newest first';
		}

		function renderInboxRows(msgs){
			inboxBody.innerHTML='';
			if(!msgs||msgs.length===0){
				show(noMessages);
				return;
			}
			hide(noMessages);
			var sorted=sortMessages(msgs);
			for(var i=0;i<sorted.length;i++){
				(function(msg){
					var tr=document.createElement('tr');
					tr.innerHTML='<td class="from">'+escHtml(msg.from||'')+'</td>'
						+'<td class="subj">'+escHtml(msg.subject||'(no subject)')+'</td>'
						+'<td class="date">'+escHtml(formatMsgDate(msg.date))+'</td>';
					tr.onclick=function(){openMessage(msg.id)};
					inboxBody.appendChild(tr);
				})(sorted[i]);
			}
		}

		// Load accounts
		fetch('/api/mail/accounts').then(readAPI).then(function(accts){
			acctSelect.innerHTML='';
			if(!accts||accts.length===0){
				acctSelect.innerHTML='<option value="">No accounts</option>';
				return;
			}
			for(var i=0;i<accts.length;i++){
				var o=document.createElement('option');
				o.value=accts[i].username;
				o.textContent=accts[i].address+' ('+accts[i].username+')';
				acctSelect.appendChild(o);
			}
		}).catch(function(){
			acctSelect.innerHTML='<option value="">Error loading accounts</option>';
		});

		loginBtn.onclick=function(){
			var u=acctSelect.value, p=passInput.value;
			if(!u){showErr('Select an account');return;}
			if(!p){showErr('Enter a password');return;}
			hide(loginErr);
			fetch('/api/mail/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})})
			.then(function(r){
				if(!r.ok) throw new Error('Invalid credentials');
				return readAPI(r);
			})
			.then(function(data){
				creds={username:u,password:p};
				currentAddress=data.address||u;
				hide(loginSection);
				show(inboxSection);
				inboxTitle.textContent='Inbox – '+currentAddress;
				loadInbox();
			})
			.catch(function(e){showErr(e.message)});
		};

		passInput.addEventListener('keydown',function(e){if(e.key==='Enter')loginBtn.click()});

		function showErr(msg){
			loginErr.textContent=msg;
			show(loginErr);
		}

		function loadInbox(){
			renderSortArrow();
			inboxBody.innerHTML='<tr><td colspan="3" style="text-align:center;padding:20px;color:var(--textMuted)">Loading…</td></tr>';
			hide(noMessages);
			fetch('/api/mail/inbox',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(creds)})
			.then(function(r){
				if(!r.ok) throw new Error('Failed to load inbox');
				return readAPI(r);
			})
			.then(function(msgs){
				currentMessages=Array.isArray(msgs)?msgs:[];
				renderInboxRows(currentMessages);
			})
			.catch(function(e){
				currentMessages=[];
				inboxBody.innerHTML='<tr><td colspan="3" class="errBox">'+escHtml(e.message)+'</td></tr>';
			});
		}

		function openMessage(id){
			hide(inboxSection);
			show(msgSection);
			document.getElementById('msgFrom').textContent='Loading…';
			document.getElementById('msgTo').textContent='';
			document.getElementById('msgSubject').textContent='';
			document.getElementById('msgDate').textContent='';
			document.getElementById('msgBody').textContent='';

			fetch('/api/mail/message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:creds.username,password:creds.password,messageId:id})})
			.then(function(r){
				if(!r.ok) throw new Error('Failed to load message');
				return readAPI(r);
			})
			.then(function(msg){
				document.getElementById('msgFrom').textContent=msg.from;
				document.getElementById('msgTo').textContent=msg.to;
				document.getElementById('msgSubject').textContent=msg.subject||'(no subject)';
				document.getElementById('msgDate').textContent=formatMsgDate(msg.date);
				document.getElementById('msgBody').textContent=msg.body;
				deleteBtn.onclick=function(){
					if(!confirm('Delete this message?')) return;
					fetch('/api/mail/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:creds.username,password:creds.password,messageId:id})})
					.then(function(r){
						if(!r.ok) throw new Error('Delete failed');
						hide(msgSection);
						show(inboxSection);
						loadInbox();
					})
					.catch(function(e){alert(e.message)});
				};
			})
			.catch(function(e){
				document.getElementById('msgBody').textContent='Error: '+e.message;
			});
		}

		refreshBtn.onclick=loadInbox;
		if(dateSortBtn){
			dateSortBtn.onclick=function(){
				sortDirection=sortDirection==='desc'?'asc':'desc';
				renderSortArrow();
				renderInboxRows(currentMessages);
			};
		}

		logoutBtn.onclick=function(){
			creds=null;
			currentAddress='';
			currentMessages=[];
			passInput.value='';
			hide(inboxSection);
			hide(msgSection);
			show(loginSection);
		};

		backBtn.onclick=function(){
			hide(msgSection);
			show(inboxSection);
		};

		renderSortArrow();
	})();
	</script>
</body>
</html>`

const agentAppsHTML = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="csrf-token" content="{{.CSRFToken}}" />
	<title>Tunnel Agent — Apps</title>
	<style>
		*,*::before,*::after{box-sizing:border-box}
		:root{--bg:#0f1117;--bg2:#181b25;--bg3:#1e2230;--surface:rgba(255,255,255,.04);--surfaceHover:rgba(255,255,255,.07);--border:rgba(255,255,255,.08);--borderHover:rgba(255,255,255,.14);--text:#e4e6ee;--textMuted:rgba(228,230,238,.55);--accent:#5b8def;--accentDim:rgba(91,141,239,.18);--accentBorder:rgba(91,141,239,.35);--green:#3fb950;--greenDim:rgba(63,185,80,.14);--greenBorder:rgba(63,185,80,.4);--red:#f85149;--redDim:rgba(248,81,73,.12);--redBorder:rgba(248,81,73,.4);--purple:#a371f7;--radius:10px;--radiusLg:14px;--font:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;color-scheme:dark}
		@media(prefers-color-scheme:light){:root{--bg:#f5f6fa;--bg2:#ebedf5;--bg3:#e2e4ee;--surface:rgba(0,0,0,.03);--surfaceHover:rgba(0,0,0,.06);--border:rgba(0,0,0,.10);--borderHover:rgba(0,0,0,.18);--text:#1a1d28;--textMuted:rgba(26,29,40,.50);--accentDim:rgba(91,141,239,.12);--greenDim:rgba(63,185,80,.10);--redDim:rgba(248,81,73,.08);color-scheme:light}}
		body{font-family:var(--font);margin:0;padding:0;background:var(--bg);color:var(--text);line-height:1.5}
		a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
		code{font-family:var(--mono);font-size:.8em;background:var(--surface);padding:2px 6px;border-radius:4px}
		.wrap{max-width:1060px;margin:0 auto;padding:20px 16px 60px}
		.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
		.topbar h1{font-size:18px;font-weight:700;margin:0}
		.topbar .subtitle{font-size:12px;color:var(--textMuted);margin-top:2px}
		.nav{display:flex;gap:4px}
		.nav a{font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:transparent;color:var(--text);transition:all .15s;text-decoration:none}
		.nav a:hover{background:var(--surfaceHover);border-color:var(--borderHover);text-decoration:none}
		.nav a.active{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.statusGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:20px}
		.sCard{padding:12px;border-radius:var(--radiusLg);border:1px solid var(--border);background:var(--surface);text-align:center}
		.sCard .label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted);margin-bottom:4px}
		.sCard .val{font-size:15px;font-weight:600}
		.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:500;border:1px solid}
		.pill::before{content:'';width:6px;height:6px;border-radius:50%}
		.pill.ok{color:var(--green);border-color:var(--greenBorder);background:var(--greenDim)}.pill.ok::before{background:var(--green)}
		.pill.bad{color:var(--red);border-color:var(--redBorder);background:var(--redDim)}.pill.bad::before{background:var(--red)}
		.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radiusLg);padding:16px;transition:border-color .15s}
		.secHead{margin:20px 0 10px}
		.secHead h2{font-size:14px;font-weight:600;margin:0;text-transform:uppercase;letter-spacing:.05em;color:var(--textMuted)}
		.btn{font-family:var(--font);font-size:13px;padding:7px 14px;border-radius:var(--radius);border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
		.btn:hover{background:var(--surfaceHover);border-color:var(--borderHover)}
		.btn.primary{background:var(--accentDim);border-color:var(--accentBorder);color:var(--accent)}
		.btn.sm{font-size:12px;padding:5px 10px}
		.flex{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
		.muted{color:var(--textMuted)}
		.routeRow{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)}
		.routeRow:last-child{border-bottom:none}
		.routeRow .rName{font-weight:600;min-width:80px}
		.routeRow .rProto{font-size:11px;padding:2px 6px;border-radius:4px;text-transform:uppercase;font-weight:500}
		.routeRow .rProto.tcp{background:var(--accentDim);color:var(--accent)}
		.routeRow .rProto.udp{background:rgba(163,113,247,.14);color:var(--purple)}
		.routeRow .rAddrs{font-size:12px;color:var(--textMuted)}
		.routeRow .rSource{font-size:11px;padding:2px 8px;border-radius:4px;text-transform:uppercase;font-weight:500;background:var(--surface);color:var(--textMuted)}
		.eventLog{max-height:320px;overflow:auto;margin-top:8px}
		.eventRow{display:flex;gap:10px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px}
		.eventRow:last-child{border-bottom:none}
		.eventTime{font-family:var(--mono);color:var(--textMuted);white-space:nowrap;min-width:72px}
		.eventType{font-weight:600;min-width:90px}
		.eventDetail{color:var(--textMuted);min-width:0;overflow-wrap:anywhere}
	</style>
</head>
<body>
	<div class="wrap">
		<div class="topbar">
			<div>
				<h1>Tunnel Agent</h1>
				<div class="subtitle">Apps &amp; Routes</div>
			</div>
			<div class="nav">
				<a href="/">Home</a>
				<a href="/controls">Controls</a>
				<a href="/apps" class="active">Apps</a>
				<a href="/mail">Mail</a>
			</div>
		</div>

		<div class="statusGrid">
			<div class="sCard">
				<div class="label">Connection</div>
				<div class="val"><span id="connPill" class="pill {{if .Connected}}ok{{else}}bad{{end}}">{{if .Connected}}Connected{{else}}Disconnected{{end}}</span></div>
			</div>
			<div class="sCard">
				<div class="label">Routes</div>
				<div class="val" id="routeCount">{{len .RoutesView}}</div>
			</div>
		</div>

		{{if .LastErr}}<div style="font-size:12px;padding:8px 10px;margin-bottom:16px;border-radius:8px;background:var(--redDim);border:1px solid var(--redBorder);color:var(--red);word-break:break-all"><b>Error:</b> {{.LastErr}}</div>{{end}}

		<div class="flex" style="margin-bottom:16px">
			<button class="btn sm primary" id="btnRegisterAll">Register all apps</button>
			<button class="btn sm" id="btnRefresh">Refresh</button>
		</div>

		<div class="secHead"><h2>Active Routes</h2></div>
		<div class="card">
			<div id="routesEmpty" class="muted" {{if .Connected}}style="display:none"{{end}}>Routes appear after the agent connects.</div>
			<div id="routesList">
				{{range .RoutesView}}
				<div class="routeRow">
					<span class="rName">{{.Name}}</span>
					<span class="rProto {{.Proto}}">{{.Proto}}</span>
					<span class="rAddrs"><code>{{.PublicAddr}}</code> &rarr; <code>{{.LocalAddr}}</code></span>
					<span class="rSource">dynamic</span>
				</div>
				{{end}}
			</div>
		</div>

		<div class="secHead"><h2>Events</h2></div>
		<div class="card">
			<div id="eventLog" class="eventLog">
				<div class="muted" id="eventsEmpty">Listening for events…</div>
			</div>
		</div>
	</div>

	<script>
	(function(){
		var csrfMeta=document.querySelector('meta[name="csrf-token"]');
		var csrfToken=csrfMeta?csrfMeta.content:'';
		var origFetch=window.fetch;
		window.fetch=function(url,opts){opts=opts||{};if(opts.method&&opts.method.toUpperCase()!=='GET'&&opts.method.toUpperCase()!=='HEAD'){opts.headers=opts.headers||{};if(typeof opts.headers==='object'&&!opts.headers['X-CSRF-Token']){opts.headers['X-CSRF-Token']=csrfToken;}}return origFetch(url,opts);};
		function apiData(payload){return payload&&payload.status==='ok'&&Object.prototype.hasOwnProperty.call(payload,'data')?payload.data:payload;}
		async function readAPI(res){return apiData(await res.json());}
		var reloadScheduled=false;
		function scheduleReload(){if(reloadScheduled)return;reloadScheduled=true;setTimeout(function(){location.reload();},1500);}
		async function fetchJSON(url){var ctl=new AbortController();var timer=setTimeout(function(){ctl.abort();},5000);try{var res=await fetch(url,{cache:'no-store',headers:{'Accept':'application/json'},signal:ctl.signal});var ct=res.headers.get('content-type')||'';if(res.redirected||ct.indexOf('application/json')<0){scheduleReload();throw new Error('dashboard response changed');}if(!res.ok)throw new Error('http '+res.status);return await readAPI(res);}finally{clearTimeout(timer);}}

		function esc(s){return s==null?'':String(s).replace(/[&<>"']/g,function(ch){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[ch];});}
		function fmtMs(ts){if(!ts)return '';try{return new Date(ts).toLocaleTimeString();}catch(e){return String(ts);}}

		var connPill=document.getElementById('connPill');
		var routeCount=document.getElementById('routeCount');
		var routesEmpty=document.getElementById('routesEmpty');
		var routesList=document.getElementById('routesList');
		var eventLog=document.getElementById('eventLog');
		var eventsEmpty=document.getElementById('eventsEmpty');

		function renderRoutes(routes){
			if(!routesList)return;
			routesList.innerHTML='';
			if(!routes||!routes.length){if(routesEmpty)routesEmpty.style.display='';return;}
			if(routesEmpty)routesEmpty.style.display='none';
			for(var i=0;i<routes.length;i++){
				var rt=routes[i]||{};
				var row=document.createElement('div');row.className='routeRow';
				var nm=document.createElement('span');nm.className='rName';nm.textContent=esc(rt.name);row.appendChild(nm);
				var pr=document.createElement('span');pr.className='rProto '+(esc(rt.proto).toLowerCase());pr.textContent=esc(rt.proto);row.appendChild(pr);
				var ad=document.createElement('span');ad.className='rAddrs';
				var c1=document.createElement('code');c1.textContent=esc(rt.public_addr||rt.publicAddr||'');ad.appendChild(c1);
				ad.appendChild(document.createTextNode(' \u2192 '));
				var c2=document.createElement('code');c2.textContent=esc(rt.local_addr||rt.localAddr||'');ad.appendChild(c2);
				row.appendChild(ad);
				var src=document.createElement('span');src.className='rSource';src.textContent=esc(rt.source||'dynamic');row.appendChild(src);
				routesList.appendChild(row);
			}
			if(routeCount)routeCount.textContent=String(routes.length);
		}

		function addEvent(ev){
			if(eventsEmpty){eventsEmpty.style.display='none';}
			var row=document.createElement('div');row.className='eventRow';
			var tm=document.createElement('span');tm.className='eventTime';tm.textContent=fmtMs(ev.timestamp);row.appendChild(tm);
			var tp=document.createElement('span');tp.className='eventType';tp.textContent=esc(ev.type);row.appendChild(tp);
			var dt=document.createElement('span');dt.className='eventDetail';dt.textContent=esc(ev.route_name?(ev.route_name+' '+(ev.detail||'')):ev.detail||'');row.appendChild(dt);
			eventLog.insertBefore(row,eventLog.firstChild);
			while(eventLog.children.length>100){eventLog.removeChild(eventLog.lastChild);}
		}

		function setPill(el,ok,t){if(!el)return;el.classList.remove('ok','bad','warn');el.classList.add(ok==='warn'?'warn':(ok?'ok':'bad'));el.textContent=t;}

		async function pollOnce(){
			try{
				var j=await fetchJSON('/api/status');
				setPill(connPill,!!j.connected,j.connected?'Connected':'Disconnected');
				renderRoutes(j.routes);
			}catch(e){setPill(connPill,'warn','Syncing');}
		}

		document.getElementById('btnRefresh').onclick=pollOnce;

		document.getElementById('btnRegisterAll').onclick=async function(){
			try{await fetch('/api/v1/apps/register-all',{method:'POST'});}catch(_){}
			setTimeout(pollOnce,500);
		};

		pollOnce();setInterval(pollOnce,3000);

		try{
			var source=new EventSource('/api/v1/events');
			source.onmessage=function(e){
				try{var ev=JSON.parse(e.data);addEvent(ev);}catch(_){}
			};
		}catch(e){}
	})();
	</script>
</body>
</html>`
