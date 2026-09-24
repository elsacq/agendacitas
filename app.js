(function(){
  "use strict";
  const GIST_FILENAME = 'agenda-citas.enc.json';
  const LS_KEY = 'agenda_citas_config';

  /* ================= Cifrado ================= */
  function randomBytes(n){ const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }
  function bytesToB64(b){ let s=''; for(let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]); return btoa(s); }
  function b64ToBytes(b64){ const bin=atob(b64); const o=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) o[i]=bin.charCodeAt(i); return o; }
  async function deriveKey(pass, saltB64){
    const salt = b64ToBytes(saltB64);
    const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:150000, hash:'SHA-256'}, km, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
  }
  async function encryptObj(key, obj){
    const iv = randomBytes(12);
    const pt = new TextEncoder().encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, pt);
    return { iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(ct)) };
  }
  async function decryptObj(key, ivB64, ctB64){
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64ToBytes(ivB64)}, key, b64ToBytes(ctB64));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  function uid(){ return crypto.randomUUID ? crypto.randomUUID() : 'id-'+Math.random().toString(36).slice(2)+Date.now(); }
  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function euros(n){ return (Math.round((n||0)*100)/100).toFixed(2).replace('.', ',') + ' €'; }

  /* ================= Almacenamiento: Gist privado de GitHub ================= */
  function ghHeaders(token, extra){
    return Object.assign({ 'Authorization':'Bearer '+token, 'Accept':'application/vnd.github+json' }, extra||{});
  }
  async function gistGet(token, gistId){
    const res = await fetch('https://api.github.com/gists/'+gistId, { headers: ghHeaders(token) });
    if (res.status === 404) { const e=new Error('not_found'); e.code='not_found'; throw e; }
    if (res.status === 401 || res.status === 403) { const e=new Error('auth'); e.code='auth'; throw e; }
    if (!res.ok) { const e=new Error('http_'+res.status); e.code='http'; throw e; }
    const data = await res.json();
    const file = data.files && data.files[GIST_FILENAME];
    if (!file || !file.content) return null;
    try { return JSON.parse(file.content); } catch(e){ return null; }
  }
  async function gistCreate(token, obj){
    const res = await fetch('https://api.github.com/gists', {
      method:'POST', headers: ghHeaders(token, {'Content-Type':'application/json'}),
      body: JSON.stringify({ description:'Agenda de citas (datos cifrados)', public:false, files:{ [GIST_FILENAME]: { content: JSON.stringify(obj) } } })
    });
    if (res.status === 401 || res.status === 403) { const e=new Error('auth'); e.code='auth'; throw e; }
    if (!res.ok) { const e=new Error('http_'+res.status); e.code='http'; throw e; }
    const data = await res.json();
    return data.id;
  }
  async function gistSet(token, gistId, obj){
    const res = await fetch('https://api.github.com/gists/'+gistId, {
      method:'PATCH', headers: ghHeaders(token, {'Content-Type':'application/json'}),
      body: JSON.stringify({ files:{ [GIST_FILENAME]: { content: JSON.stringify(obj) } } })
    });
    if (res.status === 401 || res.status === 403) { const e=new Error('auth'); e.code='auth'; throw e; }
    if (!res.ok) { const e=new Error('http_'+res.status); e.code='http'; throw e; }
  }

  function loadConfig(){ try { return JSON.parse(localStorage.getItem(LS_KEY) || 'null'); } catch(e){ return null; } }
  function saveConfig(cfg){ localStorage.setItem(LS_KEY, JSON.stringify(cfg)); }
  function clearConfig(){ localStorage.removeItem(LS_KEY); }
  function exportJson(){
    const blob = new Blob([JSON.stringify(state, null, 2)], { type:'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'agenda-citas.json';
    link.click();
    URL.revokeObjectURL(url);
  }
  async function importEncryptedJson(event){
    const input = event.target;
    const file = input.files && input.files[0];
    input.value = '';
    if (!file) return;
    try {
      const imported = JSON.parse(await file.text());
      const isEncrypted = imported && imported.salt && imported.iv && imported.ciphertext;
      let payload = imported;
      let importedState = null;
      if (!isEncrypted) {
        if (!cryptoKey || !salt) throw new Error('session_required');
        if (!imported || !Array.isArray(imported.pacientes) || !Array.isArray(imported.terapias) || !Array.isArray(imported.bonos) || !Array.isArray(imported.citas)) {
          throw new Error('invalid_plain_json');
        }
        importedState = {
          pacientes: imported.pacientes,
          terapias: imported.terapias,
          bonos: imported.bonos,
          citas: imported.citas
        };
        const encrypted = await encryptObj(cryptoKey, importedState);
        payload = { salt, iv: encrypted.iv, ciphertext: encrypted.ciphertext, updatedAt: Date.now() };
      }
      if (!confirm('Esto reemplazará los datos cifrados actuales del Gist. ¿Continuar?')) return;
      await gistSet(ghToken, gistId, payload);
      if (importedState) {
        state = importedState;
        render();
        showToast('JSON importado y cifrado');
      } else {
        showToast('JSON cifrado importado');
        lock();
      }
    } catch(e){
      const message = e.message==='session_required' ? 'Desbloquea la agenda antes de importar' :
        (e.message==='invalid_plain_json' ? 'El JSON no tiene el formato de la agenda' : 'No se pudo importar el JSON');
      showToast(message);
    }
  }

  /* ================= Estado de la app ================= */
  let ghToken = null, gistId = null, cryptoKey = null, salt = null;
  let state = { pacientes: [], terapias: [], bonos: [], citas: [] };
  let saveChain = Promise.resolve();
  let currentTab = 'agenda';
  let agendaView = 'semana';
  let agendaWeekStart = null; // se inicializa en boot
  let agendaSelectedDate = null;
  let agendaShowPast = false, agendaFilterEstado = '', agendaSearch = '';
  let pacientesSearch = '', terapiasSearch = '';

  const FORMAS_PAGO = [['efectivo','Efectivo'],['tarjeta','Tarjeta'],['transferencia','Transferencia'],['bizum','Bizum']];
  const ESTADOS_CITA = [['pendiente','Pendiente'],['en_consulta','En consulta'],['finalizada','Finalizada'],['anulada','Anulada']];

  function todayISO(){ const d=new Date(); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
  function nowHM(){ const d=new Date(); return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0'); }
  function fechaCorta(iso){ if(!iso) return ''; const [y,m,d]=iso.split('-'); const meses=['ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic']; return d+' '+meses[parseInt(m,10)-1]+(y!=new Date().getFullYear()?' '+y:''); }

  function persist(){
    saveChain = saveChain.then(async () => {
      try {
        const enc = await encryptObj(cryptoKey, state);
        await gistSet(ghToken, gistId, { salt, iv: enc.iv, ciphertext: enc.ciphertext, updatedAt: Date.now() });
      } catch(e){
        console.error('Error guardando', e);
        showToast(e.code==='auth' ? '⚠️ Token de GitHub inválido o sin permisos' : '⚠️ No se pudo guardar en GitHub (revisa tu conexión)');
      }
    }).catch(()=>{});
    return saveChain;
  }
  function save(){ persist(); render(); }
  function showToast(msg){ const t=document.createElement('div'); t.className='toast'; t.textContent=msg; document.body.appendChild(t); setTimeout(()=>t.remove(),2600); }

  /* ================= Arranque ================= */
  async function boot(){
    const app = document.getElementById('app');
    const cfg = loadConfig();
    if (!cfg || !cfg.token || !cfg.gistId) { renderConfigScreen(cfg); return; }
    ghToken = cfg.token; gistId = cfg.gistId;
    app.innerHTML = authShell('🔒','Conectando…','<p>Leyendo los datos cifrados desde GitHub…</p>');
    try {
      const data = await gistGet(ghToken, gistId);
      if (!data || !data.salt || !data.ciphertext) renderSetupScreen();
      else renderLoginScreen(data);
    } catch(e){
      if (e.code==='not_found') { renderConfigScreen(cfg, 'No se encontró ese Gist. Revisa el ID o deja el campo vacío para crear uno nuevo.'); }
      else if (e.code==='auth') { renderConfigScreen(cfg, 'El token no es válido o no tiene permiso sobre ese Gist.'); }
      else { renderConfigScreen(cfg, 'No se pudo conectar con GitHub. Comprueba tu conexión e inténtalo de nuevo.'); }
    }
  }

  function authShell(icon, title, bodyHtml){ return '<div class="auth-wrap"><div class="auth-card"><div class="icon">'+icon+'</div><h1>'+esc(title)+'</h1>'+bodyHtml+'</div></div>'; }

  function renderConfigScreen(prevCfg, errMsg){
    const app = document.getElementById('app');
    app.innerHTML =
      '<div class="auth-wrap"><div class="auth-card">'+
      '<div class="icon">🔗</div><h1>Conectar con GitHub</h1>'+
      '<p>Los datos (ya cifrados) se guardan en un <b>Gist privado</b> de tu cuenta de GitHub. Necesitas un token de acceso personal <b>clásico</b> con el permiso <code>gist</code> marcado (nada más).</p>'+
      '<input type="password" id="cfgToken" placeholder="Token de GitHub (ghp_…)" value="'+esc(prevCfg&&prevCfg.token||'')+'">'+
      '<input type="text" id="cfgGist" placeholder="ID del Gist (déjalo vacío la primera vez)" value="'+esc(prevCfg&&prevCfg.gistId||'')+'">'+
      '<div class="err" id="cfgErr">'+esc(errMsg||'')+'</div>'+
      '<button class="btn" id="cfgBtn">Continuar</button>'+
      '<div class="auth-hint">El token se guarda solo en este navegador (localStorage) para no pedirlo cada vez. Úsalo únicamente con el alcance <code>gist</code> y revócalo si compartes o pierdes el dispositivo.</div>'+
      '</div></div>';
    document.getElementById('cfgBtn').onclick = async () => {
      const token = document.getElementById('cfgToken').value.trim();
      let gid = document.getElementById('cfgGist').value.trim();
      const err = document.getElementById('cfgErr');
      if (!token) { err.textContent = 'Introduce el token de GitHub.'; return; }
      err.textContent = 'Conectando…';
      try {
        if (!gid) {
          gid = await gistCreate(token, { placeholder: true });
        } else {
          await gistGet(token, gid); // valida acceso, aunque el resultado se relee en boot()
        }
        ghToken = token; gistId = gid;
        saveConfig({ token, gistId: gid });
        boot();
      } catch(e){
        err.textContent = e.code==='auth' ? 'Token inválido o sin permiso "gist".' : (e.code==='not_found' ? 'No se encontró ese Gist. Revisa el ID.' : 'No se pudo conectar. Inténtalo de nuevo.');
      }
    };
  }

  function renderSetupScreen(){
    const app = document.getElementById('app');
    app.innerHTML =
      '<div class="auth-wrap"><div class="auth-card">'+
      '<div class="icon">🗓️</div><h1>Crear agenda</h1>'+
      '<p>Es la primera vez que se usa este Gist. Define una contraseña: cifrará todos los datos de pacientes y citas antes de guardarlos en GitHub. Guárdala en un lugar seguro — si se pierde, los datos no se pueden recuperar.</p>'+
      '<div class="gistid-box"><b>ID de este Gist (guárdalo para conectar otros dispositivos)</b>'+esc(gistId)+'</div>'+
      '<input type="password" id="pw1" placeholder="Nueva contraseña" autocomplete="new-password">'+
      '<input type="password" id="pw2" placeholder="Repetir contraseña" autocomplete="new-password">'+
      '<div class="err" id="setupErr"></div>'+
      '<button class="btn" id="setupBtn">Crear agenda</button>'+
      '<button class="auth-link" id="changeCfg">Cambiar token / Gist</button>'+
      '</div></div>';
    document.getElementById('changeCfg').onclick = () => { clearConfig(); boot(); };
    document.getElementById('setupBtn').onclick = async () => {
      const pw1 = document.getElementById('pw1').value, pw2 = document.getElementById('pw2').value;
      const err = document.getElementById('setupErr');
      if (pw1.length < 4) { err.textContent = 'La contraseña debe tener al menos 4 caracteres.'; return; }
      if (pw1 !== pw2) { err.textContent = 'Las contraseñas no coinciden.'; return; }
      err.textContent = 'Creando…';
      try {
        salt = bytesToB64(randomBytes(16));
        cryptoKey = await deriveKey(pw1, salt);
        state = { pacientes: [], terapias: [], bonos: [], citas: [] };
        const enc = await encryptObj(cryptoKey, state);
        await gistSet(ghToken, gistId, { salt, iv: enc.iv, ciphertext: enc.ciphertext, updatedAt: Date.now() });
        renderApp();
      } catch(e){ console.error(e); err.textContent = 'No se pudo crear la agenda. Inténtalo de nuevo.'; }
    };
  }

  function renderLoginScreen(data){
    const app = document.getElementById('app');
    app.innerHTML =
      '<div class="auth-wrap"><div class="auth-card">'+
      '<div class="icon">🔒</div><h1>Centro de Medicina Integral<br/>Dra. Otilia Quireza</h1>'+
      '<p>Introduce la contraseña para descifrar los datos.</p>'+
      '<input type="password" id="pwLogin" placeholder="Contraseña" autocomplete="current-password">'+
      '<div class="err" id="loginErr"></div>'+
      '<button class="btn" id="loginBtn">Entrar</button>'+
      '<button class="auth-link" id="changeCfg">Cambiar token / Gist</button>'+
      '</div></div>';
    document.getElementById('changeCfg').onclick = () => { clearConfig(); boot(); };
    const tryLogin = async () => {
      const pw = document.getElementById('pwLogin').value;
      const err = document.getElementById('loginErr');
      err.textContent = 'Comprobando…';
      try {
        const key = await deriveKey(pw, data.salt);
        const decoded = await decryptObj(key, data.iv, data.ciphertext);
        salt = data.salt; cryptoKey = key; state = decoded;
        state.pacientes=state.pacientes||[]; state.terapias=state.terapias||[]; state.bonos=state.bonos||[]; state.citas=state.citas||[];
        renderApp();
      } catch(e){ err.textContent = 'Contraseña incorrecta.'; }
    };
    document.getElementById('loginBtn').onclick = tryLogin;
    document.getElementById('pwLogin').addEventListener('keydown', e => { if (e.key==='Enter') tryLogin(); });
  }

  function lock(){ cryptoKey=null; state={pacientes:[],terapias:[],bonos:[],citas:[]}; boot(); }

  /* ================= App principal ================= */
  const TABS = [['agenda','📅 Agenda'],['pacientes','🧑‍🤝‍🧑 Pacientes'],['terapias','💆 Terapias'],['bonos','🎟️ Bonos'],['contabilidad','💰 Contabilidad']];

  function renderApp(){
    const app = document.getElementById('app');
    app.innerHTML =
      '<header class="topbar"><div class="topbar-inner"><h1>Centro de Medicina Integral<br/>Dra. Otilia Quireza</h1>'+
      '<div><button class="icon-btn" id="infoBtn" title="ID del Gist">ℹ️</button><button class="icon-btn" id="exportBtn" title="Descargar JSON">💾</button><button class="icon-btn" id="importBtn" title="Importar JSON cifrado">📥</button><button class="icon-btn" id="lockBtn" title="Bloquear">🔒</button><input type="file" id="importFile" accept="application/json,.json" hidden></div></div>'+
      '<nav class="tabs">'+TABS.map(t=>'<button data-tab="'+t[0]+'" class="'+(currentTab===t[0]?'active':'')+'">'+t[1]+'</button>').join('')+'</nav>'+
      '</header><main id="content"></main>'+
      (currentTab!=='contabilidad' && currentTab!=='bonos' ? '<button class="fab" id="fabBtn">+</button>' : '');
    document.getElementById('lockBtn').onclick = lock;
    document.getElementById('infoBtn').onclick = () => alert('ID de este Gist (para conectar otro dispositivo):\n\n'+gistId);
    document.getElementById('exportBtn').onclick = exportJson;
    document.getElementById('importBtn').onclick = () => document.getElementById('importFile').click();
    document.getElementById('importFile').onchange = importEncryptedJson;
    document.querySelectorAll('nav.tabs button').forEach(b => b.onclick = () => { currentTab=b.dataset.tab; renderApp(); });
    const fab = document.getElementById('fabBtn');
    if (fab) fab.onclick = () => {
      if (currentTab==='agenda') openCitaModal(agendaView==='semana' ? agendaSelectedDate : todayISO());
      else if (currentTab==='pacientes') openPacienteModal();
      else if (currentTab==='terapias') openTerapiaModal();
    };
    render();
  }

  function render(){
    if (!document.getElementById('content')) return;
    if (currentTab==='agenda') renderAgenda();
    else if (currentTab==='pacientes') renderPacientes();
    else if (currentTab==='terapias') renderTerapias();
    else if (currentTab==='bonos') renderBonos();
    else if (currentTab==='contabilidad') renderContabilidad();
  }

  function paciente(id){ return state.pacientes.find(p=>p.id===id); }
  function terapia(id){ return state.terapias.find(t=>t.id===id); }
  function bono(id){ return state.bonos.find(b=>b.id===id); }
  function bonoActivo(pacienteId, terapiaId){ return state.bonos.find(b=>b.pacienteId===pacienteId && b.terapiaId===terapiaId && b.sesionesRestantes>0); }

  /* ---- utilidades de fecha ---- */
  function isoToDate(iso){ const [y,m,d]=iso.split('-').map(Number); return new Date(y,m-1,d); }
  function dateToISO(d){ return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
  function addDays(iso,n){ const d=isoToDate(iso); d.setDate(d.getDate()+n); return dateToISO(d); }
  function mondayOf(iso){ const d=isoToDate(iso); const day=d.getDay(); const diff=(day===0?-6:1-day); d.setDate(d.getDate()+diff); return dateToISO(d); }
  const DIAS_SEMANA = ['Lun','Mar','Mié','Jue','Vie','Sáb','Dom'];

  /* ================= AGENDA ================= */
  function renderAgenda(){
    const c = document.getElementById('content');
    let html = '<div class="toolbar">'+
      '<button class="btn small '+(agendaView==='semana'?'':'secondary')+'" id="vSemana">Semana</button>'+
      '<button class="btn small '+(agendaView==='lista'?'':'secondary')+'" id="vLista">Lista</button>'+
      '</div>';
    c.innerHTML = html + '<div id="agendaBody"></div>';
    document.getElementById('vSemana').onclick = () => { agendaView='semana'; render(); };
    document.getElementById('vLista').onclick = () => { agendaView='lista'; render(); };
    if (agendaView==='semana') renderAgendaSemana(document.getElementById('agendaBody'));
    else renderAgendaLista(document.getElementById('agendaBody'));
  }

  function renderAgendaSemana(box){
    if (!agendaWeekStart) { agendaSelectedDate = todayISO(); agendaWeekStart = mondayOf(agendaSelectedDate); }
    const dias = [0,1,2,3,4,5,6].map(n => addDays(agendaWeekStart, n));
    const today = todayISO();
    let html = '<div class="toolbar" style="align-items:center">'+
      '<button class="btn small secondary" id="wPrev">‹</button>'+
      '<button class="btn small secondary" id="wHoy">Hoy</button>'+
      '<button class="btn small secondary" id="wNext">›</button>'+
      '</div>';
    html += '<div style="display:flex;gap:6px;overflow-x:auto;margin-bottom:14px;padding-bottom:2px">';
    dias.forEach((iso,i) => {
      const n = state.citas.filter(ci => ci.fecha===iso && ci.estado!=='anulada').length;
      const selected = iso===agendaSelectedDate;
      const isToday = iso===today;
      html += '<button data-day="'+iso+'" style="flex:1;min-width:44px;padding:8px 4px;border-radius:10px;border:1px solid '+(selected?'var(--primary)':'var(--border)')+';background:'+(selected?'var(--primary)':'var(--surface)')+';color:'+(selected?'var(--primary-contrast)':'var(--text)')+';font-size:12px;font-weight:600;text-align:center;position:relative">'+
        DIAS_SEMANA[i]+'<br><span style="font-size:15px">'+parseInt(iso.split('-')[2],10)+'</span>'+
        (isToday && !selected ? '<div style="width:5px;height:5px;border-radius:50%;background:var(--primary);margin:2px auto 0"></div>' : '')+
        (n>0 ? '<div style="font-size:10px;margin-top:1px;'+(selected?'opacity:.85':'color:var(--text-dim)')+'">'+n+'</div>' : '')+
        '</button>';
    });
    html += '</div>';
    html += '<div class="section-label">'+fechaCorta(agendaSelectedDate)+(agendaSelectedDate===today?' · Hoy':'')+'</div>';
    const citasDia = state.citas.filter(ci=>ci.fecha===agendaSelectedDate).sort((a,b)=>a.hora.localeCompare(b.hora));
    if (citasDia.length===0) html += '<div class="empty">No hay citas este día.<br><br><button class="btn ghost" id="emptyNewCita">+ Nueva cita</button></div>';
    else citasDia.forEach(ci => { html += citaCardHtml(ci, paciente(ci.pacienteId), terapia(ci.terapiaId)); });
    box.innerHTML = html;
    document.getElementById('wPrev').onclick = () => { agendaWeekStart=addDays(agendaWeekStart,-7); render(); };
    document.getElementById('wNext').onclick = () => { agendaWeekStart=addDays(agendaWeekStart,7); render(); };
    document.getElementById('wHoy').onclick = () => { agendaWeekStart=mondayOf(today); agendaSelectedDate=today; render(); };
    box.querySelectorAll('[data-day]').forEach(b => b.onclick = () => { agendaSelectedDate=b.dataset.day; render(); });
    const en = document.getElementById('emptyNewCita'); if (en) en.onclick = () => openCitaModal(agendaSelectedDate);
    wireCitaCardActions();
  }

  function renderAgendaLista(box){
    let citas = state.citas.slice().sort((a,b)=>(a.fecha+a.hora).localeCompare(b.fecha+b.hora));
    const today = todayISO();
    if (!agendaShowPast) citas = citas.filter(ci => ci.fecha >= today && ci.estado !== 'anulada');
    if (agendaFilterEstado) citas = citas.filter(ci => ci.estado === agendaFilterEstado);
    if (agendaSearch.trim()) { const q=agendaSearch.trim().toLowerCase(); citas = citas.filter(ci=>{ const p=paciente(ci.pacienteId); return p && (p.nombre.toLowerCase().includes(q) || (p.numero||'').toLowerCase().includes(q)); }); }

    let html = '<div class="toolbar">'+
      '<select id="fEstado"><option value="">Todos los estados</option>'+ESTADOS_CITA.map(e=>'<option value="'+e[0]+'"'+(agendaFilterEstado===e[0]?' selected':'')+'>'+e[1]+'</option>').join('')+'</select>'+
      '<input type="search" id="fBuscar" placeholder="Buscar paciente o nº…" value="'+esc(agendaSearch)+'">'+
      '<button class="btn secondary small" id="fPast">'+(agendaShowPast?'Ver próximas':'Ver histórico')+'</button>'+
      '</div>';
    if (citas.length===0) html += '<div class="empty">No hay citas'+(agendaShowPast?'':' próximas')+' que mostrar.<br><br><button class="btn ghost" id="emptyNewCita">+ Nueva cita</button></div>';
    else {
      let lastFecha=null;
      citas.forEach(ci => {
        const p=paciente(ci.pacienteId), t=terapia(ci.terapiaId);
        if (ci.fecha!==lastFecha) { html += '<div class="section-label">'+fechaCorta(ci.fecha)+'</div>'; lastFecha=ci.fecha; }
        html += citaCardHtml(ci,p,t);
      });
    }
    box.innerHTML = html;
    document.getElementById('fEstado').onchange = e => { agendaFilterEstado=e.target.value; render(); };
    document.getElementById('fBuscar').oninput = e => { agendaSearch=e.target.value; render(); };
    document.getElementById('fPast').onclick = () => { agendaShowPast=!agendaShowPast; render(); };
    const en = document.getElementById('emptyNewCita'); if (en) en.onclick = () => openCitaModal();
    wireCitaCardActions();
  }

  function citaCardHtml(ci,p,t){
    const pagoLabel = ci.pagoEstado==='bono' ? 'Bono' : (ci.pagoEstado==='pagada'?'Pagada':'Pago pendiente');
    const bloqueada = ci.estado==='finalizada' && ci.pagoEstado!=='pendiente';
    return '<div class="card" data-cita="'+ci.id+'">'+
      '<div class="row1"><div class="when" style="text-align:left"><b>'+esc(ci.hora)+'</b>'+fechaCorta(ci.fecha)+'</div>'+
      '<div class="titlebox" style="text-align:right"><div class="t1">'+esc(p?pacienteLabel(p):'Paciente eliminado')+'</div><div class="t2">'+esc(t?t.nombre:'—')+'</div></div></div>'+
      '<div class="badges"><span class="badge estado-'+ci.estado+'">'+labelEstado(ci.estado)+'</span>'+
      '<span class="badge pago-'+ci.pagoEstado+'">'+pagoLabel+(ci.formaPago?' · '+labelForma(ci.formaPago):'')+'</span>'+
      (ci.pagoEstado!=='bono' ? '<span class="badge" style="background:var(--surface-2);color:var(--text-dim)">'+euros(ci.precio)+'</span>' : '')+'</div>'+
      (ci.notas ? '<div class="hint" style="margin-top:8px">'+esc(ci.notas)+'</div>' : '')+
      '<div class="actions">'+
      (ci.estado!=='anulada' && ci.estado!=='finalizada' ? '<button class="btn small secondary" data-act="estado" data-next="'+nextEstado(ci.estado)+'">→ '+labelEstado(nextEstado(ci.estado))+'</button>' : '')+
      (ci.pagoEstado==='pendiente' ? '<button class="btn small secondary" data-act="pagar">💶 Marcar pagada</button>' : '')+
      (ci.estado!=='anulada' && !bloqueada ? '<button class="btn small secondary" data-act="reagendar">🗓️ Reagendar</button>' : '')+
      (ci.estado!=='anulada' && !bloqueada ? '<button class="btn small danger" data-act="anular">Anular</button>' : '')+
      '</div></div>';
  }
  function labelEstado(e){ return (ESTADOS_CITA.find(x=>x[0]===e)||['',''])[1]; }
  function labelForma(f){ return (FORMAS_PAGO.find(x=>x[0]===f)||['',''])[1]; }
  function nextEstado(e){ return e==='pendiente' ? 'en_consulta' : 'finalizada'; }

  function wireCitaCardActions(){
    document.querySelectorAll('.card[data-cita]').forEach(card => {
      const id = card.dataset.cita; const ci = state.citas.find(x=>x.id===id); if (!ci) return;
      card.querySelectorAll('[data-act]').forEach(btn => {
        btn.onclick = () => {
          const act = btn.dataset.act;
          if (act==='estado') { ci.estado = btn.dataset.next; save(); }
          else if (act==='pagar') openPagoModal(ci);
          else if (act==='reagendar') openReagendarModal(ci);
          else if (act==='anular') anularCita(ci);
        };
      });
    });
  }

  function anularCita(ci){
    if (!confirm('¿Anular esta cita?')) return;
    ci.estado = 'anulada';
    if (ci.bonoId) {
      const b = bono(ci.bonoId);
      if (b) {
        b.sesionesRestantes = Math.min(b.sesionesTotales, b.sesionesRestantes+1);
        if (b.creadoPorCitaId === ci.id) { state.bonos = state.bonos.filter(x=>x.id!==b.id); ci.bonoId=null; }
      }
    }
    save();
  }

  function openPagoModal(ci){
    openModal('Registrar pago', modalFieldsHtml([{ type:'select', id:'forma', label:'Forma de pago', options: FORMAS_PAGO }]) + confirmCancelHtml('Marcar pagada'), () => {
      const forma = document.getElementById('mf_forma').value;
      ci.pagoEstado='pagada'; ci.formaPago=forma;
      if (ci.bonoId) { const b = bono(ci.bonoId); if (b && b.creadoPorCitaId===ci.id) { b.pagado=true; b.formaPago=forma; } }
      save(); closeModal();
    });
  }
  function openReagendarModal(ci){
    openModal('Reagendar cita', modalFieldsHtml([{ type:'date', id:'fecha', label:'Fecha', value:ci.fecha },{ type:'time', id:'hora', label:'Hora', value:ci.hora }]) + confirmCancelHtml('Guardar'), () => {
      ci.fecha=document.getElementById('mf_fecha').value; ci.hora=document.getElementById('mf_hora').value;
      if (ci.estado==='anulada') ci.estado='pendiente';
      save(); closeModal();
    });
  }

  function pacienteLabel(p){ return p.nombre + (p.numero ? ' ('+p.numero+')' : ''); }

  function renderAutocomplete(containerId, hiddenId, items, labelFn, subFn, onSelect, placeholder){
    const box = document.getElementById(containerId);
    box.innerHTML = '<div class="ac-wrap">'+
      '<input type="text" id="'+containerId+'_input" placeholder="'+esc(placeholder)+'" autocomplete="off">'+
      '<input type="hidden" id="'+hiddenId+'">'+
      '<div class="ac-results" id="'+containerId+'_results"></div></div>';
    const input = document.getElementById(containerId+'_input');
    const hidden = document.getElementById(hiddenId);
    const results = document.getElementById(containerId+'_results');
    function norm(s){ return (s||'').toString().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,''); }
    function showResults(list){
      if (list.length===0) { results.innerHTML = '<div class="ac-item ac-empty">Sin resultados</div>'; }
      else {
        results.innerHTML = list.map(it => '<div class="ac-item" data-id="'+esc(it.id)+'">'+esc(labelFn(it))+(subFn && subFn(it) ? '<div class="ac-sub">'+esc(subFn(it))+'</div>' : '')+'</div>').join('');
      }
      results.classList.add('open');
      results.querySelectorAll('.ac-item[data-id]').forEach(el => {
        el.onclick = () => {
          const it = items.find(x=>x.id===el.dataset.id);
          hidden.value = it.id; input.value = labelFn(it);
          results.classList.remove('open');
          if (onSelect) onSelect(it);
        };
      });
    }
    input.addEventListener('focus', () => showResults(items.slice(0,50)));
    input.addEventListener('input', () => {
      hidden.value = '';
      const q = norm(input.value);
      const filtered = q ? items.filter(it => norm(labelFn(it)).includes(q) || norm(subFn && subFn(it)).includes(q)) : items;
      showResults(filtered.slice(0,50));
    });
    document.addEventListener('click', function outside(e){
      if (!box.contains(e.target)) results.classList.remove('open');
    });
  }

  function openCitaModal(defaultFecha){
    if (state.pacientes.length===0) { showToast('Añade primero un paciente'); return; }
    if (state.terapias.length===0) { showToast('Añade primero una terapia'); return; }
    const pacientesOrdenados = state.pacientes.slice().sort((a,b)=>a.nombre.localeCompare(b.nombre));
    const terapiasOpts = state.terapias.slice().sort((a,b)=>a.nombre.localeCompare(b.nombre)).map(t=>[t.id, t.nombre+(t.esBono?' · bono '+t.sesiones+' ses.':' · '+euros(t.precio))]);
    const bodyId = 'citaDynamic';
    let html = '<div class="field"><label>Paciente</label><div id="pacienteAc"></div></div>' +
      modalFieldsHtml([
        { type:'select', id:'terapia', label:'Terapia / consulta', options: terapiasOpts },
        { type:'date', id:'fecha', label:'Fecha', value: defaultFecha || todayISO() },
        { type:'time', id:'hora', label:'Hora', value: nowHM() }
      ]);
    html += '<div id="'+bodyId+'"></div>' + confirmCancelHtml('Agendar cita');
    openModal('Nueva cita', html, () => {
      const pacienteId = document.getElementById('mf_paciente').value;
      const terapiaId = document.getElementById('mf_terapia').value;
      const t = terapia(terapiaId);
      const fecha = document.getElementById('mf_fecha').value, hora = document.getElementById('mf_hora').value;
      if (!pacienteId || !terapiaId || !fecha || !hora) { showToast('Completa todos los campos (elige un paciente de la lista)'); return; }
      const nueva = { id: uid(), pacienteId, terapiaId, fecha, hora, duracion: t.duracion, estado:'pendiente', notas:(document.getElementById('mf_notas')||{}).value||'' };
      if (t.esBono) {
        const activo = bonoActivo(pacienteId, terapiaId);
        if (activo) { activo.sesionesRestantes -= 1; nueva.bonoId=activo.id; nueva.precio=0; nueva.pagoEstado='bono'; nueva.formaPago=activo.formaPago; }
        else {
          const nb = { id: uid(), pacienteId, terapiaId, sesionesTotales:t.sesiones, sesionesRestantes:t.sesiones-1, fechaCompra:fecha, pagado:false, formaPago:null, creadoPorCitaId:nueva.id };
          state.bonos.push(nb); nueva.bonoId=nb.id; nueva.precio=t.precio; nueva.pagoEstado='pendiente'; nueva.formaPago=null;
        }
      } else {
        nueva.precio=t.precio; nueva.pagoEstado='pendiente'; nueva.formaPago=null;
      }
      state.citas.push(nueva); save(); closeModal(); showToast('Cita agendada');
    });
    renderAutocomplete('pacienteAc', 'mf_paciente', pacientesOrdenados, pacienteLabel, p=>p.telefono, updateDynamic, 'Buscar por nombre, apellido o nº de paciente…');
    function updateDynamic(){
      const terapiaId = document.getElementById('mf_terapia').value, pacienteId = document.getElementById('mf_paciente').value;
      const t = terapia(terapiaId); const box = document.getElementById(bodyId);
      if (!t) { box.innerHTML=''; return; }
      if (t.esBono) {
        const activo = pacienteId ? bonoActivo(pacienteId, terapiaId) : null;
        if (activo) box.innerHTML = '<div class="note-box">Se descontará una sesión del bono activo ('+activo.sesionesRestantes+' de '+activo.sesionesTotales+' restantes). No se cobra.</div>';
        else box.innerHTML = '<div class="note-box">Primera sesión del bono: se creará un bono de '+t.sesiones+' sesiones, pago pendiente. Márcalo como pagado cuando se abone.</div>';
      } else {
        box.innerHTML = '';
      }
    }
    document.getElementById('mf_terapia').onchange = updateDynamic;
    updateDynamic();
  }

  /* ================= PACIENTES ================= */
  function renderPacientes(){
    const c = document.getElementById('content');
    const all = state.pacientes.slice().sort((a,b)=>a.nombre.localeCompare(b.nombre));
    const query = pacientesSearch.trim().toLowerCase();
    const list = query ? all.filter(p => (p.nombre+' '+(p.numero||'')+' '+(p.telefono||'')).toLowerCase().includes(query)) : all;
    let html = '<div class="toolbar"><input type="search" id="pacientesSearch" placeholder="Buscar paciente, número o teléfono…" value="'+esc(pacientesSearch)+'"></div>';
    if (all.length===0) html += '<div class="empty">Todavía no hay pacientes.<br><br><button class="btn ghost" id="emptyNewP">+ Nuevo paciente</button></div>';
    else if (list.length===0) html += '<div class="empty">No hay pacientes que coincidan con la búsqueda.</div>';
    else html += list.map(p => (
      '<div class="card"><div class="row1"><div class="titlebox"><div class="t1">'+esc(pacienteLabel(p))+'</div>'+
      '<div class="t2">'+esc(p.telefono||'sin teléfono')+(p.whatsapp?' · WhatsApp ✓':'')+'</div></div></div>'+
      '<div class="actions"><button class="btn small secondary" data-edit="'+p.id+'">Editar</button><button class="btn small danger" data-del="'+p.id+'">Eliminar</button></div></div>'
    )).join('');
    c.innerHTML = html;
    document.getElementById('pacientesSearch').oninput = e => {
      pacientesSearch=e.target.value;
      renderPacientes();
      const search = document.getElementById('pacientesSearch');
      search.focus();
      search.setSelectionRange(search.value.length, search.value.length);
    };
    const emptyNew = document.getElementById('emptyNewP');
    if (emptyNew) emptyNew.onclick=()=>openPacienteModal();
    c.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>openPacienteModal(paciente(b.dataset.edit)));
    c.querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>{
      const id=b.dataset.del;
      if (state.citas.some(ci=>ci.pacienteId===id) || state.bonos.some(x=>x.pacienteId===id)) { showToast('No se puede eliminar: tiene citas o bonos asociados'); return; }
      if (confirm('¿Eliminar este paciente?')) { state.pacientes=state.pacientes.filter(p=>p.id!==id); save(); }
    });
  }
  function openPacienteModal(existing){
    const html = modalFieldsHtml([
      { type:'text', id:'nombre', label:'Nombre completo', value: existing?existing.nombre:'' },
      { type:'text', id:'numero', label:'Nº de paciente (opcional)', value: existing?existing.numero:'' },
      { type:'tel', id:'telefono', label:'Teléfono de contacto', value: existing?existing.telefono:'' }
    ]) + '<div class="field checkrow"><input type="checkbox" id="mf_whatsapp" '+(existing&&existing.whatsapp?'checked':'')+'><label for="mf_whatsapp" style="margin:0">Permite avisos por WhatsApp</label></div>'
      + confirmCancelHtml(existing?'Guardar':'Añadir paciente');
    openModal(existing?'Editar paciente':'Nuevo paciente', html, () => {
      const nombre = document.getElementById('mf_nombre').value.trim();
      if (!nombre) { showToast('El nombre es obligatorio'); return; }
      if (existing) { existing.nombre=nombre; existing.numero=document.getElementById('mf_numero').value.trim(); existing.telefono=document.getElementById('mf_telefono').value.trim(); existing.whatsapp=document.getElementById('mf_whatsapp').checked; }
      else state.pacientes.push({ id: uid(), nombre, numero: document.getElementById('mf_numero').value.trim(), telefono: document.getElementById('mf_telefono').value.trim(), whatsapp: document.getElementById('mf_whatsapp').checked });
      save(); closeModal();
    });
  }

  /* ================= TERAPIAS ================= */
  function renderTerapias(){
    const c = document.getElementById('content');
    const all = state.terapias.slice().sort((a,b)=>a.nombre.localeCompare(b.nombre));
    const query = terapiasSearch.trim().toLowerCase();
    const list = query ? all.filter(t => t.nombre.toLowerCase().includes(query)) : all;
    let html = '<div class="toolbar"><input type="search" id="terapiasSearch" placeholder="Buscar terapia o consulta…" value="'+esc(terapiasSearch)+'"></div>';
    if (all.length===0) html += '<div class="empty">Todavía no hay terapias o consultas.<br><br><button class="btn ghost" id="emptyNewT">+ Nueva terapia</button></div>';
    else if (list.length===0) html += '<div class="empty">No hay terapias que coincidan con la búsqueda.</div>';
    else html += list.map(t => (
      '<div class="card"><div class="row1"><div class="titlebox"><div class="t1">'+esc(t.nombre)+'</div>'+
      '<div class="t2">'+t.duracion+' min · '+(t.esBono? 'Bono de '+t.sesiones+' sesiones · '+euros(t.precio)+' total' : euros(t.precio))+'</div></div></div>'+
      '<div class="actions"><button class="btn small secondary" data-edit="'+t.id+'">Editar</button><button class="btn small danger" data-del="'+t.id+'">Eliminar</button></div></div>'
    )).join('');
    c.innerHTML = html;
    document.getElementById('terapiasSearch').oninput = e => {
      terapiasSearch=e.target.value;
      renderTerapias();
      const search = document.getElementById('terapiasSearch');
      search.focus();
      search.setSelectionRange(search.value.length, search.value.length);
    };
    const emptyNew = document.getElementById('emptyNewT');
    if (emptyNew) emptyNew.onclick=()=>openTerapiaModal();
    c.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>openTerapiaModal(terapia(b.dataset.edit)));
    c.querySelectorAll('[data-del]').forEach(b=>b.onclick=()=>{
      const id=b.dataset.del;
      if (state.citas.some(ci=>ci.terapiaId===id) || state.bonos.some(x=>x.terapiaId===id)) { showToast('No se puede eliminar: tiene citas o bonos asociados'); return; }
      if (confirm('¿Eliminar esta terapia?')) { state.terapias=state.terapias.filter(t=>t.id!==id); save(); }
    });
  }
  function openTerapiaModal(existing){
    const html = modalFieldsHtml([
      { type:'text', id:'nombre', label:'Nombre de la terapia / consulta', value: existing?existing.nombre:'' },
      { type:'number', id:'duracion', label:'Duración a reservar (minutos)', value: existing?existing.duracion:30 }
    ]) + '<div class="field checkrow"><input type="checkbox" id="mf_esBono" '+(existing&&existing.esBono?'checked':'')+'><label for="mf_esBono" style="margin:0">Es un bono de varias sesiones</label></div>'
      + '<div id="terapiaDynamic"></div>' + confirmCancelHtml(existing?'Guardar':'Añadir terapia');
    openModal(existing?'Editar terapia':'Nueva terapia', html, () => {
      const nombre = document.getElementById('mf_nombre').value.trim();
      const duracion = parseInt(document.getElementById('mf_duracion').value,10)||30;
      const esBono = document.getElementById('mf_esBono').checked;
      const precio = parseFloat(document.getElementById('mf_precio').value)||0;
      const sesiones = esBono ? (parseInt(document.getElementById('mf_sesiones').value,10)||1) : null;
      if (!nombre) { showToast('El nombre es obligatorio'); return; }
      if (existing) { existing.nombre=nombre; existing.duracion=duracion; existing.esBono=esBono; existing.precio=precio; existing.sesiones=sesiones; }
      else state.terapias.push({ id: uid(), nombre, duracion, esBono, precio, sesiones });
      save(); closeModal();
    });
    const updateDynamic = () => {
      const esBono = document.getElementById('mf_esBono').checked;
      document.getElementById('terapiaDynamic').innerHTML = modalFieldsHtml([
        { type:'number', id:'precio', label: esBono?'Precio total del bono (€)':'Precio (€)', value: existing?existing.precio:'', step:'0.01' },
        ...(esBono ? [{ type:'number', id:'sesiones', label:'Nº de sesiones incluidas', value: existing?existing.sesiones:5 }] : [])
      ]);
    };
    document.getElementById('mf_esBono').onchange = updateDynamic;
    updateDynamic();
  }

  /* ================= CONTABILIDAD ================= */
  function monthLabel(key){
    const [y,m] = key.split('-');
    const meses = ['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
    return meses[parseInt(m,10)-1] + ' ' + y;
  }
  function renderContabilidad(){
    const c = document.getElementById('content');
    const pagadas = state.citas.filter(ci => ci.estado!=='anulada' && ci.pagoEstado==='pagada');
    const totalGeneral = pagadas.reduce((s,ci)=>s+(ci.precio||0),0);

    const porMes = {};
    pagadas.forEach(ci => { const k = ci.fecha.slice(0,7); porMes[k]=(porMes[k]||0)+(ci.precio||0); });
    const mesesOrdenados = Object.keys(porMes).sort().reverse();

    const porForma = {};
    pagadas.forEach(ci => { const f = ci.formaPago||'sin_especificar'; porForma[f]=(porForma[f]||0)+(ci.precio||0); });

    const finPorTerapia = {};
    state.citas.filter(ci=>ci.estado==='finalizada').forEach(ci => { finPorTerapia[ci.terapiaId]=(finPorTerapia[ci.terapiaId]||0)+1; });
    const terapiaRows = Object.keys(finPorTerapia).map(id => ({ id, nombre: (terapia(id)||{}).nombre || 'Terapia eliminada', n: finPorTerapia[id] })).sort((a,b)=>b.n-a.n);

    let html = '<div class="card"><div class="row1"><div class="titlebox"><div class="t1">Total cobrado</div><div class="t2">'+pagadas.length+' citas pagadas</div></div><div class="when"><b>'+euros(totalGeneral)+'</b></div></div></div>';

    html += '<div class="section-label">Por mes</div>';
    html += mesesOrdenados.length===0 ? '<div class="empty">Sin pagos registrados.</div>' :
      mesesOrdenados.map(k => '<div class="card"><div class="row1"><div class="titlebox"><div class="t1" style="text-transform:capitalize">'+esc(monthLabel(k))+'</div></div><div class="when"><b>'+euros(porMes[k])+'</b></div></div></div>').join('');

    html += '<div class="section-label">Por forma de pago</div>';
    const formaRows = FORMAS_PAGO.filter(f=>porForma[f[0]]).map(f=>[f[1], porForma[f[0]]]);
    if (porForma['sin_especificar']) formaRows.push(['Sin especificar', porForma['sin_especificar']]);
    html += formaRows.length===0 ? '<div class="empty">Sin pagos registrados.</div>' :
      formaRows.map(r => '<div class="card"><div class="row1"><div class="titlebox"><div class="t1">'+esc(r[0])+'</div></div><div class="when"><b>'+euros(r[1])+'</b></div></div></div>').join('');

    html += '<div class="section-label">Citas finalizadas por terapia</div>';
    html += terapiaRows.length===0 ? '<div class="empty">Todavía no hay citas finalizadas.</div>' :
      terapiaRows.map(r => '<div class="card"><div class="row1"><div class="titlebox"><div class="t1">'+esc(r.nombre)+'</div></div><div class="when"><b>'+r.n+'</b></div></div></div>').join('');

    c.innerHTML = html;
  }

  /* ================= BONOS ================= */
  function renderBonos(){
    const c = document.getElementById('content');
    const list = state.bonos.slice().sort((a,b)=> b.fechaCompra.localeCompare(a.fechaCompra));
    if (list.length===0) { c.innerHTML='<div class="empty">Todavía no hay bonos. Se crean automáticamente al agendar la primera sesión de una terapia tipo bono.</div>'; return; }
    c.innerHTML = list.map(b => {
      const p=paciente(b.pacienteId), t=terapia(b.terapiaId); const activo = b.sesionesRestantes>0;
      return '<div class="card"><div class="row1"><div class="titlebox"><div class="t1">'+esc(p?p.nombre:'—')+'</div><div class="t2">'+esc(t?t.nombre:'—')+' · comprado '+fechaCorta(b.fechaCompra)+'</div></div>'+
        '<div class="when"><b>'+b.sesionesRestantes+'/'+b.sesionesTotales+'</b>sesiones</div></div>'+
        '<div class="badges"><span class="badge '+(activo?'estado-finalizada':'estado-anulada')+'">'+(activo?'Activo':'Agotado')+'</span>'+
        '<span class="badge '+(b.pagado?'pago-pagada':'pago-pendiente')+'">'+(b.pagado?('Pagado · '+labelForma(b.formaPago)):'Pago pendiente')+'</span></div></div>';
    }).join('');
  }

  /* ================= Modal genérico ================= */
  function modalFieldsHtml(fields){
    return fields.map(f => {
      const id='mf_'+f.id; let input;
      if (f.type==='select') input = '<select id="'+id+'">'+f.options.map(o=>'<option value="'+esc(o[0])+'">'+esc(o[1])+'</option>').join('')+'</select>';
      else if (f.type==='number') input = '<input type="number" id="'+id+'" value="'+esc(f.value)+'" '+(f.step?'step="'+f.step+'"':'')+'>';
      else input = '<input type="'+f.type+'" id="'+id+'" value="'+esc(f.value)+'">';
      return '<div class="field"><label for="'+id+'">'+esc(f.label)+'</label>'+input+'</div>';
    }).join('');
  }
  function confirmCancelHtml(label){ return '<div class="modal-actions"><button class="btn secondary" id="modalCancel">Cancelar</button><button class="btn" id="modalConfirm">'+esc(label)+'</button></div>'; }
  function openModal(title, bodyHtml, onConfirm){
    closeModal();
    const bd = document.createElement('div'); bd.className='modal-backdrop'; bd.id='modalBackdrop';
    bd.innerHTML = '<div class="modal"><h2>'+esc(title)+'</h2>'+bodyHtml+'</div>';
    document.body.appendChild(bd);
    bd.addEventListener('click', e => { if (e.target===bd) closeModal(); });
    const cancelBtn = document.getElementById('modalCancel'); if (cancelBtn) cancelBtn.onclick = closeModal;
    const confirmBtn = document.getElementById('modalConfirm'); if (confirmBtn) confirmBtn.onclick = onConfirm;
  }
  function closeModal(){ const bd = document.getElementById('modalBackdrop'); if (bd) bd.remove(); }

  boot();
})();
