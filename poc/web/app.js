(() => {
  'use strict';
  const VERSION = '1.0.0';
  const RETRY_DELAYS = [2000, 5000, 15000];
  const appState = { csrf:'', user:null, permissions:{}, users:[], cameras:[], adminCameras:[], states:new Map(), observer:null, detail:null, suspended:false, wallMode:false, wallControlsTimer:null, elevatedUntil:0, scanTimer:null, scanId:null, connectionCamera:null, connectionRollout:null, connectionRequest:0, capabilityCamera:null, capabilityRequest:0, ptz:null };
  const $ = (selector, root=document) => root.querySelector(selector);
  const $$ = (selector, root=document) => [...root.querySelectorAll(selector)];
  const mediaHost = location.hostname;
  const sameOriginMedia = !['127.0.0.1', 'localhost'].includes(mediaHost);
  const whepUrl = (path) => sameOriginMedia ? `${location.origin}/whep/${encodeURIComponent(path)}/whep` : `http://${mediaHost}:8889/${encodeURIComponent(path)}/whep`;
  const hlsUrl = (path) => sameOriginMedia ? `${location.origin}/hls/${encodeURIComponent(path)}?autoplay=true&muted=true&controls=true&playsInline=true` : `http://${mediaHost}:8888/${encodeURIComponent(path)}?autoplay=true&muted=true&controls=true&playsInline=true`;
  const toast = (message) => { const node=$('#toast'); node.textContent=message; node.hidden=false; clearTimeout(node.timer); node.timer=setTimeout(()=>node.hidden=true,3500); };
  const relativeTime = (value) => value ? new Intl.DateTimeFormat('de-DE',{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date(value)) : '–';

  class ApiError extends Error { constructor(status, code){ super(code); this.status=status; this.code=code; } }
  async function api(path, options={}) {
    const method = options.method || 'GET';
    const headers = new Headers(options.headers || {});
    if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type','application/json');
    if (!['GET','HEAD'].includes(method) && appState.csrf) headers.set('X-CSRF-Token',appState.csrf);
    const response = await fetch(path,{...options,headers,credentials:'same-origin',cache:'no-store'});
    if (response.status === 204) return null;
    let data={}; try { data=await response.json(); } catch {}
    if (!response.ok) throw new ApiError(response.status,data.detail || data.error || `http-${response.status}`);
    return data;
  }

  let reauthResolver=null,reauthPromise=null;
  function requestReauth(){
    if(reauthPromise)return reauthPromise;
    $('#reauth-error').textContent=''; $('#reauth-password').value=''; $('#reauth-dialog').showModal();
    reauthPromise=new Promise((resolve,reject)=>{reauthResolver=(ok)=>{reauthResolver=null;reauthPromise=null;ok?resolve():reject(new Error('reauth-cancelled'));};});
    return reauthPromise;
  }
  async function adminApi(path,options={}){
    try { return await api(path,options); }
    catch(error){ if(error.code!=='reauth-required') throw error; await requestReauth(); return api(path,options); }
  }

  function openMenu(){
    const menu=$('#app-menu'), button=$('#menu-button'), backdrop=$('#menu-backdrop');
    menu.classList.add('is-open'); menu.removeAttribute('inert'); menu.setAttribute('aria-hidden','false'); button.setAttribute('aria-expanded','true'); button.setAttribute('aria-label','Menü schließen'); backdrop.hidden=false; document.body.classList.add('menu-open');
    $('.nav-item',menu)?.focus();
  }
  function closeMenu(returnFocus=true){
    const menu=$('#app-menu'), button=$('#menu-button'); menu.classList.remove('is-open'); menu.setAttribute('inert',''); menu.setAttribute('aria-hidden','true'); button.setAttribute('aria-expanded','false'); button.setAttribute('aria-label','Menü öffnen'); $('#menu-backdrop').hidden=true; document.body.classList.remove('menu-open'); if(returnFocus) button.focus();
  }
  function showView(name){
    if(appState.wallMode&&name!=='overview')exitWallMode();
    const permission={discover:'discoverCameras',manage:'manageCameras',zones:'manageZones',users:'manageUsers'}[name];
    if(permission&&!appState.permissions[permission])name='overview';
    if(appState.detail) closeDetail();
    $$('.view').forEach((view)=>{ const active=view.dataset.view===name; view.hidden=!active; view.classList.toggle('is-active',active); });
    $$('.nav-item').forEach((item)=>item.classList.toggle('is-active',item.dataset.view===name));
    closeMenu(false); history.replaceState(null,'',`#${name}`);const heading=$(`#view-${name} h2`);if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}
    if(name==='manage') loadAdminCameras(); if(name==='zones') loadZoneCamera(); if(name==='users') loadUsers(); if(name==='system') refreshDiagnostics();
  }

  function revealWallControls(){
    if(!appState.wallMode)return;
    document.body.classList.add('wall-controls-visible');
    clearTimeout(appState.wallControlsTimer);
    appState.wallControlsTimer=setTimeout(()=>{
      if(!$('#exit-wall-mode').matches(':focus-visible'))document.body.classList.remove('wall-controls-visible');
    },3500);
  }
  function enterWallMode(nativeFullscreen=true){
    const enterButton=$('#enter-wall-mode'),exitButton=$('#exit-wall-mode');if(!appState.csrf||appState.wallMode||!enterButton||!exitButton)return;
    closeMenu(false);appState.wallMode=true;document.body.classList.add('wall-mode');exitButton.hidden=false;enterButton.setAttribute('aria-pressed','true');document.title='Camera Hub · Leitstelle';history.replaceState(null,'','#wall');revealWallControls();
    appState.states.forEach(state=>{state.visible=true;if(!state.reader&&state.camera.displayMode!=='snapshot')connect(state,state.camera.lowPath,'low',true);});
    if(nativeFullscreen&&!document.fullscreenElement&&document.documentElement.requestFullscreen)document.documentElement.requestFullscreen().catch(()=>{});
  }
  function exitWallMode({leaveFullscreen=true,updateHistory=true}={}){
    if(!appState.wallMode)return;
    appState.wallMode=false;clearTimeout(appState.wallControlsTimer);appState.wallControlsTimer=null;document.body.classList.remove('wall-mode','wall-controls-visible');const exitButton=$('#exit-wall-mode'),enterButton=$('#enter-wall-mode');if(exitButton)exitButton.hidden=true;if(enterButton)enterButton.setAttribute('aria-pressed','false');document.title='PKWS Camera Hub';if(updateHistory)history.replaceState(null,'','#overview');
    if(leaveFullscreen&&document.fullscreenElement&&document.exitFullscreen)document.exitFullscreen().catch(()=>{});
  }

  function closeReader(state,release=true){
    if(!state) return; clearTimeout(state.retryTimer); clearTimeout(state.startupTimer); clearTimeout(state.snapshotTimer); state.retryTimer=state.startupTimer=state.snapshotTimer=null; state.generation+=1;
    if(state.reader) state.reader.close(); state.reader=null; state.video?.pause(); if(state.video) state.video.srcObject=null;
    if(state.snapshot){state.snapshot.onload=null;state.snapshot.onerror=null;state.snapshot.removeAttribute('src');}
    if(release && state.camera?.id && state.leaseId && appState.csrf){
      const leaseId=state.leaseId;state.leaseId=null;
      api(`/api/cameras/${encodeURIComponent(state.camera.id)}/lease?leaseId=${encodeURIComponent(leaseId)}`,{method:'DELETE'}).catch(()=>{});
    }
  }
  function mark(state,status,text){ state.status.dataset.state=status; const target=state.status.querySelector('.status-text,span:last-child'); if(target) target.textContent=text; if(state.wallStatus){state.wallStatus.dataset.state=status;const wallText=$('span',state.wallStatus);if(wallText)wallText.textContent=status==='live'?'Live':text;} if(state.placeholder) state.placeholder.hidden=status==='live'; }
  async function resumePlayback(state){
    if(!state?.video)return;
    if(!state.video.srcObject){connect(state,state.path,state.mode,true);return;}
    try{await state.video.play();}catch{mark(state,'loading','Zum Start antippen');}
  }
  function stampFrame(state){ state.lastFrameAt=new Date().toISOString(); if(state.lastFrame) state.lastFrame.textContent=relativeTime(state.lastFrameAt); }
  function watchFrames(state,generation){ if(state.generation!==generation||!state.reader)return; state.firstFrameReceived=true; clearTimeout(state.startupTimer); stampFrame(state); mark(state,'live',state.mode==='high'?'Live · Hauptstream':'Live'); if('requestVideoFrameCallback'in state.video)state.video.requestVideoFrameCallback(()=>watchFrames(state,generation)); }
  function scheduleRetry(state,path,mode){ if(state.retryTimer)return; if(appState.suspended||state.retryCount>=RETRY_DELAYS.length){mark(state,'offline','Erneut verbinden');return;} const delay=RETRY_DELAYS[state.retryCount++]; mark(state,'loading',`Neuer Versuch in ${delay/1000} s`); state.retryTimer=setTimeout(()=>connect(state,path,mode),delay); }
  async function connect(state,path,mode='low',manual=false){
    closeReader(state,false); if(manual)state.retryCount=0; if(appState.suspended||!navigator.onLine){mark(state,'offline','Netzwerk offline');return;}
    if(state===appState.detail){$('#detail-video').hidden=false; $('#detail-hls').hidden=true; $('#detail-hls').removeAttribute('src');}
    const generation=state.generation; mark(state,'loading','Verbindung wird hergestellt');
    if(!state.leaseId)try { const lease=await api(`/api/cameras/${encodeURIComponent(state.camera.id)}/lease`,{method:'POST'});if(state.generation!==generation){api(`/api/cameras/${encodeURIComponent(state.camera.id)}/lease?leaseId=${encodeURIComponent(lease.leaseId)}`,{method:'DELETE'}).catch(()=>{});return;}state.leaseId=lease.leaseId; } catch(error){ if(error.status===401){showAuth(false);return;} }
    if(state.generation!==generation)return;
    let reader; reader=new MediaMTXWebRTCReader({url:whepUrl(path),user:'',pass:'',token:'',onError:()=>{if(state.generation!==generation||state.reader!==reader)return;closeReader(state,false);scheduleRetry(state,path,mode);},onTrack:(event)=>{if(state.generation!==generation)return;state.video.srcObject=event.streams[0];state.video.play().catch(()=>mark(state,'loading','Zum Start antippen'));}});
    state.reader=reader; state.path=path; state.mode=mode; state.firstFrameReceived=false;
    state.startupTimer=setTimeout(()=>{if(state.generation!==generation||state.firstFrameReceived)return;closeReader(state,false);scheduleRetry(state,path,mode);},14000);
  }
  function bindVideoEvents(state){
    const video=state.video;video._cameraState=state;
    if(video.dataset.cameraEventsBound==='true')return;
    video.dataset.cameraEventsBound='true';
    video.addEventListener('playing',()=>{const current=video._cameraState;if(!current)return;current.retryCount=0;mark(current,'live',current.mode==='high'?'Live · Hauptstream':'Live');watchFrames(current,current.generation);});
    video.addEventListener('waiting',()=>{const current=video._cameraState;if(current)mark(current,'loading','Puffert');});
    video.addEventListener('stalled',()=>{const current=video._cameraState;if(current)scheduleRetry(current,current.path,current.mode);});
    video.addEventListener('timeupdate',()=>{const current=video._cameraState;if(current)stampFrame(current);});
  }
  function startSnapshot(state,manual=false){
    closeReader(state,false);if(manual)state.retryCount=0;if(appState.suspended||!navigator.onLine){mark(state,'offline','Netzwerk offline');return;}
    const generation=state.generation;state.video.hidden=true;state.snapshot.hidden=false;mark(state,'loading','Vorschau wird geladen');
    state.snapshot.onload=()=>{if(state.generation!==generation)return;state.retryCount=0;stampFrame(state);mark(state,'live','Vorschau aktuell');state.snapshotTimer=setTimeout(()=>startSnapshot(state),5000);};
    state.snapshot.onerror=()=>{if(state.generation!==generation)return;if(state.retryCount>=RETRY_DELAYS.length){mark(state,'offline','Vorschau nicht erreichbar');return;}const delay=RETRY_DELAYS[state.retryCount++];mark(state,'loading',`Neuer Versuch in ${delay/1000} s`);state.snapshotTimer=setTimeout(()=>startSnapshot(state),delay);};
    state.snapshot.src=`${state.camera.snapshotPath}?t=${Date.now()}`;
  }
  function renderCamera(camera){
    const fragment=$('#camera-template').content.cloneNode(true),card=$('.camera-card',fragment),video=$('video',fragment),snapshot=$('.card-snapshot',fragment),status=$('.card-status',fragment);
    const state={camera,card,video,snapshot,status,wallStatus:$('.wall-camera-status',fragment),placeholder:$('.card-placeholder',fragment),lastFrame:$('.last-frame span',fragment),reader:null,retryTimer:null,startupTimer:null,snapshotTimer:null,retryCount:0,generation:0,visible:false,lastFrameAt:null,firstFrameReceived:false,mode:'low',path:camera.lowPath,leaseId:null};
    if(camera.displayMode==='snapshot')video.hidden=true;else bindVideoEvents(state);
    const authBadge=$('.auth-badge',fragment),usesCredentials=Boolean(camera.usesCredentials),authText=usesCredentials?'Mit Anmeldung':'Ohne Anmeldung';
    card.dataset.cameraId=camera.id;$('h3',fragment).textContent=camera.name;$('.wall-camera-name',fragment).textContent=camera.name;$('.source-badge',fragment).textContent=camera.source;authBadge.dataset.auth=String(usesCredentials);authBadge.setAttribute('aria-label',authText);authBadge.title=authText;$('.auth-badge-text',fragment).textContent=authText;$('.open-camera',fragment).addEventListener('click',()=>openDetail(camera.id));$('.reconnect-camera',fragment).addEventListener('click',()=>camera.displayMode==='snapshot'?startSnapshot(state,true):connect(state,camera.lowPath,'low',true));state.placeholder.addEventListener('click',()=>resumePlayback(state));video.addEventListener('click',()=>resumePlayback(state));appState.states.set(camera.id,state);$('#camera-grid').append(fragment);appState.observer.observe(card);
  }
  async function loadCameras(){
    appState.states.forEach(closeReader); appState.states.clear(); $('#camera-grid').replaceChildren();
    const data=await api('/api/cameras'); appState.cameras=data.cameras||[];$('#camera-grid').dataset.count=String(appState.cameras.length);appState.cameras.forEach(renderCamera); await loadHealth(); populateZoneSelect();
  }
  async function loadHealth(){try{const data=await api('/api/health');$('#system-state').dataset.state='live';$('#system-state span').textContent='Lokales Gateway online';data.cameras?.forEach((item)=>{const state=appState.states.get(item.camera);if(!state||state.reader||state.camera.displayMode==='snapshot')return;if(item.lastFrameAt)state.lastFrame.textContent=relativeTime(item.lastFrameAt);if(item.state!=='live')mark(state,'offline','Kamera nicht erreichbar');});}catch{$('#system-state').dataset.state='offline';$('#system-state span').textContent='Gateway nicht erreichbar';}}
  function openDetail(id){
    const camera=appState.cameras.find(item=>item.id===id),tile=appState.states.get(id);if(!camera||!tile)return;const returnFocus=document.activeElement;closeReader(tile);$$('.view').forEach(view=>view.hidden=true);$('#detail').hidden=false;history.replaceState(null,'',`#camera/${camera.id}`);$('#detail-name').textContent=camera.name;$('#detail-source').textContent=camera.source;$('#detail-quality').textContent=camera.displayMode==='snapshot'?'Vorschaubild':(camera.detailQuality||'Hauptstream');const mode=camera.highPath===camera.lowPath?'low':'high';const state={camera,video:$('#detail-video'),snapshot:$('#detail-snapshot'),status:$('#detail-status'),placeholder:$('#detail-message'),lastFrame:$('#detail-last-frame'),reader:null,retryTimer:null,startupTimer:null,snapshotTimer:null,retryCount:0,generation:0,lastFrameAt:null,firstFrameReceived:false,mode,path:camera.highPath,returnFocus,leaseId:null};appState.detail=state;
    const isSnapshot=camera.displayMode==='snapshot';$('#detail-video').hidden=isSnapshot;$('#detail-snapshot').hidden=!isSnapshot;$('#detail-fallback').hidden=isSnapshot;$('#detail-hls-toggle').hidden=isSnapshot;$('#detail-audio').hidden=isSnapshot||!camera.features?.audio;$('#detail-video').muted=true;$('#detail-audio').textContent='Audio einschalten';loadDetailFunctions(camera);$('#detail-back').focus();if(isSnapshot)startSnapshot(state,true);else{bindVideoEvents(state);connect(state,camera.highPath,mode,true);}
  }
  async function loadDetailFunctions(camera){
    appState.ptz=null;$('#detail-functions').hidden=true;$('#ptz-panel').hidden=true;$('#ptz-presets').replaceChildren(new Option('Preset auswählen',''));
    if(!appState.permissions.controlCameras||!camera.features?.ptz)return;
    try{
      const data=await api(`/api/admin/cameras/${encodeURIComponent(camera.id)}/capabilities`),profile=data.profiles?.[0];
      if(appState.detail?.camera.id!==camera.id)return;
      if(!data.available||!data.ptz?.supported||!profile?.token)return;
      appState.ptz={cameraId:camera.id,profileToken:profile.token,moving:false,pending:false,stopRequested:false,operation:0,stopSentFor:0,movePromise:null};
      $('#detail-functions').hidden=false;$('#ptz-panel').hidden=false;$('#ptz-state').textContent='Bereit';
      (data.ptz.presets||[]).forEach(item=>$('#ptz-presets').add(new Option(item.name||'Preset',item.token)));
    }catch{}
  }
  async function startPTZ(button){
    if(!appState.ptz)return;const current=appState.ptz,operation=++current.operation;current.pending=true;current.stopRequested=false;const payload={x:Number(button.dataset.ptzX||0),y:Number(button.dataset.ptzY||0),zoom:Number(button.dataset.ptzZ||0),profileToken:current.profileToken};
    current.movePromise=adminApi(`/api/admin/cameras/${encodeURIComponent(current.cameraId)}/ptz/move`,{method:'POST',body:JSON.stringify(payload)});
    try{await current.movePromise;if(appState.ptz!==current||operation!==current.operation)return;current.pending=false;current.moving=true;if(current.stopRequested)await sendPTZStop(current,operation);else $('#ptz-state').textContent='Bewegung aktiv';}catch(error){current.pending=false;current.moving=false;$('#ptz-state').textContent=`PTZ: ${error.code}`;}
  }
  async function sendPTZStop(current,operation){
    if(current.stopSentFor===operation)return;current.stopSentFor=operation;current.moving=false;current.pending=false;$('#ptz-state').textContent='Stoppt …';
    try{await api(`/api/admin/cameras/${encodeURIComponent(current.cameraId)}/ptz/stop`,{method:'POST',keepalive:true,body:JSON.stringify({profileToken:current.profileToken})});if(appState.ptz===current)$('#ptz-state').textContent='Bereit';}catch(error){if(appState.ptz===current)$('#ptz-state').textContent=`Stop fehlgeschlagen: ${error.code}`;}
  }
  async function stopPTZ(){
    if(!appState.ptz)return;const current=appState.ptz,operation=current.operation;if(!operation)return;current.stopRequested=true;
    if(current.pending){try{await current.movePromise;}catch{}}
    await sendPTZStop(current,operation);
  }
  async function gotoPreset(){
    const token=$('#ptz-presets').value;if(!token||!appState.ptz)return;
    try{await adminApi(`/api/admin/cameras/${encodeURIComponent(appState.ptz.cameraId)}/ptz/presets/${encodeURIComponent(token)}/goto`,{method:'POST',body:JSON.stringify({profileToken:appState.ptz.profileToken})});$('#ptz-state').textContent='Preset angefahren';}catch(error){$('#ptz-state').textContent=`Preset fehlgeschlagen: ${error.code}`;}
  }
  function toggleDetailAudio(){
    const video=$('#detail-video');video.muted=!video.muted;video.play().catch(()=>{});$('#detail-audio').textContent=video.muted?'Audio einschalten':'Audio ausschalten';
  }
  function closeDetail(){const returnFocus=appState.detail?.returnFocus;stopPTZ();if(appState.detail)closeReader(appState.detail);appState.detail=null;appState.ptz=null;$('#detail-functions').hidden=true;$('#detail-hls').hidden=true;$('#detail-hls').removeAttribute('src');$('#detail-snapshot').hidden=true;$('#detail-fallback').hidden=false;$('#detail-hls-toggle').hidden=false;$('#detail').hidden=true;showView('overview');if(returnFocus?.isConnected)returnFocus.focus();}
  function suspend(){stopPTZ();appState.suspended=true;appState.states.forEach(closeReader);if(appState.detail)closeReader(appState.detail);$('#detail-hls').hidden=true;$('#detail-hls').removeAttribute('src');}
  function resume(){if(document.hidden||!navigator.onLine||!appState.csrf)return;appState.suspended=false;if(appState.detail){appState.detail.camera.displayMode==='snapshot'?startSnapshot(appState.detail,true):connect(appState.detail,appState.detail.path,appState.detail.mode,true);}else appState.states.forEach(state=>{if(state.visible)state.camera.displayMode==='snapshot'?startSnapshot(state,true):connect(state,state.camera.lowPath,'low',true);});loadHealth();}

  function showAuth(setup){
    $('#system-state').dataset.state='loading';$('#system-state span').textContent=setup?'Eigentümerkonto anlegen':'Anmeldung erforderlich';$('#auth-title').textContent=setup?'Eigentümerzugang einrichten':'Anmelden';$('#auth-copy').textContent=setup?'Legen Sie Benutzername und Passwort für den lokalen Eigentümerzugang fest.':'Livebilder und Einstellungen sind geschützt.';$('#auth-dialog').dataset.setup=String(setup);$('#auth-error').textContent='';if(!$('#auth-dialog').open)$('#auth-dialog').showModal();
  }
  async function initializeAuth(){
    const state=await api('/api/auth/state');if(!state.authenticated){$('#app').hidden=true;showAuth(state.setupRequired);return false;}applyAccess(state);$('#auth-dialog').close();$('#app').hidden=false;await loadCameras();return true;
  }

  const ROLE_LABELS={owner:'Eigentümer',admin:'Administrator',viewer:'Betrachter'};
  function applyAccess(state){
    appState.csrf=state.csrfToken;appState.elevatedUntil=state.elevatedUntil;appState.user=state.user;appState.permissions=state.permissions||{};
    $$('[data-permission]').forEach(node=>node.hidden=!appState.permissions[node.dataset.permission]);
    $('#current-user').textContent=state.user?.displayName||state.user?.username||'Angemeldet';
    $('#current-role').textContent=ROLE_LABELS[state.user?.role]||state.user?.role||'';
  }

  async function loadAdminCameras(){
    try{const data=await api('/api/admin/cameras');appState.adminCameras=data.cameras||[];renderManage();}catch(error){if(error.status===401)showAuth(false);}
  }
  function connectionBadges(camera){
    const active=camera.activeCredentials||{},draft=camera.draftCredentials||{},live=camera.liveAccess||{};
    const activeHasAuth=Boolean(active.onvif||active.stream),draftHasAuth=Boolean(draft.onvif||draft.stream);
    const badges=[];
    badges.push(`<span class="connection-badge" data-state="${escapeHtml(camera.connectionState||'missing')}">Aktiv ${camera.activeRevision?`R${camera.activeRevision}`:'fehlt'} · ${activeHasAuth?'Zugang gespeichert':'ohne Zugang'}</span>`);
    if(camera.draftRevision){
      const verified=camera.draftTestStatus==='verified';
      badges.push(`<span class="connection-badge" data-state="${verified?'verified':'untested'}">Entwurf R${camera.draftRevision} · ${draftHasAuth?(verified?'Anmeldung geprüft':'Zugang ungeprüft'):(verified?'ohne Anmeldung geprüft':'ohne Zugang')}</span>`);
    }
    if(live.ready&&live.authenticatedLive){
      badges.push(`<span class="connection-badge live-auth" data-state="verified">Live · Anmeldung aktiv${live.revision?` · R${live.revision}`:''}</span>`);
    }else if(live.ready){
      badges.push('<span class="connection-badge live-ready" data-state="live">Live · ohne Anmeldung</span>');
    }else{
      badges.push(`<span class="connection-badge" data-state="offline">${live.state==='media-server-offline'?'Medienserver nicht erreichbar':'Livequelle offline'}</span>`);
    }
    if(camera.draftRevision&&draftHasAuth&&!live.usesActiveRevision){
      badges.push('<span class="connection-note">Geprüfter Entwurf ist noch nicht die Livequelle.</span>');
    }
    return badges.join('');
  }
  function renderManage(){
    const list=$('#manage-list');list.replaceChildren();appState.adminCameras.forEach((camera)=>{
      const row=document.createElement('article');row.className='manage-row';row.dataset.id=camera.id;
      row.innerHTML=`<button class="drag-handle" aria-label="${escapeHtml(camera.name)} verschieben">↕</button><div><h3>${escapeHtml(camera.name)}</h3><div class="manage-meta"><span>${escapeHtml(camera.source)}</span><span>${escapeHtml(camera.manufacturer||'')}</span><span>${escapeHtml(camera.codec.toUpperCase())}</span><span>${camera.enabled?'Aktiv':'Deaktiviert'}</span></div><div class="connection-statuses" aria-label="Verbindungsstatus">${connectionBadges(camera)}</div></div><div class="row-actions"><button data-connection>Verbindung</button><button data-capabilities>Funktionen</button><button data-rollback>Letzte Verbindung</button><button data-move="up" aria-label="Nach oben">↑</button><button data-move="down" aria-label="Nach unten">↓</button><button data-rename>Umbenennen</button><button data-toggle>${camera.enabled?'In App deaktivieren':'In App aktivieren'}</button>${camera.managed?'<button data-remove>Entfernen</button>':''}</div>`;
      $('.drag-handle',row).addEventListener('pointerdown',beginDrag);
      $$('[data-move]',row).forEach(button=>button.addEventListener('click',()=>moveCamera(camera.id,button.dataset.move==='up'?-1:1)));
      $('[data-connection]',row).addEventListener('click',()=>openConnectionDialog(camera));
      $('[data-capabilities]',row).addEventListener('click',()=>openCapabilities(camera));
      $('[data-rollback]',row).addEventListener('click',()=>rollbackConnection(camera));
      $('[data-rename]',row).addEventListener('click',()=>renameCamera(camera));$('[data-toggle]',row).addEventListener('click',()=>toggleCamera(camera));$('[data-remove]',row)?.addEventListener('click',()=>removeCamera(camera));list.append(row);
    });
  }
  const escapeHtml=(value='')=>String(value).replace(/[&<>'"]/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
  let orderSave=Promise.resolve();
  function persistOrder(){const ids=$$('.manage-row',$('#manage-list')).map(row=>row.dataset.id);$('#order-status').textContent='Speichert …';orderSave=orderSave.catch(()=>{}).then(async()=>{try{await adminApi('/api/admin/cameras/order',{method:'PUT',body:JSON.stringify({cameraIds:ids})});$('#order-status').textContent='Gespeichert';await loadAdminCameras();await loadCameras();}catch{$('#order-status').textContent='Speichern fehlgeschlagen';}});return orderSave;}
  function moveCamera(id,direction){const rows=$$('.manage-row'),index=rows.findIndex(row=>row.dataset.id===id),target=rows[index+direction];if(!target)return;direction<0?target.before(rows[index]):target.after(rows[index]);persistOrder();}
  let dragged=null;
  function beginDrag(event){dragged=event.currentTarget.closest('.manage-row');dragged.classList.add('is-dragging');event.currentTarget.setPointerCapture(event.pointerId);event.currentTarget.addEventListener('pointermove',dragMove);for(const name of ['pointerup','pointercancel','lostpointercapture'])event.currentTarget.addEventListener(name,endDrag,{once:true});}
  function dragMove(event){if(!dragged)return;const target=document.elementFromPoint(event.clientX,event.clientY)?.closest('.manage-row');if(!target||target===dragged)return;const box=target.getBoundingClientRect();event.clientY<box.top+box.height/2?target.before(dragged):target.after(dragged);}
  function endDrag(event){event.currentTarget.removeEventListener('pointermove',dragMove);for(const name of ['pointerup','pointercancel','lostpointercapture'])event.currentTarget.removeEventListener(name,endDrag);const changed=Boolean(dragged);dragged?.classList.remove('is-dragging');dragged=null;if(changed)persistOrder();}
  async function toggleCamera(camera){try{await adminApi(`/api/admin/cameras/${encodeURIComponent(camera.id)}`,{method:'PATCH',body:JSON.stringify({enabled:!camera.enabled})});await loadAdminCameras();await loadCameras();}catch(error){toast(`Änderung fehlgeschlagen: ${error.code}`);}}
  async function renameCamera(camera){const name=window.prompt('Neuer Kameraname',camera.name)?.trim();if(!name||name===camera.name)return;try{await adminApi(`/api/admin/cameras/${encodeURIComponent(camera.id)}`,{method:'PATCH',body:JSON.stringify({name})});await loadAdminCameras();await loadCameras();toast('Kameraname gespeichert');}catch(error){toast(`Umbenennen fehlgeschlagen: ${error.code}`);}}
  async function removeCamera(camera){if(!window.confirm(`„${camera.name}“ aus der App entfernen? Das Gerät selbst wird nicht verändert.`))return;try{await adminApi(`/api/admin/cameras/${encodeURIComponent(camera.id)}`,{method:'DELETE'});await loadAdminCameras();await loadCameras();toast('Kamera aus der App entfernt');}catch(error){toast(`Entfernen fehlgeschlagen: ${error.code}`);}}

  function updateCredentialFields(){
    const mode=$('#credential-mode').value;
    $('#credentials-shared').hidden=mode!=='shared';
    $('#credentials-separate').hidden=mode!=='separate';
  }
  function connectionFormPayload(){
    const form=$('#connection-form'),data=new FormData(form),payload=Object.fromEntries(data.entries());
    delete payload.cameraId;payload.baseRevision=payload.draftRevision?Number(payload.draftRevision):null;delete payload.draftRevision;
    for(const key of ['streamPort','onvifPort'])payload[key]=Number(payload[key]);
    for(const key of ['clearSharedCredentials','clearOnvifCredentials','clearStreamCredentials'])payload[key]=Boolean(payload[key]);
    return payload;
  }
  async function openConnectionDialog(camera){
    appState.connectionCamera=camera;const requestId=++appState.connectionRequest,form=$('#connection-form');form.reset();form.elements.cameraId.value=camera.id;
    $('#connection-title').textContent=`Verbindung · ${camera.name}`;$('#connection-error').textContent='';$('#connection-test').textContent='Verbindungsdaten werden geladen …';$('#connection-test').dataset.state='';
    try{
      const data=await api(`/api/admin/cameras/${encodeURIComponent(camera.id)}/connection`);
      if(requestId!==appState.connectionRequest||appState.connectionCamera?.id!==camera.id)return;
      appState.connectionRollout=data.rollout||null;
      const editable=data.revisions?.find(item=>item.state==='draft')||data.connection;
      if(!editable)throw new Error('connection-missing');
      for(const key of ['address','streamProtocol','streamPort','lowSourcePath','highSourcePath','codec','onvifScheme','onvifPort','onvifPath'])if(form.elements[key])form.elements[key].value=editable[key]??'';
      form.elements.credentialMode.value=editable.credentials?.mode||'none';
      form.elements.draftRevision.value=editable.state==='draft'?editable.revision:'';
      form.dataset.tested=editable.testStatus==='verified'?'true':'false';
      const liveSummary=camera.liveAccess?.authenticatedLive?'Liveansicht verwendet eine Anmeldung':camera.liveAccess?.ready?'Liveansicht läuft ohne Anmeldung':'Livequelle derzeit offline';
      $('#connection-state').textContent=`Aktiv: Revision ${data.activeRevision??'–'} · Bearbeitet: Revision ${editable.revision} (${editable.state}) · ${liveSummary}${data.rollout?.liveRelayUsesActiveRevision?' · aktiver Entwurf steuert nach Aktivierung den dynamischen Relay':' · statischer Relay bleibt bis zur Abnahme aktiv'}`;
      const flags=editable.credentials||{};$('#credential-hint').textContent=flags.shared?'Gemeinsamer Zugang gespeichert. Leere Felder behalten ihn bei.':flags.onvif||flags.stream?`ONVIF: ${flags.onvif?'gespeichert':'ohne Zugang'} · Stream: ${flags.stream?'gespeichert':'ohne Zugang'}`:'Keine Zugangsdaten gespeichert.';
      $('#connection-test').textContent=editable.testStatus==='verified'?'Diese Revision wurde erfolgreich geprüft.':'Diese Revision ist noch nicht vollständig geprüft.';
      $('#connection-test').dataset.state=editable.testStatus==='verified'?'ok':'';
      $('#connection-activate').disabled=editable.state!=='draft';
      updateCredentialFields();if(!$('#connection-dialog').open)$('#connection-dialog').showModal();
    }catch(error){toast(`Verbindung konnte nicht geladen werden: ${error.code||error.message}`);}
  }
  async function testConnection(){
    if(!appState.connectionCamera)return;const button=$('#connection-test-button');if(button.disabled)return;button.disabled=true;button.setAttribute('aria-busy','true');const output=$('#connection-test');output.textContent='ONVIF sowie Haupt- und Substream werden geprüft …';output.dataset.state='';
    try{
      const result=await adminApi(`/api/admin/cameras/${encodeURIComponent(appState.connectionCamera.id)}/connection/test`,{method:'POST',body:JSON.stringify(connectionFormPayload())});
      const low=result.stream?.low||{},high=result.stream?.high||{},onvif=result.onvif||{};
      const audio=[low,high].find(item=>item.audioAvailable);
      output.textContent=`Stream: ${low.ok?'Substream bestätigt':'Substream fehlgeschlagen'}${high.ok?' · Hauptstream bestätigt':' · Hauptstream fehlgeschlagen'} · Audio: ${audio?String(audio.audioCodec||'verfügbar').toUpperCase():'nicht erkannt'} · ONVIF: ${onvif.ok?`${onvif.device?.manufacturer||''} ${onvif.device?.model||''}`.trim()||'bestätigt':onvif.error||'nicht verfügbar'}`;
      output.dataset.state=result.verified?'ok':'error';$('#connection-form').dataset.tested=String(Boolean(result.verified));
    }catch(error){output.textContent=`Prüfung fehlgeschlagen: ${error.code||error.message}`;output.dataset.state='error';$('#connection-form').dataset.tested='false';}finally{button.disabled=false;button.removeAttribute('aria-busy');}
  }
  async function saveConnection(event){
    event.preventDefault();if(!appState.connectionCamera)return;const form=event.currentTarget,button=event.submitter;if(button?.disabled)return;if(button){button.disabled=true;button.setAttribute('aria-busy','true');}$('#connection-error').textContent='';
    try{
      const saved=await adminApi(`/api/admin/cameras/${encodeURIComponent(appState.connectionCamera.id)}/connection`,{method:'PUT',body:JSON.stringify(connectionFormPayload())});
      form.elements.draftRevision.value=saved.revision;for(const key of ['sharedUsername','sharedPassword','onvifUsername','onvifPassword','streamUsername','streamPassword'])form.elements[key].value='';
      form.dataset.tested=String(saved.testStatus==='verified');
      $('#connection-activate').disabled=false;$('#connection-state').textContent=`Entwurf Revision ${saved.revision} gespeichert · ${saved.testStatus}`;toast('Verbindungsentwurf verschlüsselt gespeichert');loadAdminCameras().catch(()=>toast('Entwurf gespeichert · Kameraliste bitte neu laden'));
    }catch(error){$('#connection-error').textContent=`Speichern fehlgeschlagen: ${error.code||'unerwarteter-fehler'}`;}finally{if(button){button.disabled=false;button.removeAttribute('aria-busy');}}
  }
  async function activateConnection(){
    if(!appState.connectionCamera)return;const button=$('#connection-activate');if(button.disabled)return;const revision=Number($('#connection-form').elements.draftRevision.value);if(!revision){$('#connection-error').textContent='Bitte zuerst einen Entwurf speichern.';return;}
    if($('#connection-form').dataset.tested!=='true'&&!window.confirm('Diese Verbindung wurde nicht erfolgreich geprüft. Sie wird nach 60 Sekunden ohne Videoframes automatisch zurückgesetzt. Trotzdem aktivieren?'))return;
    button.disabled=true;button.setAttribute('aria-busy','true');try{const result=await adminApi(`/api/admin/cameras/${encodeURIComponent(appState.connectionCamera.id)}/connection/activate`,{method:'POST',body:JSON.stringify({revision})});$('#connection-dialog').close();toast(result.liveRelayUsesActiveRevision?'Verbindung aktiviert · 60-Sekunden-Überwachung läuft':'Verbindung geprüft und vorgemerkt · statischer Relay bleibt bis zur Abnahme aktiv');await loadAdminCameras();await loadCameras();}catch(error){$('#connection-error').textContent=`Aktivierung fehlgeschlagen: ${error.code}`;}finally{button.disabled=false;button.removeAttribute('aria-busy');}
  }
  async function rollbackConnection(camera){
    if(!window.confirm(`Für „${camera.name}“ die letzte bekannte Verbindung wiederherstellen?`))return;
    try{await adminApi(`/api/admin/cameras/${encodeURIComponent(camera.id)}/connection/rollback`,{method:'POST'});toast('Letzte Verbindung wiederhergestellt');await loadAdminCameras();await loadCameras();}catch(error){toast(`Zurücksetzen nicht möglich: ${error.code}`);}
  }
  function capabilityCard(title,lines){return `<article class="capability-card"><h3>${escapeHtml(title)}</h3>${lines.map(line=>`<p>${escapeHtml(line)}</p>`).join('')}</article>`;}
  function renderCapabilities(data){
    const content=$('#capability-content');content.replaceChildren();if(!data.available&&data.revision===0){content.innerHTML=capabilityCard('Noch nicht erkannt',['Starten Sie eine authentifizierte Neuerkennung.']);return;}
    const device=data.device||{},profiles=data.profiles||[],ptz=data.ptz||{},audio=data.audio||{};
    content.innerHTML=[
      capabilityCard('Gerät',[`${device.manufacturer||'Unbekannt'} ${device.model||''}`.trim(),device.firmwareVersion?`Firmware ${device.firmwareVersion}`:'Firmware nicht gemeldet',device.serialNumber?`Seriennummer ${device.serialNumber}`:'Seriennummer nicht gemeldet']),
      capabilityCard('Medien',profiles.length?profiles.map(item=>`${item.name}: ${(item.codec||'').toUpperCase()} ${item.width||'?'}×${item.height||'?'}`):['Keine Profile gemeldet']),
      capabilityCard('Audio',[audio.supported?`Verfügbar: ${(audio.codecs||[]).join(', ')||'Codec unbekannt'}`:'Nicht gemeldet','Gegensprechen: vorbereitet, nicht aktiviert']),
      capabilityCard('PTZ',[ptz.supported?'Unterstützt':'Nicht gemeldet',`Vorhandene Presets: ${(ptz.presets||[]).length}`]),
      capabilityCard('Weitere Funktionen',[`Snapshot: ${data.snapshot?.supported?'ja':'nein'}`,`Imaging: ${data.imaging?'lesbar':'nicht gemeldet'}`,`Events: ${data.events?'unterstützt':'nicht gemeldet'}`,`Analytics: ${data.analytics?'unterstützt':'nicht gemeldet'}`]),
      capabilityCard('Ausgänge',[data.deviceIo?'Device I/O erkannt':'Keine Device-I/O-Angabe','Sirene, Licht und Relais bleiben in V1 deaktiviert'])
    ].join('');
  }
  async function openCapabilities(camera){
    appState.capabilityCamera=camera;const requestId=++appState.capabilityRequest;$('#capability-title').textContent=`Funktionen · ${camera.name}`;$('#capability-error').textContent='';$('#capability-content').innerHTML=capabilityCard('Laden',['Gespeicherte Fähigkeiten werden geladen …']);$('#capability-dialog').showModal();
    try{const data=await api(`/api/admin/cameras/${encodeURIComponent(camera.id)}/capabilities`);if(requestId===appState.capabilityRequest&&appState.capabilityCamera?.id===camera.id)renderCapabilities(data);}catch(error){if(requestId===appState.capabilityRequest)$('#capability-error').textContent=`Laden fehlgeschlagen: ${error.code}`;}
  }
  async function refreshCapabilities(){
    if(!appState.capabilityCamera)return;$('#capability-error').textContent='ONVIF-Funktionen werden gelesen …';
    try{const data=await adminApi(`/api/admin/cameras/${encodeURIComponent(appState.capabilityCamera.id)}/capabilities/refresh`,{method:'POST'});$('#capability-error').textContent='';renderCapabilities({...data,available:true});await loadAdminCameras();await loadCameras();}catch(error){$('#capability-error').textContent=`Erkennung fehlgeschlagen: ${error.code}`;}
  }

  async function loadUsers(){
    if(!appState.permissions.manageUsers)return;
    try{const data=await api('/api/admin/users');appState.users=data.users||[];renderUsers();}catch(error){toast(`Benutzer konnten nicht geladen werden: ${error.code}`);}
  }
  function renderUsers(){
    const list=$('#user-list');list.replaceChildren();appState.users.forEach(user=>{const self=user.id===appState.user?.id,row=document.createElement('article');row.className='user-row';row.dataset.enabled=String(user.enabled);row.innerHTML=`<div class="user-identity"><div class="user-avatar">${escapeHtml((user.displayName||user.username).slice(0,2).toUpperCase())}</div><div><h3>${escapeHtml(user.displayName)}</h3><div class="user-meta"><span>@${escapeHtml(user.username)}</span><span class="role-badge" data-role="${user.role}">${ROLE_LABELS[user.role]}</span><span>${user.enabled?'Aktiv':'Deaktiviert'}</span>${self?'<span>Ihr Konto</span>':''}</div></div></div><div class="user-actions"><select data-role aria-label="Rolle von ${escapeHtml(user.displayName)}" ${self?'disabled':''}><option value="viewer">Betrachter</option><option value="admin">Administrator</option><option value="owner">Eigentümer</option></select><button data-password>Passwort setzen</button><button data-toggle ${self?'disabled':''}>${user.enabled?'Deaktivieren':'Aktivieren'}</button><button data-remove ${self?'disabled':''}>Entfernen</button></div>`;const role=$('select[data-role]',row);role.value=user.role;role.addEventListener('change',()=>patchUser(user,{role:role.value}));$('[data-password]',row).addEventListener('click',()=>openPasswordDialog(user));$('[data-toggle]',row).addEventListener('click',()=>patchUser(user,{enabled:!user.enabled}));$('[data-remove]',row).addEventListener('click',()=>removeUser(user));list.append(row);});
  }
  async function patchUser(user,changes){try{await adminApi(`/api/admin/users/${encodeURIComponent(user.id)}`,{method:'PATCH',body:JSON.stringify(changes)});toast('Benutzer aktualisiert');await loadUsers();}catch(error){toast(`Änderung fehlgeschlagen: ${error.code}`);await loadUsers();}}
  function openPasswordDialog(user){const form=$('#password-form');form.reset();form.elements.userId.value=user.id;$('#password-title').textContent=`Passwort für ${user.displayName} setzen`;$('#password-error').textContent='';$('#password-dialog').showModal();}
  async function removeUser(user){if(!window.confirm(`Benutzer „${user.displayName}“ wirklich entfernen?`))return;try{await adminApi(`/api/admin/users/${encodeURIComponent(user.id)}`,{method:'DELETE'});toast('Benutzer entfernt');await loadUsers();}catch(error){toast(`Entfernen fehlgeschlagen: ${error.code}`);}}
  async function createUser(event){event.preventDefault();const form=event.currentTarget,data=new FormData(form),payload=Object.fromEntries(data.entries());if(payload.password!==payload.confirmation){$('#user-error').textContent='Die Passwörter stimmen nicht überein.';return;}delete payload.confirmation;try{await adminApi('/api/admin/users',{method:'POST',body:JSON.stringify(payload)});form.reset();$('#user-dialog').close();toast('Benutzer angelegt');await loadUsers();}catch(error){$('#user-error').textContent=`Anlegen fehlgeschlagen: ${error.code}`;}}
  async function saveUserPassword(event){event.preventDefault();const form=event.currentTarget;if(form.elements.password.value!==form.elements.confirmation.value){$('#password-error').textContent='Die Passwörter stimmen nicht überein.';return;}try{await adminApi(`/api/admin/users/${encodeURIComponent(form.elements.userId.value)}/password`,{method:'POST',body:JSON.stringify({password:form.elements.password.value})});form.reset();$('#password-dialog').close();toast('Passwort gespeichert; bestehende Sitzungen wurden beendet');}catch(error){$('#password-error').textContent=`Speichern fehlgeschlagen: ${error.code}`;}}
  async function changeOwnPassword(event){event.preventDefault();const form=event.currentTarget;if(form.elements.newPassword.value!==form.elements.confirmation.value){$('#own-password-error').textContent='Die Passwörter stimmen nicht überein.';return;}try{await api('/api/auth/change-password',{method:'POST',body:JSON.stringify({currentPassword:form.elements.currentPassword.value,newPassword:form.elements.newPassword.value})});form.reset();$('#own-password-dialog').close();toast('Ihr Passwort wurde geändert');}catch(error){$('#own-password-error').textContent=error.code==='current-password-invalid'?'Das aktuelle Passwort ist nicht korrekt.':`Änderung fehlgeschlagen: ${error.code}`;}}

  async function startScan(){
    $('#scan-progress').hidden=false;$('#start-scan').disabled=true;$('#discovery-list').replaceChildren();
    try{const scan=await adminApi('/api/admin/discovery/scans',{method:'POST'});appState.scanId=scan.id;$('#cancel-scan').hidden=false;pollScan(scan.id);}catch(error){$('#scan-progress').hidden=true;$('#start-scan').disabled=false;toast(`Suche nicht gestartet: ${error.code}`);}
  }
  async function cancelScan(){if(!appState.scanId)return;clearTimeout(appState.scanTimer);try{await adminApi(`/api/admin/discovery/scans/${encodeURIComponent(appState.scanId)}`,{method:'DELETE'});}catch{}appState.scanId=null;appState.scanTimer=null;$('#scan-progress').hidden=true;$('#cancel-scan').hidden=true;$('#start-scan').disabled=false;toast('Kamerasuche beendet');}
  async function pollScan(id){if(id!==appState.scanId)return;try{const scan=await api(`/api/admin/discovery/scans/${id}`);renderDiscovery(scan.results||[],id,scan.state!=='complete');$('#scan-progress span').textContent=`Netzwerk wird kontrolliert durchsucht … ${scan.completedHosts||0}/${scan.totalHosts||254}`;if(scan.state==='complete'){clearTimeout(appState.scanTimer);appState.scanTimer=null;appState.scanId=null;$('#scan-progress').hidden=true;$('#cancel-scan').hidden=true;$('#start-scan').disabled=false;renderDiscovery(scan.results||[],id,false);return;}if(['failed','cancelled'].includes(scan.state)){throw new Error('scan-failed');}}catch{clearTimeout(appState.scanTimer);appState.scanTimer=null;appState.scanId=null;$('#scan-progress').hidden=true;$('#cancel-scan').hidden=true;$('#start-scan').disabled=false;toast('Netzwerksuche fehlgeschlagen');return;}appState.scanTimer=setTimeout(()=>pollScan(id),1800);}
  async function openConfiguredDiscovery(item){if(!appState.adminCameras.length)await loadAdminCameras();const camera=appState.adminCameras.find(candidate=>candidate.id===item.configuredCameraId);if(camera)openConnectionDialog(camera);else toast('Gespeicherte Kamera konnte nicht geladen werden');}
  function renderDiscovery(items,scanId,running=false){const list=$('#discovery-list');list.replaceChildren();if(!items.length){list.innerHTML=running?'<div class="empty-state"><h3>Suche läuft</h3><p>Treffer erscheinen bereits während der Prüfung.</p></div>':'<div class="empty-state"><h3>Keine standardisierte Kamera gefunden</h3><p>Sie können eine bekannte RTSP-, HLS-, MJPEG- oder Snapshot-Quelle manuell hinzufügen.</p></div>';return;}items.forEach(item=>{const row=document.createElement('article');row.className='device-row';const protocols=[item.onvif?'ONVIF':'',item.rtsp?'RTSP':''].filter(Boolean),profile=item.profiles?.[0],details=profile?[profile.codec?.toUpperCase(),profile.width&&profile.height?`${profile.width}×${profile.height}`:''].filter(Boolean).join(' · '):'Profile nach Anmeldung prüfen';const configured=Boolean(item.configuredCameraId);row.innerHTML=`${item.previewAvailable?`<img class="device-preview" src="/api/admin/discovery/scans/${encodeURIComponent(scanId)}/devices/${encodeURIComponent(item.id)}/preview" alt="Vorschau ${escapeHtml(item.model)}">`:'<div class="device-preview is-empty">Keine Vorschau</div>'}<div><h3>${escapeHtml(item.manufacturer)} ${escapeHtml(item.model)}</h3><div class="device-meta"><span>${escapeHtml(item.address)}</span>${protocols.map(value=>`<span class="protocol-pill">${value}</span>`).join('')}<span>${escapeHtml(details)}</span><span>Ports: ${item.openPorts.join(', ')}</span>${configured?`<span class="connection-badge">Bereits hinzugefügt: ${escapeHtml(item.configuredName||'Kamera')}</span>`:''}</div></div><button class="primary">${configured?'Verbindung bearbeiten':'Auswählen'}</button>`;$('button',row).addEventListener('click',()=>configured?openConfiguredDiscovery(item):openCameraDialog(item));list.append(row);});}
  function openCameraDialog(item={}){const form=$('#camera-form'),profile=item.profiles?.[0];form.reset();form.elements.name.value=item.model&&item.model!=='Unbekannt'?item.model:'Neue Kamera';form.elements.address.value=item.address||'';form.elements.port.value=item.rtsp?(item.openPorts?.find(port=>[554,8554,10554].includes(port))||554):554;form.elements.lowSourcePath.value=profile?.streamPath||'';if(['h264','h265','mjpeg'].includes(profile?.codec))form.elements.codec.value=profile.codec;form.elements.manufacturer.value=item.manufacturer||'';form.elements.model.value=item.model||'';$('#source-test').textContent='Bitte testen Sie die Quelle vor dem Hinzufügen.';$('#camera-error').textContent='';form.dataset.tested='false';$('#camera-dialog').showModal();}
  function cameraPayload(){const form=$('#camera-form'),data=new FormData(form);return Object.fromEntries([...data.entries()].map(([key,value])=>[key,key==='port'?Number(value):value]));}
  async function testSource(){const payload=cameraPayload();$('#source-test').textContent='Quelle wird gelesen …';try{const result=await adminApi('/api/admin/cameras/test-source',{method:'POST',body:JSON.stringify(payload)});if(!result.ok)throw new Error(result.error);$('#camera-form').dataset.tested='true';$('#source-test').textContent=`Videoframes bestätigt · ${String(result.codec).toUpperCase()} · ${result.width}×${result.height} · ${result.packets} Pakete`;}catch(error){$('#camera-form').dataset.tested='false';$('#source-test').textContent=`Kein Frame-Nachweis: ${error.code||error.message}`;}}
  async function addCamera(event){event.preventDefault();const form=event.currentTarget;if(form.dataset.tested!=='true'){ $('#camera-error').textContent='Bitte zuerst einen erfolgreichen Frame-Test durchführen.';return;}try{await adminApi('/api/admin/cameras',{method:'POST',body:JSON.stringify(cameraPayload())});form.reset();$('#camera-dialog').close();toast('Kamera wurde hinzugefügt');await loadAdminCameras();await loadCameras();showView('overview');}catch(error){$('#camera-error').textContent=`Hinzufügen fehlgeschlagen: ${error.code||'unerwarteter-fehler'}`;}}

  const zoneState={cameraId:'',revision:0,zones:[],draft:[],kind:'alarm',request:0};
  function populateZoneSelect(){const select=$('#zone-camera'),current=select.value;select.replaceChildren();appState.cameras.forEach(camera=>{const option=new Option(camera.name,camera.id);select.add(option);});if(appState.cameras.some(camera=>camera.id===current))select.value=current;}
  async function loadZoneCamera(){const id=$('#zone-camera').value||appState.cameras[0]?.id;if(!id)return;const request=++zoneState.request;zoneState.cameraId=id;zoneState.draft=[];zoneState.zones=[];renderZoneList();$('#zone-empty').hidden=false;$('#zone-empty').textContent='Vorschau wird geladen';const image=$('#zone-preview');image.hidden=true;image.onload=()=>{if(request!==zoneState.request||zoneState.cameraId!==id)return;$('#zone-empty').hidden=true;image.hidden=false;resizeCanvas();};image.onerror=()=>{if(request!==zoneState.request||zoneState.cameraId!==id)return;$('#zone-empty').textContent='Keine Vorschau verfügbar – die Quelle bleibt unverändert.';resizeCanvas();};image.src=`/api/admin/cameras/${encodeURIComponent(id)}/preview?t=${Date.now()}`;try{const data=await api(`/api/admin/cameras/${encodeURIComponent(id)}/zones`);if(request!==zoneState.request||zoneState.cameraId!==id)return;zoneState.revision=data.revision;zoneState.zones=data.zones;renderZoneList();drawZones();}catch(error){if(request===zoneState.request)toast(`Zonen konnten nicht geladen werden: ${error.code}`);}}
  function resizeCanvas(){const canvas=$('#zone-canvas'),rect=canvas.getBoundingClientRect(),dpr=Math.min(devicePixelRatio||1,2);canvas.width=Math.max(1,Math.round(rect.width*dpr));canvas.height=Math.max(1,Math.round(rect.height*dpr));drawZones();}
  function zoneImageRect(){const canvas=$('#zone-canvas'),image=$('#zone-preview'),rect=canvas.getBoundingClientRect(),dpr=canvas.width/Math.max(1,rect.width);if(image.hidden||!image.naturalWidth||!image.naturalHeight)return{x:0,y:0,width:canvas.width,height:canvas.height,dpr};const scale=Math.min(rect.width/image.naturalWidth,rect.height/image.naturalHeight),width=image.naturalWidth*scale*dpr,height=image.naturalHeight*scale*dpr;return{x:(canvas.width-width)/2,y:(canvas.height-height)/2,width,height,dpr};}
  function drawPolygon(context,points,kind,draft=false){if(!points.length)return;const area=zoneImageRect();context.beginPath();points.forEach((point,index)=>{const x=area.x+point.x*area.width,y=area.y+point.y*area.height;index?context.lineTo(x,y):context.moveTo(x,y);});if(!draft&&points.length>2)context.closePath();context.strokeStyle=kind==='alarm'?'#ffbd63':'#6aa7ff';context.fillStyle=kind==='alarm'?'#ffbd6326':'#6aa7ff26';context.lineWidth=3*area.dpr;if(!draft)context.fill();context.stroke();points.forEach(point=>{context.beginPath();context.arc(area.x+point.x*area.width,area.y+point.y*area.height,5*area.dpr,0,Math.PI*2);context.fillStyle=context.strokeStyle;context.fill();});}
  function drawZones(){const canvas=$('#zone-canvas'),context=canvas.getContext('2d');context.clearRect(0,0,canvas.width,canvas.height);zoneState.zones.filter(zone=>zone.enabled).forEach(zone=>drawPolygon(context,zone.points,zone.kind));drawPolygon(context,zoneState.draft,zoneState.kind,true);}
  function addZonePoint(event){const canvas=$('#zone-canvas'),rect=canvas.getBoundingClientRect(),area=zoneImageRect(),dpr=area.dpr,x=(event.clientX-rect.left)*dpr,y=(event.clientY-rect.top)*dpr;if(x<area.x||x>area.x+area.width||y<area.y||y>area.y+area.height){toast('Bitte einen Punkt innerhalb des Kamerabilds setzen');return;}zoneState.draft.push({x:(x-area.x)/area.width,y:(y-area.y)/area.height});drawZones();}
  function addZoneCoordinate(){const x=Number($('#zone-x').value),y=Number($('#zone-y').value);if(!Number.isFinite(x)||!Number.isFinite(y)||x<0||x>100||y<0||y>100){toast('Koordinaten müssen zwischen 0 und 100 liegen');return;}zoneState.draft.push({x:x/100,y:y/100});drawZones();toast('Zonenpunkt hinzugefügt');}
  function completeZone(){if(zoneState.draft.length<3){toast('Mindestens drei Punkte erforderlich');return;}zoneState.zones.push({id:null,name:$('#zone-name').value.trim()||'Zone',kind:zoneState.kind,points:[...zoneState.draft],enabled:true});zoneState.draft=[];renderZoneList();drawZones();}
  function renderZoneList(){const list=$('#zone-list');list.replaceChildren();zoneState.zones.forEach((zone,index)=>{const row=document.createElement('div');row.className='zone-entry';row.dataset.kind=zone.kind;row.innerHTML=`<i class="zone-color"></i><span>${escapeHtml(zone.name)} · ${zone.kind==='alarm'?'Alarm':'Alarmfrei'}</span><label class="zone-enabled"><input type="checkbox" ${zone.enabled?'checked':''}> Aktiv</label><button aria-label="Zone löschen">×</button>`;$('input',row).addEventListener('change',event=>{zone.enabled=event.currentTarget.checked;drawZones();});$('button',row).addEventListener('click',()=>{zoneState.zones.splice(index,1);renderZoneList();drawZones();});list.append(row);});}
  async function saveZones(){const button=$('#zone-save');if(button.disabled)return;button.disabled=true;button.setAttribute('aria-busy','true');try{const result=await adminApi(`/api/admin/cameras/${encodeURIComponent(zoneState.cameraId)}/zones`,{method:'PUT',body:JSON.stringify({revision:zoneState.revision,zones:zoneState.zones})});zoneState.revision=result.revision;toast('Zonen wurden gespeichert');}catch(error){toast(`Speichern fehlgeschlagen: ${error.code}`);}finally{button.disabled=false;button.removeAttribute('aria-busy');}}

  function refreshDiagnostics(){const video=document.createElement('video');$('#diag-secure').textContent=window.isSecureContext?'Ja':'Nein';$('#diag-sw').textContent='serviceWorker'in navigator?(navigator.serviceWorker.controller?'Aktiv':'Verfügbar'):'Nicht verfügbar';$('#diag-webrtc').textContent='RTCPeerConnection'in window?'Verfügbar':'Nicht verfügbar';$('#diag-hls').textContent=video.canPlayType('application/vnd.apple.mpegurl')?'Nativ':'Gateway-Fallback';$('#diag-backend').textContent=appState.csrf?'Angemeldet':'Nicht angemeldet';$('#diag-origin').textContent=location.origin;$('#diag-version').textContent=VERSION;}

  function bindEvents(){
    $('#menu-button').addEventListener('click',()=>$('#app-menu').classList.contains('is-open')?closeMenu():openMenu());$('#menu-close').addEventListener('click',()=>closeMenu());$('#menu-backdrop').addEventListener('click',()=>closeMenu());$$('.nav-item').forEach(item=>item.addEventListener('click',()=>showView(item.dataset.view)));
    document.addEventListener('keydown',(event)=>{if(event.key==='Escape'&&appState.wallMode){event.preventDefault();exitWallMode();return;}if(event.key==='Escape'&&$('#app-menu').classList.contains('is-open'))closeMenu();if(event.key==='Tab'&&$('#app-menu').classList.contains('is-open')){const focusable=$$('button:not([disabled])',$('#app-menu'));const first=focusable[0],last=focusable.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}}});
    $$('dialog').forEach(dialog=>dialog.addEventListener('cancel',event=>{if(dialog.dataset.static==='true'){event.preventDefault();return;}if(dialog.id==='reauth-dialog')reauthResolver?.(false);}));
    $('#auth-form').addEventListener('submit',async(event)=>{event.preventDefault();const setup=$('#auth-dialog').dataset.setup==='true',body={username:$('#auth-user').value,password:$('#auth-password').value};try{const result=await api(setup?'/api/auth/setup':'/api/auth/login',{method:'POST',body:JSON.stringify(body)});applyAccess(result);$('#auth-password').value='';$('#auth-dialog').close();$('#app').hidden=false;await loadCameras();refreshDiagnostics();if(location.hash==='#wall')enterWallMode(false);}catch(error){$('#auth-error').textContent=error.code==='login-failed'?'Anmeldung fehlgeschlagen.':`Fehler: ${error.code}`;}});
    $('#reauth-form').addEventListener('submit',async(event)=>{event.preventDefault();try{const result=await api('/api/auth/reauth',{method:'POST',body:JSON.stringify({password:$('#reauth-password').value})});appState.elevatedUntil=result.elevatedUntil;$('#reauth-dialog').close();reauthResolver?.(true);}catch{$('#reauth-error').textContent='Passwort nicht bestätigt.';}});$$('[data-close-dialog]').forEach(button=>button.addEventListener('click',()=>{const dialog=button.closest('dialog');dialog.close();if(dialog.id==='reauth-dialog')reauthResolver?.(false);}));
    $('#logout').addEventListener('click',async()=>{clearTimeout(appState.scanTimer);appState.scanTimer=null;appState.scanId=null;exitWallMode();try{await api('/api/auth/logout',{method:'POST'});}catch{}appState.csrf='';appState.user=null;appState.permissions={};suspend();$('#app').hidden=true;showAuth(false);closeMenu(false);});
    const enterWall=$('#enter-wall-mode'),exitWall=$('#exit-wall-mode');if(enterWall&&exitWall){enterWall.addEventListener('click',()=>enterWallMode(true));exitWall.addEventListener('click',()=>exitWallMode());exitWall.addEventListener('blur',revealWallControls);}document.addEventListener('pointermove',revealWallControls,{passive:true});document.addEventListener('touchstart',revealWallControls,{passive:true});document.addEventListener('fullscreenchange',()=>{if(appState.wallMode&&!document.fullscreenElement)exitWallMode({leaveFullscreen:false});});
    $('#refresh-all').addEventListener('click',loadHealth);$('#detail-back').addEventListener('click',closeDetail);$('#detail-reconnect').addEventListener('click',()=>{if(!appState.detail)return;appState.detail.camera.displayMode==='snapshot'?startSnapshot(appState.detail,true):connect(appState.detail,appState.detail.path,appState.detail.mode,true);});$('#detail-fallback').addEventListener('click',()=>{if(!appState.detail)return;$('#detail-quality').textContent='Substream';connect(appState.detail,appState.detail.camera.lowPath,'low',true);});$('#detail-hls-toggle').addEventListener('click',()=>{if(!appState.detail)return;closeReader(appState.detail,false);$('#detail-video').hidden=true;const frame=$('#detail-hls');frame.hidden=false;frame.src=hlsUrl(appState.detail.camera.lowPath);mark(appState.detail,'loading','HLS-Fallback lädt');});$('#detail-hls').addEventListener('load',()=>{if(appState.detail)mark(appState.detail,'live','Live · HLS-Fallback');});$('#detail-message').addEventListener('click',()=>resumePlayback(appState.detail));$('#detail-video').addEventListener('click',()=>resumePlayback(appState.detail));$('#detail-audio').addEventListener('click',toggleDetailAudio);$('#detail-fullscreen').addEventListener('click',()=>{const shell=$('#detail-shell'),video=$('#detail-video');if(shell.requestFullscreen)shell.requestFullscreen();else video.webkitEnterFullscreen?.();});
    $$('[data-ptz-x]').forEach(button=>{button.addEventListener('pointerdown',event=>{event.preventDefault();button.setPointerCapture?.(event.pointerId);startPTZ(button);});for(const name of ['pointerup','pointercancel','pointerleave'])button.addEventListener(name,stopPTZ);button.addEventListener('keydown',event=>{if((event.key===' '||event.key==='Enter')&&!event.repeat){event.preventDefault();startPTZ(button);}});button.addEventListener('keyup',event=>{if(event.key===' '||event.key==='Enter')stopPTZ();});button.addEventListener('blur',stopPTZ);});$('[data-ptz-stop]').addEventListener('click',stopPTZ);$('#ptz-presets').addEventListener('change',gotoPreset);
    $('#start-scan').addEventListener('click',startScan);$('#cancel-scan').addEventListener('click',cancelScan);$('#manual-add').addEventListener('click',()=>openCameraDialog());$('#test-source').addEventListener('click',testSource);$('#camera-form').addEventListener('submit',addCamera);for(const name of ['input','change'])$('#camera-form').addEventListener(name,()=>{$('#camera-form').dataset.tested='false';$('#source-test').textContent='Verbindungsdaten geändert · bitte erneut testen.';});$('#credential-mode').addEventListener('change',updateCredentialFields);$('#connection-test-button').addEventListener('click',testConnection);$('#connection-form').addEventListener('submit',saveConnection);for(const name of ['input','change'])$('#connection-form').addEventListener(name,()=>{$('#connection-form').dataset.tested='false';$('#connection-test').dataset.state='';$('#connection-test').textContent='Verbindungsdaten geändert · bitte erneut prüfen.';});$('#connection-activate').addEventListener('click',activateConnection);$('#capability-refresh').addEventListener('click',refreshCapabilities);$('#zone-camera').addEventListener('change',loadZoneCamera);$('#zone-canvas').addEventListener('pointerdown',addZonePoint);$('#zone-add-coordinate').addEventListener('click',addZoneCoordinate);$$('[data-zone-kind]').forEach(button=>button.addEventListener('click',()=>{$$('[data-zone-kind]').forEach(item=>item.classList.remove('is-active'));button.classList.add('is-active');zoneState.kind=button.dataset.zoneKind;}));$('#zone-undo').addEventListener('click',()=>{zoneState.draft.pop();drawZones();});$('#zone-complete').addEventListener('click',completeZone);$('#zone-save').addEventListener('click',saveZones);window.addEventListener('resize',resizeCanvas);
    $('#add-user').addEventListener('click',()=>{$('#user-form').reset();$('#user-error').textContent='';$('#user-dialog').showModal();});$('#user-form').addEventListener('submit',createUser);$('#password-form').addEventListener('submit',saveUserPassword);$('#change-own-password').addEventListener('click',()=>{$('#own-password-form').reset();$('#own-password-error').textContent='';$('#own-password-dialog').showModal();});$('#own-password-form').addEventListener('submit',changeOwnPassword);
    document.addEventListener('visibilitychange',()=>document.hidden?suspend():resume());window.addEventListener('pagehide',suspend);window.addEventListener('pageshow',resume);window.addEventListener('focus',resume);window.addEventListener('blur',stopPTZ);window.addEventListener('offline',suspend);window.addEventListener('online',resume);
  }

  window.addEventListener('load',async()=>{
    bindEvents();refreshDiagnostics();appState.observer=new IntersectionObserver(entries=>entries.forEach(entry=>{const state=appState.states.get(entry.target.dataset.cameraId);if(!state)return;state.visible=entry.isIntersecting;if(appState.detail)return;if(state.visible)state.camera.displayMode==='snapshot'?startSnapshot(state,true):connect(state,state.camera.lowPath,'low',true);else closeReader(state);}),{threshold:.2,rootMargin:'100px'});
    try{await initializeAuth();}catch{showAuth(false);}
    if('serviceWorker'in navigator){let reloadingForUpdate=false;navigator.serviceWorker.addEventListener('controllerchange',()=>{if(reloadingForUpdate)return;reloadingForUpdate=true;location.reload();});navigator.serviceWorker.register('./sw.js').then(refreshDiagnostics).catch(()=>{});}
    const initial=location.hash.slice(1);if(initial==='wall'&&appState.csrf)enterWallMode(false);else if(['discover','manage','zones','users','system'].includes(initial)&&appState.csrf)showView(initial);
  });
})();
