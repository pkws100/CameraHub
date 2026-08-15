(() => {
  'use strict';
  const VERSION = '1.7.0-dev';
  const RETRY_DELAYS = [2000, 5000, 15000];
  const appState = { csrf:'', user:null, permissions:{}, users:[], cameras:[], camerasLoaded:false, adminCameras:[], cloudAccounts:[], cloudProviders:[], displayProfiles:[], profileCameraOptions:[], displayProfileId:'', renderedDisplayProfileId:'', profileDraftOrder:[], profileDraftModes:{}, profileDraftSchedules:[], displayDevices:[], displayDeviceProfileOptions:[], displayDeviceDraftProfiles:[], cameraRequest:0, states:new Map(), observer:null, detail:null, suspended:false, wallMode:false, wallControlsTimer:null, elevatedUntil:0, scanTimer:null, scanId:null, discoveryItems:[], discoveryResultScanId:null, discoveryDevice:null, cloudImportContext:null, connectionCamera:null, connectionRollout:null, connectionRequest:0, capabilityCamera:null, capabilityRequest:0, ptz:null, webhookTargets:[], restoreValidated:false, detection:null, motionSource:null, motionAlert:null, recordings:{sources:[],cameraId:'',items:[],leaseId:null,request:0} };
  const $ = (selector, root=document) => root.querySelector(selector);
  const $$ = (selector, root=document) => [...root.querySelectorAll(selector)];
  const mediaHost = location.hostname;
  const sameOriginMedia = !['127.0.0.1', 'localhost'].includes(mediaHost);
  const whepUrl = (path) => sameOriginMedia ? `${location.origin}/whep/${encodeURIComponent(path)}/whep` : `http://${mediaHost}:8889/${encodeURIComponent(path)}/whep`;
  const hlsUrl = (path) => sameOriginMedia ? `${location.origin}/hls/${encodeURIComponent(path)}/?autoplay=true&muted=true&controls=true&playsInline=true` : `http://${mediaHost}:8888/${encodeURIComponent(path)}/?autoplay=true&muted=true&controls=true&playsInline=true`;
  const toast = (message) => { const node=$('#toast'); node.textContent=message; node.hidden=false; clearTimeout(node.timer); node.timer=setTimeout(()=>node.hidden=true,3500); };
  const relativeTime = (value) => value ? new Intl.DateTimeFormat('de-DE',{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date(value)) : '–';
  function hashRoute(){
    const fragment=location.hash.slice(1),separator=fragment.indexOf('?'),view=(separator<0?fragment:fragment.slice(0,separator))||'overview',params=new URLSearchParams(separator<0?'':fragment.slice(separator+1));
    return {view,profileId:params.get('profile')||''};
  }
  function liveHash(view=appState.wallMode?'wall':'overview'){
    const profile=appState.displayProfileId?`?profile=${encodeURIComponent(appState.displayProfileId)}`:'';
    return `#${view}${profile}`;
  }

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
    reauthPromise=new Promise((resolve,reject)=>{reauthResolver=(ok)=>{reauthResolver=null;reauthPromise=null;ok?resolve():reject(new ApiError(0,'reauth-cancelled'));};});
    return reauthPromise;
  }
  async function adminApi(path,options={},reauthTransition={}){
    try { return await api(path,options); }
    catch(error){ if(error.code!=='reauth-required') throw error; reauthTransition.before?.(); await requestReauth(); reauthTransition.after?.(); return api(path,options); }
  }
  async function ownerFetch(path,options={}){
    const send=async()=>{
      const method=options.method||'GET',headers=new Headers(options.headers||{});
      if(!['GET','HEAD'].includes(method)&&appState.csrf)headers.set('X-CSRF-Token',appState.csrf);
      if(options.body&&!((options.body) instanceof FormData)&&!headers.has('Content-Type'))headers.set('Content-Type','application/json');
      const response=await fetch(path,{...options,headers,credentials:'same-origin',cache:'no-store'});
      if(response.ok)return response;
      let data={};try{data=await response.clone().json();}catch{}
      throw new ApiError(response.status,data.detail||`http-${response.status}`);
    };
    try{return await send();}catch(error){if(error.code!=='reauth-required')throw error;await requestReauth();return send();}
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
    if(name!=='recordings')stopRecordingPlayback();
    const permission={discover:'discoverCameras',manage:'manageCameras',zones:'manageZones',users:'manageUsers'}[name];
    if(permission&&!appState.permissions[permission])name='overview';
    if(appState.detail) closeDetail();
    $$('.view').forEach((view)=>{ const active=view.dataset.view===name; view.hidden=!active; view.classList.toggle('is-active',active); });
    $$('.nav-item').forEach((item)=>item.classList.toggle('is-active',item.dataset.view===name));
    closeMenu(false); history.replaceState(null,'',name==='overview'?liveHash('overview'):`#${name}`);const heading=$(`#view-${name} h2`);if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}
    if(name==='overview'&&!appState.camerasLoaded)loadCameras();if(name==='recordings')loadRecordingSources();if(name==='discover') loadCloudAccounts(); if(name==='manage') loadAdminCameras(); if(name==='zones') loadZoneCamera(); if(name==='users') loadUsers(); if(name==='system'){refreshDiagnostics();loadOperations();}
  }

  function revealWallControls(){
    if(!appState.wallMode)return;
    document.body.classList.add('wall-controls-visible');
    clearTimeout(appState.wallControlsTimer);
    appState.wallControlsTimer=setTimeout(()=>{
      if(!$('#wall-controls').contains(document.activeElement))document.body.classList.remove('wall-controls-visible');
    },3500);
  }
  function updateWallGridLayout(){
    if(!appState.wallMode)return;
    const grid=$('#camera-grid'),count=Math.max(0,appState.cameras.length);
    if(!grid)return;
    if(count<=1){
      grid.style.setProperty('--wall-columns','1');
      grid.style.setProperty('--wall-rows','1');
      return;
    }
    const width=Math.max(1,window.innerWidth),height=Math.max(1,window.innerHeight);
    const portrait=height>width;
    const minColumns=portrait?(count<=2?1:2):(count<=3?count:2);
    const maxColumns=Math.min(count,portrait?4:8);
    let best={columns:minColumns,rows:Math.ceil(count/minColumns),score:Number.POSITIVE_INFINITY};
    for(let columns=minColumns;columns<=maxColumns;columns+=1){
      const rows=Math.ceil(count/columns);
      const tileAspect=(width/columns)/(height/rows);
      const emptyCells=(columns*rows-count)/(columns*rows);
      const score=Math.abs(Math.log(tileAspect/(16/9)))+emptyCells*.18;
      if(score<best.score)best={columns,rows,score};
    }
    grid.style.setProperty('--wall-columns',String(best.columns));
    grid.style.setProperty('--wall-rows',String(best.rows));
  }
  function enterWallMode(nativeFullscreen=true){
    const enterButton=$('#enter-wall-mode'),controls=$('#wall-controls');if(!appState.csrf||appState.wallMode||!enterButton||!controls)return;
    closeMenu(false);appState.wallMode=true;document.body.classList.add('wall-mode');controls.hidden=false;enterButton.setAttribute('aria-pressed','true');document.title='Camera Hub · Leitstelle';history.replaceState(null,'',liveHash('wall'));updateWallGridLayout();revealWallControls();
    appState.states.forEach(state=>{state.visible=true;if(state.camera.displayMode==='explicit')startSnapshot(state,true);else if(!state.reader&&state.camera.displayMode!=='snapshot')connect(state,state.camera.lowPath,'low',true);});
    if(nativeFullscreen&&!document.fullscreenElement&&document.documentElement.requestFullscreen)document.documentElement.requestFullscreen().catch(()=>{});
  }
  function exitWallMode({leaveFullscreen=true,updateHistory=true}={}){
    if(!appState.wallMode)return;
    appState.wallMode=false;clearTimeout(appState.wallControlsTimer);appState.wallControlsTimer=null;document.body.classList.remove('wall-mode','wall-controls-visible');const controls=$('#wall-controls'),enterButton=$('#enter-wall-mode');if(controls)controls.hidden=true;if(enterButton)enterButton.setAttribute('aria-pressed','false');document.title='PKWS Camera Hub';if(updateHistory)history.replaceState(null,'',liveHash('overview'));
    if(leaveFullscreen&&document.fullscreenElement&&document.exitFullscreen)document.exitFullscreen().catch(()=>{});
  }

  function closeReader(state,release=true){
    if(!state) return; clearTimeout(state.retryTimer); clearTimeout(state.startupTimer); clearTimeout(state.snapshotTimer); clearTimeout(state.hlsTimer); state.retryTimer=state.startupTimer=state.snapshotTimer=state.hlsTimer=null;if(release){clearTimeout(state.explicitTimer);state.explicitTimer=null;} state.generation+=1;
    if(state.reader) state.reader.close(); state.reader=null; state.video?.pause(); if(state.video) state.video.srcObject=null;
    if(state.snapshot){state.snapshot.onload=null;state.snapshot.onerror=null;state.snapshot.removeAttribute('src');}
    if(release){clearTimeout(state.leaseTimer);state.leaseTimer=null;}
    if(release && state.camera?.id && state.leaseId && appState.csrf){
      const leaseId=state.leaseId;state.leaseId=null;
      api(`/api/cameras/${encodeURIComponent(state.camera.id)}/lease?leaseId=${encodeURIComponent(leaseId)}`,{method:'DELETE'}).catch(()=>{});
    }
    if(release&&state.camera?.explicitLiveOnly)state.explicitStarted=false;
  }
  function scheduleLeaseRenewal(state){
    clearTimeout(state.leaseTimer);state.leaseTimer=null;
    if(!state.leaseId||!appState.csrf)return;
    const cameraId=state.camera.id,leaseId=state.leaseId;
    state.leaseTimer=setTimeout(async()=>{
      if(state.leaseId!==leaseId)return;
      try{
        const renewed=await api(`/api/cameras/${encodeURIComponent(cameraId)}/lease?leaseId=${encodeURIComponent(leaseId)}`,{method:'PUT'});
        if(renewed.maxExpiresAt)state.maxExpiresAt=renewed.maxExpiresAt;
        if(state.leaseId===leaseId)scheduleLeaseRenewal(state);
      }catch(error){
        if(state.leaseId===leaseId){state.leaseId=null;state.leaseTimer=null;if(state.camera?.explicitLiveOnly){state.explicitStarted=false;clearTimeout(state.explicitTimer);state.explicitTimer=null;closeReader(state,false);mark(state,'loading',error.code==='blink-live-session-expired'?'Blink-Livebild beendet · erneut starten':'Blink-Livebild unterbrochen');}}
      }
    },45000);
  }
  function mark(state,status,text){ state.status.dataset.state=status; const target=state.status.querySelector('.status-text,span:last-child'); if(target) target.textContent=text; if(state.wallStatus){state.wallStatus.dataset.state=status;const wallText=$('span',state.wallStatus);if(wallText)wallText.textContent=status==='live'?'Live':text;} if(state.placeholder) state.placeholder.hidden=status==='live'; }
  async function resumePlayback(state){
    if(!state?.video)return;
    if(!state.video.srcObject){connect(state,state.path,state.mode,true);return;}
    try{await state.video.play();}catch{mark(state,'loading','Zum Start antippen');}
  }
  function stampFrame(state){ state.lastFrameAt=new Date().toISOString(); if(state.lastFrame) state.lastFrame.textContent=relativeTime(state.lastFrameAt); }
  function reportAvailability(state,value,code='stream-unavailable'){
    if(!state?.camera?.onDemand||state.availabilityReported===value||!appState.csrf)return;
    state.availabilityReported=value;
    api(`/api/cameras/${encodeURIComponent(state.camera.id)}/availability`,{method:'POST',body:JSON.stringify({state:value,code})}).catch(()=>{state.availabilityReported='';});
  }
  function watchFrames(state,generation){ if(state.generation!==generation||!state.reader)return; state.firstFrameReceived=true; clearTimeout(state.startupTimer); stampFrame(state); mark(state,'live',state.mode==='high'?'Live · Hauptstream':'Live'); reportAvailability(state,'recovered'); if('requestVideoFrameCallback'in state.video)state.video.requestVideoFrameCallback(()=>watchFrames(state,generation)); }
  function scheduleRetry(state,path,mode){ if(state.retryTimer)return; if(appState.suspended||state.retryCount>=RETRY_DELAYS.length){mark(state,'offline','Erneut verbinden');reportAvailability(state,'failure');return;} const delay=RETRY_DELAYS[state.retryCount++]; mark(state,'loading',`Neuer Versuch in ${delay/1000} s`); state.retryTimer=setTimeout(()=>connect(state,path,mode),delay); }
  async function connect(state,path,mode='low',manual=false){
    closeReader(state,false); if(manual)state.retryCount=0; if(appState.suspended||!navigator.onLine){mark(state,'offline','Netzwerk offline');return;}
    if(state===appState.detail){$('#detail-video').hidden=false; $('#detail-hls').hidden=true; $('#detail-hls').removeAttribute('src');}
    const generation=state.generation; mark(state,'loading','Verbindung wird hergestellt');
    if(state.camera?.explicitLiveOnly&&!state.explicitStarted){mark(state,'loading','Livebild startet nur auf Anforderung');return;}
    if(!state.leaseId)try { const lease=await api(`/api/cameras/${encodeURIComponent(state.camera.id)}/lease`,{method:'POST'});if(state.generation!==generation){api(`/api/cameras/${encodeURIComponent(state.camera.id)}/lease?leaseId=${encodeURIComponent(lease.leaseId)}`,{method:'DELETE'}).catch(()=>{});return;}state.leaseId=lease.leaseId;state.maxExpiresAt=lease.maxExpiresAt||null;if(state.maxExpiresAt){const remaining=Math.max(0,state.maxExpiresAt*1000-Date.now());state.explicitTimer=setTimeout(()=>{if(state.leaseId===lease.leaseId){closeReader(state);mark(state,'loading','Blink-Livebild beendet · erneut starten');startSnapshot(state,true);}},remaining);}scheduleLeaseRenewal(state); } catch(error){ if(error.status===401){showAuth(false);return;}mark(state,'offline',error.code==='blink-system-busy'?'Blink-System ist beschäftigt':`Livebild nicht verfügbar · ${error.code}`);return; }
    else if(!state.leaseTimer)scheduleLeaseRenewal(state);
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
  function watchHlsPlayback(state,generation){
    if(state!==appState.detail||state.generation!==generation)return;
    const frame=$('#detail-hls');if(frame.hidden)return;
    if(!sameOriginMedia){stampFrame(state);mark(state,'live',state.hlsLiveLabel||'Live · HLS');return;}
    const video=frame.contentDocument?.querySelector('video');
    if(video&&video.readyState>=2&&!video.paused&&video.currentTime>0){
      stampFrame(state);mark(state,'live',state.hlsLiveLabel||'Live · HLS');return;
    }
    state.hlsChecks=(state.hlsChecks||0)+1;
    if(state.hlsChecks>=60){mark(state,'offline','HLS-Stream konnte nicht gestartet werden');return;}
    state.hlsTimer=setTimeout(()=>watchHlsPlayback(state,generation),500);
  }
  function startSnapshot(state,manual=false){
    closeReader(state,false);if(manual)state.retryCount=0;if(appState.suspended||!navigator.onLine){mark(state,'offline','Netzwerk offline');return;}
    const generation=state.generation;state.video.hidden=true;state.snapshot.hidden=false;mark(state,'loading','Vorschau wird geladen');
    const refreshDelay=state.camera?.explicitLiveOnly?300000:5000;
    state.snapshot.onload=()=>{if(state.generation!==generation)return;state.retryCount=0;stampFrame(state);mark(state,'live',state.camera?.explicitLiveOnly?'Letzte Blink-Vorschau':'Vorschau aktuell');state.snapshotTimer=setTimeout(()=>startSnapshot(state),refreshDelay);};
    state.snapshot.onerror=()=>{if(state.generation!==generation)return;if(state.retryCount>=RETRY_DELAYS.length){mark(state,'offline','Vorschau nicht erreichbar');return;}const delay=RETRY_DELAYS[state.retryCount++];mark(state,'loading',`Neuer Versuch in ${delay/1000} s`);state.snapshotTimer=setTimeout(()=>startSnapshot(state),delay);};
    state.snapshot.src=`${state.camera.snapshotPath}?t=${Date.now()}`;
  }
  function renderDisplayProfileSelects(){
    for(const select of [$('#display-profile-select'),$('#wall-profile-select')]){
      const selected=appState.displayProfileId;select.replaceChildren(new Option('Alle aktiven Kameras',''));
      appState.displayProfiles.forEach(profile=>select.add(new Option(profile.name,profile.id)));
      select.value=appState.displayProfiles.some(profile=>profile.id===selected)?selected:'';
    }
  }
  async function loadDisplayProfiles(){
    const data=await api('/api/display-profiles');
    appState.displayProfiles=data.profiles||[];appState.profileCameraOptions=data.cameraOptions||[];
    if(appState.displayProfileId&&!appState.displayProfiles.some(profile=>profile.id===appState.displayProfileId))appState.displayProfileId='';
    renderDisplayProfileSelects();
  }
  function applyDisplayProfileFromHash(){
    const requested=hashRoute().profileId;
    if(!requested){appState.displayProfileId='';return;}
    if(appState.displayProfiles.some(profile=>profile.id===requested))appState.displayProfileId=requested;
    else{appState.displayProfileId='';toast('Anzeigeprofil nicht verfügbar · alle aktiven Kameras werden angezeigt');}
    renderDisplayProfileSelects();
  }
  async function selectDisplayProfile(profileId){
    if(profileId&&!appState.displayProfiles.some(profile=>profile.id===profileId)){toast('Anzeigeprofil nicht verfügbar');profileId='';}
    appState.displayProfileId=profileId;renderDisplayProfileSelects();const applied=await loadCameras();if(applied)history.replaceState(null,'',liveHash());return applied;
  }
  async function applyLiveHashNavigation(){
    if(!appState.csrf)return;const route=hashRoute();if(!['overview','wall'].includes(route.view)){if(['recordings','discover','manage','zones','users','system'].includes(route.view))showView(route.view);return;}
    const requested=appState.displayProfiles.some(profile=>profile.id===route.profileId)?route.profileId:'';
    if(route.profileId&&!requested)toast('Anzeigeprofil nicht verfügbar · alle aktiven Kameras werden angezeigt');
    if(requested!==appState.displayProfileId&&!await selectDisplayProfile(requested))return;
    if(appState.detail)closeDetail({updateHistory:false});
    $$('.view').forEach(view=>{const active=view.dataset.view==='overview';view.hidden=!active;view.classList.toggle('is-active',active);});
    $$('.nav-item').forEach(item=>item.classList.toggle('is-active',item.dataset.view==='overview'));
    closeMenu(false);
    if(route.view==='wall'&&!appState.wallMode)enterWallMode(false);
    else if(route.view==='overview'&&appState.wallMode)exitWallMode({updateHistory:false});
    history.replaceState(null,'',liveHash(route.view));
  }
  function renderProfileEditor(profileId=''){
    const profile=appState.displayProfiles.find(item=>item.id===profileId);
    $('#profile-editor-select').value=profile?.id||'';
    $('#profile-name').value=profile?.name||'';
    appState.profileDraftOrder=profile?[...profile.cameraIds]:[];
    appState.profileDraftModes={...(profile?.cameraModes||{})};
    appState.profileDraftSchedules=(profile?.schedules||[]).map(item=>({...item}));
    $('#delete-display-profile').hidden=!profile;$('#copy-profile-live').disabled=!profile;$('#copy-profile-wall').disabled=!profile;
    renderProfileCameraList();renderProfileSchedules();
  }
  function renderProfileEditorSelect(){
    const select=$('#profile-editor-select'),selected=select.value;select.replaceChildren(new Option('Neues Profil',''));
    appState.displayProfiles.forEach(profile=>select.add(new Option(profile.name,profile.id)));
    select.value=appState.displayProfiles.some(profile=>profile.id===selected)?selected:'';
  }
  let profileDragged=null;
  function beginProfileDrag(event){
    profileDragged=event.currentTarget.closest('.profile-camera-row');profileDragged.classList.add('is-dragging');event.currentTarget.setPointerCapture(event.pointerId);event.currentTarget.addEventListener('pointermove',moveProfileDrag);for(const name of ['pointerup','pointercancel','lostpointercapture'])event.currentTarget.addEventListener(name,endProfileDrag,{once:true});
  }
  function moveProfileDrag(event){
    if(!profileDragged)return;const target=document.elementFromPoint(event.clientX,event.clientY)?.closest('.profile-camera-row');if(!target||target===profileDragged||target.dataset.selected!=='true')return;const box=target.getBoundingClientRect();event.clientY<box.top+box.height/2?target.before(profileDragged):target.after(profileDragged);
  }
  function endProfileDrag(event){
    event.currentTarget.removeEventListener('pointermove',moveProfileDrag);for(const name of ['pointerup','pointercancel','lostpointercapture'])event.currentTarget.removeEventListener(name,endProfileDrag);if(!profileDragged)return;profileDragged.classList.remove('is-dragging');appState.profileDraftOrder=$$('.profile-camera-row[data-selected="true"]',$('#profile-camera-list')).map(row=>row.dataset.cameraId);profileDragged=null;renderProfileCameraList();
  }
  function renderProfileCameraList(){
    const list=$('#profile-camera-list');list.replaceChildren();
    const options=new Map(appState.profileCameraOptions.map(camera=>[camera.id,camera]));
    const selected=appState.profileDraftOrder.filter(id=>options.has(id));
    const remaining=appState.profileCameraOptions.filter(camera=>!selected.includes(camera.id)).map(camera=>camera.id);
    [...selected,...remaining].forEach((cameraId)=>{
      const camera=options.get(cameraId),checked=selected.includes(cameraId),index=selected.indexOf(cameraId),row=document.createElement('div');
      row.className='profile-camera-row';row.dataset.enabled=String(camera.enabled);row.dataset.selected=String(checked);row.dataset.cameraId=cameraId;
      row.innerHTML=`<button type="button" class="profile-drag-handle" aria-label="${escapeHtml(camera.name)} verschieben" ${checked?'':'disabled'}>↕</button><label><input type="checkbox" ${checked?'checked':''}><span>${escapeHtml(camera.name)}${camera.enabled?'':'<small>In der Liveansicht deaktiviert</small>'}</span></label><div class="profile-camera-moves"><button type="button" data-direction="-1" aria-label="Nach oben" ${!checked||index===0?'disabled':''}>↑</button><button type="button" data-direction="1" aria-label="Nach unten" ${!checked||index===selected.length-1?'disabled':''}>↓</button></div>`;
      const quality=document.createElement('select');quality.setAttribute('aria-label',`Streamqualität für ${camera.name}`);quality.disabled=!checked;for(const [value,label] of [['auto','Automatisch'],['high','Hauptstream'],['low','Substream'],['hls','HLS-Hauptstream']])quality.add(new Option(label,value));quality.value=appState.profileDraftModes[cameraId]||'auto';quality.addEventListener('change',event=>{appState.profileDraftModes[cameraId]=event.currentTarget.value;});$('label',row).after(quality);
      $('.profile-drag-handle',row).addEventListener('pointerdown',beginProfileDrag);
      $('input',row).addEventListener('change',event=>{if(event.currentTarget.checked)appState.profileDraftOrder.push(cameraId);else appState.profileDraftOrder=appState.profileDraftOrder.filter(id=>id!==cameraId);renderProfileCameraList();});
      $$('[data-direction]',row).forEach(button=>button.addEventListener('click',()=>{const from=appState.profileDraftOrder.indexOf(cameraId),to=from+Number(button.dataset.direction);if(from<0||to<0||to>=appState.profileDraftOrder.length)return;[appState.profileDraftOrder[from],appState.profileDraftOrder[to]]=[appState.profileDraftOrder[to],appState.profileDraftOrder[from]];renderProfileCameraList();}));
      list.append(row);
    });
    if(!appState.profileCameraOptions.length)list.innerHTML='<div class="empty-state">Keine Kameras vorhanden.</div>';
  }
  const scheduleDays=['Montag','Dienstag','Mittwoch','Donnerstag','Freitag','Samstag','Sonntag'];
  const minuteValue=value=>`${String(Math.floor((value%1440)/60)).padStart(2,'0')}:${String(value%60).padStart(2,'0')}`;
  const timeMinute=value=>{const [hour,minute]=String(value).split(':').map(Number);return hour*60+minute;};
  function renderProfileSchedules(){
    const list=$('#profile-schedule-list');list.replaceChildren();
    appState.profileDraftSchedules.forEach((schedule,index)=>{
      const row=document.createElement('div');row.className='profile-schedule-row';
      const dayLabel=document.createElement('label');dayLabel.textContent='Wochentag';const day=document.createElement('select');day.dataset.field='weekday';scheduleDays.forEach((label,value)=>day.add(new Option(label,String(value))));day.value=String(schedule.weekday);dayLabel.append(day);
      const startLabel=document.createElement('label');startLabel.textContent='Beginn';const start=document.createElement('input');start.type='time';start.required=true;start.dataset.field='startMinute';start.value=minuteValue(schedule.startMinute);startLabel.append(start);
      const endLabel=document.createElement('label');endLabel.textContent='Ende';const end=document.createElement('input');end.type='time';end.required=true;end.dataset.field='endMinute';end.value=minuteValue(schedule.endMinute);endLabel.append(end);
      const remove=document.createElement('button');remove.type='button';remove.textContent='Löschen';remove.setAttribute('aria-label','Zeitfenster löschen');
      row.append(dayLabel,startLabel,endLabel,remove);
      $$('[data-field]',row).forEach(input=>input.addEventListener('change',event=>{const field=event.currentTarget.dataset.field;appState.profileDraftSchedules[index][field]=field==='weekday'?Number(event.currentTarget.value):timeMinute(event.currentTarget.value);}));
      remove.addEventListener('click',()=>{appState.profileDraftSchedules.splice(index,1);renderProfileSchedules();});
      list.append(row);
    });
    if(!appState.profileDraftSchedules.length)list.innerHTML='<div class="empty-state">Keine Zeitsteuerung · auf Anzeigegeräten immer aktiv.</div>';
  }
  function addProfileSchedule(){
    const day=new Date().getDay();appState.profileDraftSchedules.push({weekday:day===0?6:day-1,startMinute:480,endMinute:1080});renderProfileSchedules();
  }
  async function openDisplayProfileDialog(){
    try{await loadDisplayProfiles();renderProfileEditorSelect();renderProfileEditor(appState.displayProfileId);$('#display-profile-error').textContent='';$('#display-profile-dialog').showModal();}catch(error){toast(`Profile konnten nicht geladen werden: ${error.code}`);}
  }
  async function saveDisplayProfile(event){
    event.preventDefault();const profileId=$('#profile-editor-select').value,name=$('#profile-name').value.trim(),cameraModes=Object.fromEntries(appState.profileDraftOrder.map(id=>[id,appState.profileDraftModes[id]||'auto'])),body={name,cameraIds:appState.profileDraftOrder,cameraModes,schedules:appState.profileDraftSchedules};
    $('#display-profile-error').textContent='';
    if(body.schedules.some(item=>item.endMinute===item.startMinute)){$('#display-profile-error').textContent='Beginn und Ende eines Zeitfensters dürfen nicht identisch sein.';return;}
    try{
      const saved=await api(profileId?`/api/display-profiles/${encodeURIComponent(profileId)}`:'/api/display-profiles',{method:profileId?'PUT':'POST',body:JSON.stringify(body)});
      await loadDisplayProfiles();$('#display-profile-dialog').close();toast('Anzeigeprofil gespeichert');await selectDisplayProfile(saved.id);
    }catch(error){$('#display-profile-error').textContent=error.code==='display-profile-name-exists'?'Dieser Profilname ist bereits vergeben.':`Speichern fehlgeschlagen: ${error.code}`;}
  }
  async function deleteDisplayProfile(){
    const profileId=$('#profile-editor-select').value,profile=appState.displayProfiles.find(item=>item.id===profileId);if(!profile||!window.confirm(`Anzeigeprofil „${profile.name}“ löschen?`))return;
    try{await api(`/api/display-profiles/${encodeURIComponent(profileId)}`,{method:'DELETE'});const wasActive=appState.displayProfileId===profileId;await loadDisplayProfiles();$('#display-profile-dialog').close();if(wasActive)await selectDisplayProfile('');toast('Anzeigeprofil gelöscht');}catch(error){$('#display-profile-error').textContent=`Löschen fehlgeschlagen: ${error.code}`;}
  }
  async function copyText(value,successText='In Zwischenablage kopiert',promptText='Wert kopieren'){
    try{if(navigator.clipboard&&window.isSecureContext)await navigator.clipboard.writeText(value);else{const area=document.createElement('textarea');area.value=value;area.style.position='fixed';area.style.opacity='0';document.body.append(area);area.select();document.execCommand('copy');area.remove();}toast(successText);}catch{window.prompt(promptText,value);}
  }
  function copyProfileLink(view){
    const profileId=$('#profile-editor-select').value;if(!profileId)return;
    copyText(`${location.origin}${location.pathname}#${view}?profile=${encodeURIComponent(profileId)}`,'Profil-Link kopiert','Profil-Link kopieren');
  }
  function renderCamera(camera){
    const fragment=$('#camera-template').content.cloneNode(true),card=$('.camera-card',fragment),video=$('video',fragment),snapshot=$('.card-snapshot',fragment),status=$('.card-status',fragment);
    const state={camera,card,video,snapshot,status,wallStatus:$('.wall-camera-status',fragment),placeholder:$('.card-placeholder',fragment),lastFrame:$('.last-frame span',fragment),reader:null,retryTimer:null,startupTimer:null,snapshotTimer:null,leaseTimer:null,explicitTimer:null,retryCount:0,generation:0,visible:false,lastFrameAt:null,firstFrameReceived:false,mode:'low',path:camera.lowPath,leaseId:null,explicitStarted:false,maxExpiresAt:null};
    if(['snapshot','explicit'].includes(camera.displayMode))video.hidden=true;else bindVideoEvents(state);
    const authBadge=$('.auth-badge',fragment),usesCredentials=Boolean(camera.usesCredentials),authText=usesCredentials?'Mit Anmeldung':'Ohne Anmeldung';
    card.dataset.cameraId=camera.id;$('h3',fragment).textContent=camera.name;$('.wall-camera-name',fragment).textContent=camera.name;$('.source-badge',fragment).textContent=camera.source;authBadge.dataset.auth=String(usesCredentials);authBadge.setAttribute('aria-label',authText);authBadge.title=authText;$('.auth-badge-text',fragment).textContent=authText;$('.open-camera',fragment).addEventListener('click',()=>openDetail(camera.id));const reconnect=$('.reconnect-camera',fragment);if(camera.displayMode==='explicit')reconnect.textContent='Vorschau aktualisieren';reconnect.addEventListener('click',()=>['snapshot','explicit'].includes(camera.displayMode)?startSnapshot(state,true):connect(state,camera.lowPath,'low',true));state.placeholder.addEventListener('click',()=>camera.displayMode==='explicit'?startSnapshot(state,true):resumePlayback(state));video.addEventListener('click',()=>resumePlayback(state));appState.states.set(camera.id,state);$('#camera-grid').append(fragment);appState.observer.observe(card);
  }
  async function loadCameras(){
    const request=++appState.cameraRequest,requestedProfileId=appState.displayProfileId;
    const query=appState.displayProfileId?`?profileId=${encodeURIComponent(appState.displayProfileId)}`:'';
    let data;try{data=await api(`/api/cameras${query}`);}catch(error){
      if(request!==appState.cameraRequest)return false;
      if(error.code==='display-profile-not-found'){appState.displayProfileId='';renderDisplayProfileSelects();toast('Anzeigeprofil nicht verfügbar · alle aktiven Kameras werden angezeigt');try{data=await api('/api/cameras');}catch(fallbackError){if(request===appState.cameraRequest){appState.displayProfileId=appState.renderedDisplayProfileId;renderDisplayProfileSelects();toast(`Liveansicht konnte nicht geladen werden: ${fallbackError.code}`);}return false;}}
      else{appState.displayProfileId=appState.renderedDisplayProfileId;renderDisplayProfileSelects();toast(`Liveansicht konnte nicht geladen werden: ${error.code}`);return false;}
    }
    if(request!==appState.cameraRequest||requestedProfileId!==appState.displayProfileId&&appState.displayProfileId!=='')return false;
    appState.states.forEach(closeReader); appState.states.clear(); $('#camera-grid').replaceChildren();
    appState.cameras=data.cameras||[];appState.camerasLoaded=true;$('#camera-grid').dataset.count=String(appState.cameras.length);appState.cameras.forEach(renderCamera);
    if(!appState.cameras.length){const empty=document.createElement('div');empty.className='empty-state';empty.innerHTML='<h3>Keine Kameras in dieser Ansicht</h3><p>Wählen Sie ein anderes Profil oder bearbeiten Sie die Kamerazuordnung.</p>';$('#camera-grid').append(empty);}if(appState.wallMode)updateWallGridLayout();
    appState.renderedDisplayProfileId=appState.displayProfileId;await loadHealth();if(request===appState.cameraRequest)populateZoneSelect();return true;
  }
  async function loadHealth(){try{const data=await api('/api/health');$('#system-state').dataset.state='live';$('#system-state span').textContent='Lokales Gateway online';const labels={connecting:['loading','Verbindung wird aufgebaut'],sleeping:['loading','Bereit · startet beim Öffnen'],offline:['offline','Kamera nicht erreichbar'],'cloud-auth-required':['offline','Cloud-Anmeldung erforderlich'],'media-server-offline':['offline','Medienserver nicht erreichbar'],unknown:['loading','Status unbekannt']};data.cameras?.forEach((item)=>{const state=appState.states.get(item.camera),detail=appState.detail?.camera.id===item.camera?appState.detail:null;if(item.state==='cloud-auth-required'){for(const target of new Set([state,detail].filter(Boolean))){closeReader(target);mark(target,'offline','Cloud-Anmeldung erforderlich');}return;}if(!state||state.reader||['snapshot','explicit'].includes(state.camera.displayMode))return;if(item.lastFrameAt)state.lastFrame.textContent=relativeTime(item.lastFrameAt);if(item.state!=='live'){const [status,text]=labels[item.state]||labels.unknown;mark(state,status,text);}});}catch{$('#system-state').dataset.state='offline';$('#system-state span').textContent='Gateway nicht erreichbar';}}
  function openDetail(id){
    const camera=appState.cameras.find(item=>item.id===id),tile=appState.states.get(id);if(!camera||!tile)return;const returnFocus=document.activeElement;closeReader(tile);$$('.view').forEach(view=>view.hidden=true);$('#detail').hidden=false;history.replaceState(null,'',`#camera/${camera.id}`);
    const highAvailable=camera.highPath!==camera.lowPath,singlePathMain=!highAvailable&&String(camera.detailQuality||'').toLocaleLowerCase('de-DE').includes('hauptstream'),highWebRTC=highAvailable&&camera.highWebRTCCompatible!==false,initialPath=highWebRTC?camera.highPath:camera.lowPath,mode=highWebRTC||singlePathMain?'high':'low';
    $('#detail-name').textContent=camera.name;$('#detail-source').textContent=camera.source;
    const isExplicit=camera.displayMode==='explicit';
    $('#detail-quality').textContent=isExplicit?'Blink-Vorschau · Live auf Anforderung':camera.displayMode==='snapshot'?'Vorschaubild':(highWebRTC?(camera.detailQuality||'Hauptstream'):(highAvailable?'Substream · Hauptstream über HLS':(camera.detailQuality||'Substream')));
    $('#detail-hls-toggle').textContent=highAvailable&&!highWebRTC||singlePathMain?'HLS-Hauptstream':'HLS-Fallback';
    const state={camera,video:$('#detail-video'),snapshot:$('#detail-snapshot'),status:$('#detail-status'),placeholder:$('#detail-message'),lastFrame:$('#detail-last-frame'),reader:null,retryTimer:null,startupTimer:null,snapshotTimer:null,leaseTimer:null,explicitTimer:null,hlsTimer:null,hlsChecks:0,hlsLiveLabel:'',retryCount:0,generation:0,lastFrameAt:null,firstFrameReceived:false,mode,path:initialPath,returnFocus,leaseId:null,explicitStarted:false,maxExpiresAt:null};appState.detail=state;
    const isSnapshot=camera.displayMode==='snapshot';$('#detail-video').hidden=isSnapshot||isExplicit;$('#detail-snapshot').hidden=!(isSnapshot||isExplicit);$('#detail-fallback').hidden=isSnapshot||isExplicit||!highWebRTC;$('#detail-hls-toggle').hidden=isSnapshot||isExplicit;$('#detail-reconnect').hidden=isExplicit;$('#detail-start-explicit').hidden=!isExplicit;$('#detail-audio').hidden=isSnapshot||isExplicit||!camera.features?.audio;$('#detail-video').muted=true;$('#detail-audio').textContent='Audio einschalten';loadDetailFunctions(camera);$('#detail-clips').hidden=!camera.features?.clips;if(camera.features?.clips)loadBlinkClips(camera);$('#detail-back').focus();if(isSnapshot||isExplicit)startSnapshot(state,true);else{bindVideoEvents(state);connect(state,initialPath,mode,true);}

  }
  function startExplicitLive(){
    const state=appState.detail;if(!state?.camera?.explicitLiveOnly)return;
    clearTimeout(state.snapshotTimer);state.snapshotTimer=null;state.snapshot.hidden=true;state.video.hidden=false;state.explicitStarted=true;state.retryCount=0;bindVideoEvents(state);connect(state,state.camera.lowPath,'high',true);
  }
  async function loadBlinkClips(camera=appState.detail?.camera){
    const list=$('#detail-clips-list');if(!camera?.features?.clips||!list)return;
    list.innerHTML='<div class="empty-state">Blink-Clips werden geladen …</div>';
    try{
      const data=await api(`/api/cameras/${encodeURIComponent(camera.id)}/clips`);
      if(appState.detail?.camera.id!==camera.id)return;
      list.replaceChildren();
      const clips=data.clips||[];
      if(!clips.length){list.innerHTML='<div class="empty-state">Keine aktuellen Bewegungsclips gemeldet.</div>';return;}
      clips.forEach(clip=>{const row=document.createElement('article');row.className='clip-row';const time=clip.createdAt?new Intl.DateTimeFormat('de-DE',{dateStyle:'short',timeStyle:'medium'}).format(new Date(clip.createdAt)):'Zeit unbekannt';row.innerHTML=`<div><strong>${escapeHtml(time)}</strong><span>${escapeHtml(clip.kind||'Bewegung')}</span></div><button type="button">Clip öffnen</button>`;$('button',row).addEventListener('click',()=>window.open(`/api/cameras/${encodeURIComponent(camera.id)}/clips/${encodeURIComponent(clip.id)}`,'_blank','noopener'));list.append(row);});
    }catch(error){list.innerHTML=`<div class="empty-state">Clips nicht verfügbar · ${escapeHtml(error.code)}</div>`;}
  }

  const RECORDING_PROVIDER_LABELS={sannce:'SANNCE Recorder',blink:'Blink Cloud',netatmo:'Netatmo Cloud',none:'Ohne Archiv'};
  function recordingDateValue(value=new Date()){
    const year=value.getFullYear(),month=String(value.getMonth()+1).padStart(2,'0'),day=String(value.getDate()).padStart(2,'0');return `${year}-${month}-${day}`;
  }
  function recordingDayBounds(value){const start=new Date(`${value}T00:00:00`),end=new Date(start);end.setDate(end.getDate()+1);return {start,end};}
  function recordingDateTime(value){return value?new Intl.DateTimeFormat('de-DE',{dateStyle:'short',timeStyle:'short'}).format(new Date(value)):'–';}
  function recordingTime(value){return value?new Intl.DateTimeFormat('de-DE',{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date(value)):'–';}
  function recordingAvailability(source){
    if(source.status==='unsupported')return source.limitLabel||'Keine Aufzeichnungsquelle verfügbar';
    if(source.status==='reauth-required')return 'Cloud-Konto muss neu verbunden werden';
    if(source.status!=='ready')return source.limitLabel||'Quelle momentan nicht verfügbar';
    if(!source.availableFrom||!source.availableTo)return source.limitLabel||'Noch keine Aufzeichnungen gemeldet';
    const range=`${recordingDateTime(source.availableFrom)} bis ${recordingDateTime(source.availableTo)}`;return source.limitLabel?`${range} · ${source.limitLabel}`:range;
  }
  function renderRecordingSources(){
    const list=$('#recording-source-list');list.replaceChildren();
    if(!appState.recordings.sources.length){list.innerHTML='<div class="empty-state">Keine aktiven Kameras vorhanden.</div>';return;}
    appState.recordings.sources.forEach(source=>{const button=document.createElement('button');button.type='button';button.className='recording-source';button.dataset.status=source.status;button.classList.toggle('is-active',source.cameraId===appState.recordings.cameraId);button.innerHTML=`<strong>${escapeHtml(source.name)}</strong><span class="recording-provider-badge" data-provider="${escapeHtml(source.provider)}">${escapeHtml(RECORDING_PROVIDER_LABELS[source.provider]||source.provider)}</span><small>${escapeHtml(recordingAvailability(source))}</small>`;button.addEventListener('click',()=>selectRecordingSource(source.cameraId));list.append(button);});
  }
  async function loadRecordingSources(force=false){
    const request=++appState.recordings.request;$('#recording-source-list').innerHTML='<div class="empty-state">Aufzeichnungsquellen werden geladen …</div>';
    if(!$('#recording-date').value)$('#recording-date').value=recordingDateValue();
    try{const data=await api(`/api/recordings/sources${force?'?refresh=true':''}`);if(request!==appState.recordings.request)return;appState.recordings.sources=data.sources||[];if(!appState.recordings.sources.some(item=>item.cameraId===appState.recordings.cameraId))appState.recordings.cameraId=appState.recordings.sources.find(item=>item.status==='ready')?.cameraId||appState.recordings.sources[0]?.cameraId||'';renderRecordingSources();await selectRecordingSource(appState.recordings.cameraId,false);}catch(error){if(request!==appState.recordings.request)return;$('#recording-source-list').innerHTML=`<div class="empty-state">Quellen nicht verfügbar · ${escapeHtml(error.code)}</div>`;}
  }
  async function selectRecordingSource(cameraId,rerender=true){
    appState.recordings.cameraId=cameraId;if(rerender)renderRecordingSources();await stopRecordingPlayback();const source=appState.recordings.sources.find(item=>item.cameraId===cameraId);appState.recordings.items=[];
    $('#recording-camera-name').textContent=source?.name||'Keine Kamera ausgewählt';$('#recording-provider').textContent=source?RECORDING_PROVIDER_LABELS[source.provider]||source.provider:'Quelle auswählen';$('#recording-availability').textContent=source?recordingAvailability(source):'–';
    if(!source||source.status!=='ready')return renderRecordingTimeline([],source?.status==='unsupported'?'Für diese Kamera ist keine Aufzeichnungsquelle eingerichtet.':'Aufzeichnungsquelle momentan nicht verfügbar.');
    await loadCameraRecordings();
  }
  async function loadCameraRecordings(){
    const source=appState.recordings.sources.find(item=>item.cameraId===appState.recordings.cameraId);if(!source||source.status!=='ready')return;
    const request=++appState.recordings.request,date=$('#recording-date').value||recordingDateValue(),bounds=recordingDayBounds(date);renderRecordingTimeline([],'Aufzeichnungen werden geladen …');
    try{const params=new URLSearchParams({from:bounds.start.toISOString(),to:bounds.end.toISOString()}),data=await api(`/api/cameras/${encodeURIComponent(source.cameraId)}/recordings?${params}`);if(request!==appState.recordings.request||source.cameraId!==appState.recordings.cameraId)return;appState.recordings.items=data.recordings||[];renderRecordingTimeline(appState.recordings.items);}catch(error){if(request!==appState.recordings.request)return;renderRecordingTimeline([],`Aufzeichnungen nicht verfügbar · ${error.code}`);}
  }
  function renderRecordingTimeline(items,message='Für diesen Tag sind keine Aufzeichnungen gemeldet.'){
    const timeline=$('#recording-timeline'),list=$('#recording-list'),date=$('#recording-date').value||recordingDateValue(),bounds=recordingDayBounds(date),span=bounds.end-bounds.start;timeline.replaceChildren();list.replaceChildren();
    $('#recording-day-summary').textContent=items.length?`${items.length} ${items.length===1?'Abschnitt':'Abschnitte'}`:'Keine Abschnitte';
    if(!items.length){list.innerHTML=`<div class="recording-empty">${escapeHtml(message)}</div>`;return;}
    items.forEach(item=>{const start=new Date(item.startAt),end=new Date(item.endAt),left=Math.max(0,Math.min(1,(start-bounds.start)/span)),right=Math.max(left,Math.min(1,(end-bounds.start)/span));const segment=document.createElement('button');segment.type='button';segment.className='recording-segment';segment.dataset.provider=item.provider;segment.style.left=`${left*100}%`;segment.style.width=`${Math.max(.3,(right-left)*100)}%`;segment.disabled=!item.playable;segment.title=`${recordingTime(item.startAt)}–${recordingTime(item.endAt)} · ${item.kind}${item.playable?'':' · nicht abspielbar'}`;segment.setAttribute('aria-label',segment.title);segment.addEventListener('click',event=>{const ratio=Math.max(0,Math.min(1,(event.clientX-segment.getBoundingClientRect().left)/Math.max(1,segment.getBoundingClientRect().width)));startRecordingPlayback(item,ratio*Number(item.durationSeconds||0));});timeline.append(segment);
      const row=document.createElement('article');row.className='recording-row';row.innerHTML=`<strong>${escapeHtml(recordingTime(item.startAt))}–${escapeHtml(recordingTime(item.endAt))}</strong><span>${escapeHtml(RECORDING_PROVIDER_LABELS[item.provider]||item.provider)}</span><span>${escapeHtml(item.kind||'Aufzeichnung')}</span><button type="button" ${item.playable?'':'disabled'}>${item.playable?'Abspielen':'Nicht verfügbar'}</button>`;$('button',row).addEventListener('click',()=>startRecordingPlayback(item,0));list.append(row);
    });
  }
  async function startRecordingPlayback(item,offsetSeconds=0){
    await stopRecordingPlayback();const player=$('#recording-player');$('#recording-player-empty').textContent='Wiedergabe wird vorbereitet …';$('#recording-player-empty').hidden=false;
    try{const result=await api(`/api/cameras/${encodeURIComponent(item.cameraId)}/recordings/${encodeURIComponent(item.id)}/playback`,{method:'POST',body:JSON.stringify({offsetSeconds:Math.max(0,Math.floor(offsetSeconds))})});appState.recordings.leaseId=result.leaseId;player.src=result.mediaUrl;player.style.visibility='visible';$('#recording-player-empty').hidden=true;$('#recording-stop').hidden=false;$('#recording-player-label').textContent=`${recordingDateTime(item.startAt)} · ${RECORDING_PROVIDER_LABELS[item.provider]||item.provider}`;await player.play();}catch(error){player.removeAttribute('src');player.load();$('#recording-player-empty').hidden=false;$('#recording-player-empty').textContent=`Wiedergabe nicht verfügbar · ${error.code}`;$('#recording-player-label').textContent='Wiedergabe fehlgeschlagen';}
  }
  async function stopRecordingPlayback(){
    const leaseId=appState.recordings.leaseId;appState.recordings.leaseId=null;const player=$('#recording-player');if(player){player.pause();player.removeAttribute('src');player.load();player.style.visibility='hidden';}$('#recording-stop')?.setAttribute('hidden','');if($('#recording-player-empty')){$('#recording-player-empty').hidden=false;$('#recording-player-empty').textContent='Wählen Sie eine markierte Aufnahme auf der Zeitleiste.';}if($('#recording-player-label'))$('#recording-player-label').textContent='Noch keine Wiedergabe';if(leaseId){try{await api(`/api/recordings/playback/${encodeURIComponent(leaseId)}`,{method:'DELETE',keepalive:true});}catch{}}
  }
  function shiftRecordingDate(days){const current=new Date(`${$('#recording-date').value||recordingDateValue()}T12:00:00`);current.setDate(current.getDate()+days);const today=recordingDateValue();$('#recording-date').value=recordingDateValue(current)>today?today:recordingDateValue(current);loadCameraRecordings();}
  async function loadDetailFunctions(camera){
    appState.ptz=null;$('#detail-functions').hidden=true;$('#ptz-panel').hidden=true;$('#ptz-presets').replaceChildren(new Option('Preset auswählen',''));$$('[data-ptz-x]').forEach(button=>button.disabled=false);
    if(!appState.permissions.controlCameras||!camera.features?.ptz)return;
    try{
      const data=await api(`/api/admin/cameras/${encodeURIComponent(camera.id)}/capabilities`),profile=data.profiles?.[0];
      if(appState.detail?.camera.id!==camera.id)return;
      if(!data.available||!data.ptz?.supported||!profile?.token)return;
      appState.ptz={cameraId:camera.id,profileToken:profile.token,moving:false,pending:false,stopRequested:false,operation:0,stopSentFor:0,movePromise:null};
      $('#detail-functions').hidden=false;$('#ptz-panel').hidden=false;$('#ptz-state').textContent='Bereit';
      const axes=new Set(data.ptz.axes||['x','y','zoom']);$$('[data-ptz-x]').forEach(button=>{const needsX=Number(button.dataset.ptzX||0)!==0,needsY=Number(button.dataset.ptzY||0)!==0,needsZoom=Number(button.dataset.ptzZ||0)!==0;button.disabled=(needsX&&!axes.has('x'))||(needsY&&!axes.has('y'))||(needsZoom&&!axes.has('zoom'));});
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
  function closeDetail({updateHistory=true}={}){const returnFocus=appState.detail?.returnFocus;stopPTZ();if(appState.detail)closeReader(appState.detail);appState.detail=null;appState.ptz=null;$('#detail-functions').hidden=true;$('#detail-clips').hidden=true;$('#detail-clips-list').replaceChildren();$('#detail-hls').hidden=true;$('#detail-hls').removeAttribute('src');$('#detail-snapshot').hidden=true;$('#detail-reconnect').hidden=false;$('#detail-start-explicit').hidden=true;$('#detail-fallback').hidden=false;$('#detail-hls-toggle').hidden=false;$('#detail').hidden=true;if(updateHistory)showView('overview');if(returnFocus?.isConnected)returnFocus.focus();}
  function suspend(){stopPTZ();stopRecordingPlayback();appState.suspended=true;appState.states.forEach(closeReader);if(appState.detail)closeReader(appState.detail);$('#detail-hls').hidden=true;$('#detail-hls').removeAttribute('src');}
  function resume(){if(document.hidden||!navigator.onLine||!appState.csrf)return;appState.suspended=false;if(appState.detail){['snapshot','explicit'].includes(appState.detail.camera.displayMode)?startSnapshot(appState.detail,true):connect(appState.detail,appState.detail.path,appState.detail.mode,true);}else appState.states.forEach(state=>{if(state.visible)['snapshot','explicit'].includes(state.camera.displayMode)?startSnapshot(state,true):connect(state,state.camera.lowPath,'low',true);});loadHealth();}

  function showAuth(setup){
    $('#system-state').dataset.state='loading';$('#system-state span').textContent=setup?'Eigentümerkonto anlegen':'Anmeldung erforderlich';$('#auth-title').textContent=setup?'Eigentümerzugang einrichten':'Anmelden';$('#auth-copy').textContent=setup?'Legen Sie Benutzername und Passwort für den lokalen Eigentümerzugang fest.':'Livebilder und Einstellungen sind geschützt.';$('#auth-dialog').dataset.setup=String(setup);$('#auth-error').textContent='';if(!$('#auth-dialog').open)$('#auth-dialog').showModal();
  }
  function currentRouteNeedsCameras(){const view=hashRoute().view;return view==='overview'||view==='wall'||view.startsWith('camera/');}
  async function initializeAuth(){
    const state=await api('/api/auth/state');if(!state.authenticated){$('#app').hidden=true;showAuth(state.setupRequired);return false;}applyAccess(state);$('#auth-dialog').close();$('#app').hidden=false;await loadDisplayProfiles();applyDisplayProfileFromHash();if(currentRouteNeedsCameras())await loadCameras();else await loadHealth();return true;
  }

  const ROLE_LABELS={owner:'Eigentümer',admin:'Administrator',viewer:'Betrachter'};
  function applyAccess(state){
    appState.csrf=state.csrfToken;appState.elevatedUntil=state.elevatedUntil;appState.user=state.user;appState.permissions=state.permissions||{};
    $$('[data-permission]').forEach(node=>node.hidden=!appState.permissions[node.dataset.permission]);
    $('#current-user').textContent=state.user?.displayName||state.user?.username||'Angemeldet';
    $('#current-role').textContent=ROLE_LABELS[state.user?.role]||state.user?.role||'';
    initializeMotionAlerts();
  }

  async function loadAdminCameras(){
    try{const data=await api('/api/admin/cameras');appState.adminCameras=data.cameras||[];await loadDisplayProfiles();renderManage();}catch(error){if(error.status===401)showAuth(false);}
  }
  function connectionBadges(camera){
    const active=camera.activeCredentials||{},draft=camera.draftCredentials||{},live=camera.liveAccess||{};
    if(camera.externalSource){
      return live.ready
        ? '<span class="connection-badge live-auth" data-state="verified">Live · CZEview-Anmeldung aktiv</span>'
        : '<span class="connection-badge" data-state="offline">Bereit · startet beim Öffnen</span>';
    }
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
      badges.push(`<span class="connection-badge" data-state="offline">${live.state==='media-server-offline'?'Medienserver nicht erreichbar':live.state==='cloud-auth-required'?'Cloud-Anmeldung erforderlich':'Livequelle offline'}</span>`);
    }
    if(camera.draftRevision&&draftHasAuth&&!live.usesActiveRevision){
      badges.push('<span class="connection-note">Geprüfter Entwurf ist noch nicht die Livequelle.</span>');
    }
    return badges.join('');
  }
  function renderManage(){
    const list=$('#manage-list');list.replaceChildren();appState.adminCameras.forEach((camera)=>{
      const row=document.createElement('article');row.className='manage-row';row.dataset.id=camera.id;
      const connectionActions=camera.externalSource?'<button data-capabilities>Funktionen</button>':`<button data-connection>Verbindung</button><button data-capabilities>Funktionen</button><button data-rollback>Letzte Verbindung</button>`;
      row.innerHTML=`<button class="drag-handle" aria-label="${escapeHtml(camera.name)} verschieben">↕</button><div><h3>${escapeHtml(camera.name)}</h3><div class="manage-meta"><span>${escapeHtml(camera.source)}</span><span>${escapeHtml(camera.manufacturer||'')}</span><span>${escapeHtml(camera.codec.toUpperCase())}</span><span>${camera.enabled?'Aktiv':'Deaktiviert'}</span></div><div class="connection-statuses" aria-label="Verbindungsstatus">${connectionBadges(camera)}</div></div><div class="row-actions">${connectionActions}<button data-move="up" aria-label="Nach oben">↑</button><button data-move="down" aria-label="Nach unten">↓</button><button data-rename>Umbenennen</button><button data-toggle>${camera.enabled?'In App deaktivieren':'In App aktivieren'}</button>${camera.managed?'<button data-remove>Entfernen</button>':''}</div>`;
      $('.drag-handle',row).addEventListener('pointerdown',beginDrag);
      $$('[data-move]',row).forEach(button=>button.addEventListener('click',()=>moveCamera(camera.id,button.dataset.move==='up'?-1:1)));
      $('[data-connection]',row)?.addEventListener('click',()=>openConnectionDialog(camera));
      $('[data-capabilities]',row)?.addEventListener('click',()=>openCapabilities(camera));
      $('[data-rollback]',row)?.addEventListener('click',()=>rollbackConnection(camera));
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

  async function loadCloudAccounts(){
    const panel=$('#cloud-accounts');
    if(appState.user?.role!=='owner'){panel.hidden=true;return;}
    panel.hidden=false;
    try{
      const [accounts,providers]=await Promise.all([api('/api/admin/cloud/accounts'),api('/api/admin/cloud/providers')]);
      appState.cloudAccounts=accounts.accounts||[];
      appState.cloudProviders=providers.providers||[];
      renderCloudAccounts();
    }catch(error){toast(`Cloud-Konten konnten nicht geladen werden: ${error.code}`);}
  }
  function renderCloudAccounts(){
    const list=$('#cloud-account-list');
    list.replaceChildren();
    const netatmo=appState.cloudProviders.find(provider=>provider.id==='netatmo');
    $('#add-netatmo-account').disabled=!netatmo?.configured;
    $('#configure-netatmo').textContent=netatmo?.configured?'Netatmo-App ändern':'Netatmo einrichten';
    if(!appState.cloudAccounts.length){list.innerHTML='<div class="empty-state"><h3>Noch kein Cloud-Konto</h3><p>CZEview-, Blink- oder Netatmo-Konten können hier sicher verbunden werden.</p></div>';return;}
    appState.cloudAccounts.forEach(account=>{
      const row=document.createElement('article');
      row.className='cloud-account-row';
      row.dataset.enabled=String(account.enabled);
      const provider={netatmo:'Netatmo',blink:'Blink',czeview:'CZEview'}[account.provider]||account.provider;
      const state={active:'Verbunden',pending:'Wird geprüft','reauth-required':'Erneute Anmeldung erforderlich',error:'Fehler'}[account.status]||account.status;
      const reconnect=account.provider==='netatmo'
        ?'<button type="button" data-reconnect>Neu verbinden</button>'
        :account.provider==='blink'
        ?`<button type="button" data-reconnect>${account.status==='pending'?'Code eingeben':'Neu verbinden'}</button><button type="button" data-credentials>Zugang erneuern</button>`
        :'<button type="button" data-credentials>Zugang erneuern</button>';
      row.innerHTML=`<div><strong>${escapeHtml(account.label)}</strong><p>${provider} · ${escapeHtml(state)} · ${account.deviceCount||0} Gerät(e)${account.lastErrorCode?` · ${escapeHtml(account.lastErrorCode)}`:''}</p></div><div class="cloud-account-row-actions"><button type="button" data-rename>Umbenennen</button>${reconnect}<button type="button" data-toggle>${account.enabled?'Deaktivieren':'Aktivieren'}</button><button type="button" data-delete>Entfernen</button></div>`;
      $('[data-rename]',row).addEventListener('click',()=>renameCloudAccount(account));
      $('[data-credentials]',row)?.addEventListener('click',()=>account.provider==='blink'?openBlinkCredentialReplacement(account):openCzeviewCredentialReplacement(account));
      $('[data-reconnect]',row)?.addEventListener('click',()=>account.provider==='blink'?reconnectBlink(account):reconnectNetatmo(account));
      $('[data-toggle]',row).addEventListener('click',()=>updateCloudAccount(account,{enabled:!account.enabled}));
      $('[data-delete]',row).addEventListener('click',()=>deleteCloudAccount(account));
      list.append(row);
    });
  }
  async function updateCloudAccount(account,changes){
    try{await adminApi(`/api/admin/cloud/accounts/${encodeURIComponent(account.id)}`,{method:'PATCH',body:JSON.stringify(changes)});await loadCloudAccounts();toast('Cloud-Konto aktualisiert');}
    catch(error){toast(`Änderung fehlgeschlagen: ${error.code}`);}
  }
  async function renameCloudAccount(account){
    const label=window.prompt('Neue Bezeichnung des Cloud-Kontos',account.label);
    if(label===null||!label.trim()||label.trim()===account.label)return;
    await updateCloudAccount(account,{label:label.trim()});
  }
  function openCzeviewCredentialReplacement(account){
    const form=$('#czeview-account-form');
    form.reset();
    form.elements.accountId.value=account.id;
    form.elements.label.value=account.label;
    form.elements.countryCode.value='DE';
    form.elements.phoneCode.value='49';
    form.elements.sourceApp.value='141';
    $('#czeview-account-title').textContent=`Zugang für ${account.label} erneuern`;
    $('#czeview-account-error').textContent='';
    $('#czeview-account-dialog').showModal();
  }
  async function deleteCloudAccount(account){
    if(!window.confirm(`Cloud-Konto „${account.label}“ wirklich entfernen?`))return;
    try{await adminApi(`/api/admin/cloud/accounts/${encodeURIComponent(account.id)}`,{method:'DELETE'});await loadCloudAccounts();toast('Cloud-Konto entfernt');}
    catch(error){toast(error.code==='cloud-account-has-linked-cameras'?'Das Konto wird noch von mindestens einer Kamera verwendet.':`Entfernen fehlgeschlagen: ${error.code}`);}
  }
  async function saveCzeviewAccount(event){
    event.preventDefault();const form=event.currentTarget,payload=Object.fromEntries(new FormData(form).entries()),accountId=payload.accountId;delete payload.accountId;
    $('#czeview-account-error').textContent='';
    try{await adminApi(accountId?`/api/admin/cloud/accounts/${encodeURIComponent(accountId)}/czeview`:'/api/admin/cloud/accounts/czeview',{method:accountId?'PUT':'POST',body:JSON.stringify(payload)});form.reset();form.elements.countryCode.value='DE';form.elements.phoneCode.value='49';form.elements.sourceApp.value='141';$('#czeview-account-dialog').close();await loadCloudAccounts();toast(accountId?'CZEview-Zugang erneuert; die Prüfung läuft im Hintergrund':'CZEview-Konto gespeichert; die Prüfung läuft im Hintergrund');}
    catch(error){$('#czeview-account-error').textContent=`Speichern fehlgeschlagen: ${error.code}`;}
    finally{payload.password='';form.elements.password.value='';}
  }
  function openBlinkVerification(accountId){
    const form=$('#blink-verify-form');form.reset();form.elements.accountId.value=accountId;$('#blink-verify-error').textContent='';$('#blink-verify-dialog').showModal();
  }
  function openBlinkCredentialReplacement(account){
    const form=$('#blink-account-form');form.reset();form.elements.accountId.value=account.id;form.elements.label.value=account.label;$('#blink-account-title').textContent=`Blink-Zugang für ${account.label} erneuern`;$('#blink-account-error').textContent='';$('#blink-account-dialog').showModal();
  }
  async function saveBlinkAccount(event){
    event.preventDefault();const form=event.currentTarget,payload=Object.fromEntries(new FormData(form).entries()),accountId=payload.accountId;delete payload.accountId;$('#blink-account-error').textContent='';
    try{const result=await adminApi(accountId?`/api/admin/cloud/accounts/${encodeURIComponent(accountId)}/blink`:'/api/admin/cloud/accounts/blink',{method:accountId?'PUT':'POST',body:JSON.stringify(payload)});form.reset();$('#blink-account-dialog').close();await loadCloudAccounts();if(result.authStep==='verification-required'||result.status==='pending'){openBlinkVerification(result.id);toast('Blink-Code wurde angefordert');}else if(result.status==='active')toast('Blink-Konto verbunden');else toast(`Blink-Konto gespeichert · ${result.lastErrorCode||result.authStep}`);}
    catch(error){if(error.code!=='reauth-cancelled')$('#blink-account-error').textContent=`Verbindung fehlgeschlagen: ${error.code}`;}
    finally{payload.password='';form.elements.password.value='';}
  }
  async function verifyBlinkAccount(event){
    event.preventDefault();const form=event.currentTarget,accountId=form.elements.accountId.value,code=form.elements.code.value;$('#blink-verify-error').textContent='';
    try{const result=await adminApi(`/api/admin/cloud/accounts/${encodeURIComponent(accountId)}/blink/verify`,{method:'POST',body:JSON.stringify({code})});form.reset();$('#blink-verify-dialog').close();await loadCloudAccounts();toast(result.status==='active'?'Blink-Konto verbunden':`Blink-Anmeldung: ${result.authStep||result.status}`);}
    catch(error){if(error.code==='blink-verification-session-missing'){form.reset();$('#blink-verify-dialog').close();const account=appState.cloudAccounts.find(item=>item.id===accountId);if(account)await reconnectBlink(account,true);return;}if(error.code!=='reauth-cancelled')$('#blink-verify-error').textContent=`Code nicht angenommen: ${error.code}`;}
    finally{form.elements.code.value='';}
  }
  async function reconnectBlink(account,restartPending=false){
    if(account.status==='pending'&&!restartPending){openBlinkVerification(account.id);return;}
    try{const result=await adminApi(`/api/admin/cloud/accounts/${encodeURIComponent(account.id)}/blink/reconnect`,{method:'POST',body:'{}'});await loadCloudAccounts();if(result.authStep==='verification-required'||result.status==='pending')openBlinkVerification(account.id);else toast(result.status==='active'?'Blink-Konto erneut verbunden':`Blink-Anmeldung: ${result.lastErrorCode||result.authStep}`);}
    catch(error){if(error.code!=='reauth-cancelled')toast(`Blink-Wiederverbindung fehlgeschlagen: ${error.code}`);}
  }
  async function saveNetatmoConfig(event){
    event.preventDefault();const form=event.currentTarget,payload=Object.fromEntries(new FormData(form).entries());
    $('#netatmo-config-error').textContent='';
    try{await adminApi('/api/admin/cloud/providers/netatmo',{method:'PUT',body:JSON.stringify(payload)});form.reset();$('#netatmo-config-dialog').close();await loadCloudAccounts();toast('Netatmo-App gespeichert');}
    catch(error){$('#netatmo-config-error').textContent=`Speichern fehlgeschlagen: ${error.code}`;}
    finally{payload.clientSecret='';form.elements.clientSecret.value='';}
  }
  async function authorizeNetatmo(event){
    event.preventDefault();const form=event.currentTarget;
    $('#netatmo-account-error').textContent='';
    try{const result=await adminApi('/api/admin/cloud/accounts/netatmo/authorize',{method:'POST',body:JSON.stringify({label:form.elements.label.value})});location.assign(result.authorizationUrl);}
    catch(error){$('#netatmo-account-error').textContent=`Anmeldung konnte nicht gestartet werden: ${error.code}`;}
  }
  async function reconnectNetatmo(account){
    try{const result=await adminApi('/api/admin/cloud/accounts/netatmo/authorize',{method:'POST',body:JSON.stringify({label:account.label,accountId:account.id})});location.assign(result.authorizationUrl);}
    catch(error){toast(`Netatmo-Wiederverbindung konnte nicht gestartet werden: ${error.code}`);}
  }

  async function startScan(){
    $('#scan-progress').hidden=false;$('#start-scan').disabled=true;$('#discovery-list').replaceChildren();
    try{const scan=await adminApi('/api/admin/discovery/scans',{method:'POST'});appState.scanId=scan.id;$('#cancel-scan').hidden=false;pollScan(scan.id);}catch(error){$('#scan-progress').hidden=true;$('#start-scan').disabled=false;toast(`Suche nicht gestartet: ${error.code}`);}
  }
  async function cancelScan(){if(!appState.scanId)return;clearTimeout(appState.scanTimer);try{await adminApi(`/api/admin/discovery/scans/${encodeURIComponent(appState.scanId)}`,{method:'DELETE'});}catch{}appState.scanId=null;appState.scanTimer=null;$('#scan-progress').hidden=true;$('#cancel-scan').hidden=true;$('#start-scan').disabled=false;toast('Kamerasuche beendet');}
  async function pollScan(id){if(id!==appState.scanId)return;try{const scan=await api(`/api/admin/discovery/scans/${id}`);renderDiscovery(scan.results||[],id,scan.state!=='complete');$('#scan-progress span').textContent=`Netzwerk wird kontrolliert durchsucht … ${scan.completedHosts||0}/${scan.totalHosts||254}`;if(scan.state==='complete'){clearTimeout(appState.scanTimer);appState.scanTimer=null;appState.scanId=null;$('#scan-progress').hidden=true;$('#cancel-scan').hidden=true;$('#start-scan').disabled=false;renderDiscovery(scan.results||[],id,false);return;}if(['failed','cancelled'].includes(scan.state)){throw new Error('scan-failed');}}catch{clearTimeout(appState.scanTimer);appState.scanTimer=null;appState.scanId=null;$('#scan-progress').hidden=true;$('#cancel-scan').hidden=true;$('#start-scan').disabled=false;toast('Netzwerksuche fehlgeschlagen');return;}appState.scanTimer=setTimeout(()=>pollScan(id),1800);}
  async function openConfiguredDiscovery(item){if(!appState.adminCameras.length)await loadAdminCameras();const camera=appState.adminCameras.find(candidate=>candidate.id===item.configuredCameraId);if(camera)openConnectionDialog(camera);else toast('Gespeicherte Kamera konnte nicht geladen werden');}
  function profileSummary(profiles=[]){
    if(!profiles.length)return 'Profile nach Anmeldung prüfen';
    const usable=profiles.filter(profile=>profile.streamPath);
    const representative=(usable.length?usable:profiles)[0];
    const detail=[representative.codec?.toUpperCase(),representative.width&&representative.height?`${representative.width}×${representative.height}`:''].filter(Boolean).join(' · ');
    return `${profiles.length} ${profiles.length===1?'Profil':'Profile'}${detail?` · ${detail}`:''}`;
  }
  function renderDiscovery(items,scanId,running=false){
    appState.discoveryItems=items;
    appState.discoveryResultScanId=scanId;
    const list=$('#discovery-list');
    list.replaceChildren();
    if(!items.length){
      list.innerHTML=running?'<div class="empty-state"><h3>Suche läuft</h3><p>Treffer erscheinen bereits während der Prüfung.</p></div>':'<div class="empty-state"><h3>Keine standardisierte Kamera gefunden</h3><p>Sie können eine bekannte RTSP-, HLS-, MJPEG- oder Snapshot-Quelle manuell hinzufügen.</p></div>';
      return;
    }
    items.forEach(item=>{
      const row=document.createElement('article');
      row.className='device-row';
      const cloud=item.origin==='cloud';
      const recorder=item.origin==='recorder';
      const cloudName={netatmo:'Netatmo',blink:'Blink',czeview:'CZEview'}[item.provider]||item.provider;
      const protocols=cloud?[`${cloudName} Cloud`]:recorder?[item.deviceKind==='recorder'?'SANNCE NVR':'NVR-Kanal']:[item.onvif?'ONVIF':'',item.rtsp?'RTSP':''].filter(Boolean);
      const configured=Boolean(item.configuredCameraId);
      const canProbe=!recorder&&!configured&&(cloud
        ?item.streamSupport!=='unsupported'&&(item.provider!=='blink'||item.streamSupport!=='verified')
        :(item.onvif||item.onvifPort||item.openPorts?.some(port=>[80,443,2020,8000,8080,8899,10080].includes(port))));
      const preview=item.previewAvailable
        ?`<img class="device-preview" src="/api/admin/discovery/scans/${encodeURIComponent(scanId)}/devices/${encodeURIComponent(item.id)}/preview?t=${Date.now()}" alt="Vorschau ${escapeHtml(item.model)}">`
        :`<div class="device-preview is-empty">${item.previewError?'Stream erkannt, aber kein Frame':'Keine Vorschau'}</div>`;
      const locationText=cloud?`${item.accountLabel} · ${item.name}`:recorder&&item.channel?`${item.address} · Kanal ${item.channel}`:item.address;
      const details=cloud
        ?`<span>${item.streamSupport==='verified'?'Livebild bestätigt':item.provider==='blink'&&item.previewVerified?'Cloud-Vorschau bestätigt · Live optional prüfen':item.streamSupport==='unsupported'?'Kein freigegebener Livezugriff':'Livebild noch prüfen'}</span>${item.reason?`<span>${escapeHtml(item.reason)}</span>`:''}`
        :recorder
          ?item.deviceKind==='recorder'
            ?`<span>${item.detectedChannels||0} Kanäle erkannt · ${item.readyCount||0} Streams bereit</span><span>PoE-Kameras werden über den Recorder erkannt – interne IPs sind nicht erforderlich</span>`
            :`<span>${escapeHtml(profileSummary(item.profiles))}</span><span>${item.ready?'Stream über Recorder bereit':item.detected&&item.profiles?.[0]?.codec==='h265'?'Kanal erkannt · Zweitstream muss auf H.264 umgestellt werden':'Kanal derzeit offline'}</span>`
          :`<span>${escapeHtml(profileSummary(item.profiles))}</span><span>Ports: ${(item.openPorts||[]).join(', ')}</span>`;
      const selectLabel=recorder&&item.deviceKind==='recorder'?'Recorder erkannt':configured?'Bereits hinzugefügt':cloud?(item.importAllowed?'Hinzufügen':'Erst prüfen'):recorder?(item.importAllowed?'Hinzufügen':'Nicht bereit'):'Auswählen';
      const proofBadge=item.liveVerified?'<span class="connection-badge">Echte Videoframes bestätigt</span>':item.provider==='blink'&&item.previewVerified?'<span class="connection-badge">Passives Cloud-Vorschaubild bestätigt</span>':'';
      row.innerHTML=`${preview}<div class="device-description"><h3>${escapeHtml(item.manufacturer)} ${escapeHtml(item.model)}</h3><div class="device-meta"><span>${escapeHtml(locationText)}</span>${protocols.map(value=>`<span class="protocol-pill">${value}</span>`).join('')}${details}${proofBadge}${configured?`<span class="connection-badge">Bereits hinzugefügt: ${escapeHtml(item.configuredName||'Kamera')}</span>`:''}</div></div><div class="discovery-actions">${canProbe?`<button type="button" data-probe>${item.provider==='blink'?'Livebild bewusst prüfen':'Streams & Vorschau prüfen'}</button>`:''}<button type="button" class="primary" data-select ${(cloud&&!configured&&!item.importAllowed)||(recorder&&item.deviceKind==='recorder')||(recorder&&!configured&&!item.importAllowed)?'disabled':''}>${selectLabel}</button></div>`;
      const image=$('img.device-preview',row);
      image?.addEventListener('error',()=>{
        if(image.dataset.retried==='true')return;
        image.dataset.retried='true';
        window.setTimeout(()=>{image.src=image.src.replace(/([?&])t=\d+/,`$1t=${Date.now()}`);},3000);
      });
      $('[data-probe]',row)?.addEventListener('click',()=>openDiscoveryProbe(item,scanId));
      $('[data-select]',row).addEventListener('click',()=>configured?(cloud?toast('Diese Cloud-Kamera ist bereits in Camera Hub enthalten'):openConfiguredDiscovery(item)):((cloud||recorder)?openCloudImportDialog(item,scanId):openCameraDialog(item)));
      list.append(row);
    });
  }
  function openCloudImportDialog(item,scanId){
    const suggested=item.name||(item.origin==='recorder'?`SANNCE Kanal ${item.channel}`:item.model||'Cloud-Kamera');
    const form=$('#cloud-import-form');
    appState.cloudImportContext={item,scanId};
    form.reset();
    form.elements.name.value=suggested;
    $('#cloud-import-target').textContent=item.origin==='recorder'?`${item.manufacturer} ${item.model} · ${item.address}`:`${item.manufacturer} ${item.model} · ${item.accountLabel}`;
    $('#cloud-import-error').textContent='';
    $('#cloud-import-dialog').showModal();
  }
  async function importCloudCamera(event){
    event.preventDefault();
    const context=appState.cloudImportContext;
    if(!context)return;
    const {item,scanId}=context;
    const form=event.currentTarget,submit=form.querySelector('[type=submit]'),cancel=form.querySelector('[data-close-dialog]');
    const suggested=item.name||(item.origin==='recorder'?`SANNCE Kanal ${item.channel}`:item.model||'Cloud-Kamera');
    const name=form.elements.name.value.trim()||suggested;
    submit.disabled=true;
    cancel.disabled=true;
    form.setAttribute('aria-busy','true');
    $('#cloud-import-error').textContent='';
    try{
      await adminApi(
        `/api/admin/discovery/scans/${encodeURIComponent(scanId)}/devices/${encodeURIComponent(item.id)}/import`,
        {method:'POST',body:JSON.stringify({name:name.trim()||suggested})},
        {
          before:()=>{$('#cloud-import-dialog').close();appState.cloudImportContext=context;},
          after:()=>{if(!$('#cloud-import-dialog').open)$('#cloud-import-dialog').showModal();}
        }
      );
      item.configuredCameraId='imported';item.configuredName=name;
      renderDiscovery(appState.discoveryItems,scanId,false);
      if($('#cloud-import-dialog').open)$('#cloud-import-dialog').close();
      appState.cloudImportContext=null;
      await loadAdminCameras();
      await loadCameras();
      toast(item.origin==='recorder'?'Recorder-Kanal hinzugefügt':'Cloud-Kamera hinzugefügt');
    }catch(error){
      appState.cloudImportContext=context;
      if(!$('#cloud-import-dialog').open)$('#cloud-import-dialog').showModal();
      if(error.code!=='reauth-cancelled')$('#cloud-import-error').textContent=`Hinzufügen fehlgeschlagen: ${error.code}`;
    }finally{submit.disabled=false;cancel.disabled=false;form.removeAttribute('aria-busy');}
  }
  function openDiscoveryProbe(item,scanId){
    const form=$('#discovery-auth-form');
    form.reset();
    appState.discoveryDevice={item,scanId};
    const cloud=item.origin==='cloud';
    $('#discovery-auth-target').textContent=`${item.manufacturer} ${item.model} · ${cloud?item.accountLabel:item.address}`;
    form.elements.username.closest('label').hidden=cloud;
    form.elements.password.closest('label').hidden=cloud;
    $('#discovery-auth-state').textContent=cloud?(item.provider==='blink'?'Diese bewusste Prüfung weckt die Blink-Kamera einmalig und beendet den Livezugriff nach dem ersten Prüfframe.':'Camera Hub fordert kurzzeitig einen Live-Stream an und speichert genau ein Prüfbild.'):'Zugangsdaten werden nur für diese Prüfung verwendet.';
    $('#discovery-auth-error').textContent='';
    $('#discovery-auth-dialog').showModal();
  }
  async function probeDiscovery(event){
    event.preventDefault();
    const context=appState.discoveryDevice;
    if(!context)return;
    const form=event.currentTarget;
    const submit=$('button[type="submit"]',form);
    const cancel=$('[data-close-dialog]',form);
    submit.disabled=true;
    cancel.disabled=true;
    form.setAttribute('aria-busy','true');
    $('#discovery-auth-state').textContent=context.item.origin==='cloud'?'Cloud-Stream und echte Videoframes werden geprüft …':'ONVIF-Profile und echte Videoframes werden geprüft …';
    $('#discovery-auth-error').textContent='';
    const payload={username:form.elements.username.value,password:form.elements.password.value};
    try{
      const item=await adminApi(
        `/api/admin/discovery/scans/${encodeURIComponent(context.scanId)}/devices/${encodeURIComponent(context.item.id)}/probe`,
        {method:'POST',body:JSON.stringify(payload)},
        {
          before:()=>{$('#discovery-auth-dialog').close();appState.discoveryDevice=context;},
          after:()=>{if(!$('#discovery-auth-dialog').open)$('#discovery-auth-dialog').showModal();}
        }
      );
      const index=appState.discoveryItems.findIndex(candidate=>candidate.id===item.id);
      if(index>=0)appState.discoveryItems[index]=item;
      renderDiscovery(appState.discoveryItems,context.scanId,false);
      if($('#discovery-auth-dialog').open)$('#discovery-auth-dialog').close();
      appState.discoveryDevice=null;
      toast(item.previewAvailable?'Streams erkannt · echte Vorschau bestätigt':'Streamprofile erkannt · Vorschau nicht verfügbar');
    }catch(error){
      appState.discoveryDevice=context;
      if(!$('#discovery-auth-dialog').open)$('#discovery-auth-dialog').showModal();
      $('#discovery-auth-state').textContent='Prüfung nicht erfolgreich.';
      $('#discovery-auth-error').textContent=error.code==='reauth-cancelled'?'Sicherheitsbestätigung abgebrochen.':error.code==='onvif-authentication-failed'?'Anmeldung an der Kamera fehlgeschlagen.':`Prüfung fehlgeschlagen: ${error.code}`;
    }finally{
      payload.username='';
      payload.password='';
      form.elements.password.value='';
      submit.disabled=false;
      cancel.disabled=false;
      form.removeAttribute('aria-busy');
    }
  }
  function openCameraDialog(item={}){
    const form=$('#camera-form'),profiles=[...(item.profiles||[])].filter(profile=>profile.streamPath);
    profiles.sort((left,right)=>((left.width||0)*(left.height||0))-((right.width||0)*(right.height||0)));
    const low=profiles[0],high=profiles.at(-1),tapoCompatible=Boolean(item.rtsp&&item.openPorts?.includes(2020));
    form.reset();form.elements.name.value=item.model&&item.model!=='Unbekannt'?item.model:'Neue Kamera';form.elements.address.value=item.address||'';
    form.elements.port.value=item.rtsp?(low?.streamPort||item.openPorts?.find(port=>[554,8554,10554].includes(port))||554):554;
    form.elements.lowSourcePath.value=low?.streamPath||(tapoCompatible?'/stream2':'');
    form.elements.highSourcePath.value=high?.streamPath&&high?.streamPath!==low?.streamPath?high.streamPath:(tapoCompatible?'/stream1':'');
    form.elements.onvifScheme.value=item.onvifPort===443?'https':'http';
    form.elements.onvifPort.value=item.onvifPort||(tapoCompatible?2020:80);
    form.elements.onvifPath.value='/onvif/device_service';
    if(['h264','h265','mjpeg'].includes(low?.codec))form.elements.codec.value=low.codec;
    form.elements.manufacturer.value=item.manufacturer||'';form.elements.model.value=item.model||'';
    $('#source-test').textContent=tapoCompatible?'ONVIF-Port 2020 erkannt · Tapo-kompatible Stream-Pfade vorbelegt. Bitte Quelle testen.':'Bitte testen Sie die Quelle vor dem Hinzufügen.';
    $('#camera-error').textContent='';form.dataset.tested='false';$('#camera-dialog').showModal();
  }
  function cameraPayload(){const form=$('#camera-form'),data=new FormData(form);return Object.fromEntries([...data.entries()].map(([key,value])=>[key,['port','onvifPort'].includes(key)?Number(value):value]));}
  async function testSource(){const payload=cameraPayload();$('#source-test').textContent='Quelle wird gelesen …';try{const result=await adminApi('/api/admin/cameras/test-source',{method:'POST',body:JSON.stringify(payload)});if(!result.ok)throw new Error(result.error);$('#camera-form').dataset.tested='true';$('#source-test').textContent=`Videoframes bestätigt · ${String(result.codec).toUpperCase()} · ${result.width}×${result.height} · ${result.packets} Pakete`;}catch(error){$('#camera-form').dataset.tested='false';$('#source-test').textContent=`Kein Frame-Nachweis: ${error.code||error.message}`;}}
  async function addCamera(event){event.preventDefault();const form=event.currentTarget;if(form.dataset.tested!=='true'){ $('#camera-error').textContent='Bitte zuerst einen erfolgreichen Frame-Test durchführen.';return;}try{await adminApi('/api/admin/cameras',{method:'POST',body:JSON.stringify(cameraPayload())});form.reset();$('#camera-dialog').close();toast('Kamera wurde hinzugefügt');await loadAdminCameras();await loadCameras();showView('overview');}catch(error){$('#camera-error').textContent=`Hinzufügen fehlgeschlagen: ${error.code||'unerwarteter-fehler'}`;}}

  const zoneState={cameraId:'',revision:0,zones:[],draft:[],kind:'alarm',request:0,detection:{enabled:false,supported:false,schedules:[]}};
  const DETECTION_WEEKDAYS=['Montag','Dienstag','Mittwoch','Donnerstag','Freitag','Samstag','Sonntag'];
  const defaultZoneDetection=zoneId=>({zoneId,enabled:false,sensitivity:50,minAreaPercent:1.5,confirmationSeconds:1,quietSeconds:5,cooldownSeconds:30,snapshotEnabled:false,schedules:[]});
  function renderDetectionSchedules(container,schedules,onChange){
    container.replaceChildren();
    schedules.forEach((schedule,index)=>{
      const row=document.createElement('div');row.className='detection-schedule';
      row.innerHTML=`<label>Tag<select>${DETECTION_WEEKDAYS.map((name,day)=>`<option value="${day}" ${day===schedule.weekday?'selected':''}>${name}</option>`).join('')}</select></label><label>Von<input type="time" value="${minuteValue(schedule.startMinute)}"></label><label>Bis<input type="time" value="${minuteValue(schedule.endMinute)}"></label><button type="button" aria-label="Zeitfenster löschen">×</button>`;
      const inputs=$$('select,input',row);inputs.forEach(input=>input.addEventListener('change',()=>{schedule.weekday=Number(inputs[0].value);schedule.startMinute=timeMinute(inputs[1].value);const end=timeMinute(inputs[2].value);schedule.endMinute=end===0?1440:end;onChange();}));
      $('button',row).addEventListener('click',()=>{schedules.splice(index,1);onChange();});
      container.append(row);
    });
    if(!schedules.length)container.innerHTML='<p>Kein Zeitfenster · immer aktiv</p>';
  }
  function addDetectionSchedule(schedules,onChange){schedules.push({weekday:new Date().getDay()===0?6:new Date().getDay()-1,startMinute:480,endMinute:1200});onChange();}
  function activeZoneCameras(){return appState.profileCameraOptions.filter(camera=>camera.enabled);}
  function populateZoneSelect(){const select=$('#zone-camera'),current=select.value,cameras=activeZoneCameras();select.replaceChildren();cameras.forEach(camera=>{const option=new Option(camera.name,camera.id);select.add(option);});if(cameras.some(camera=>camera.id===current))select.value=current;}
  async function loadZoneCamera(){const id=$('#zone-camera').value||activeZoneCameras()[0]?.id;if(!id)return;const request=++zoneState.request;zoneState.cameraId=id;zoneState.draft=[];zoneState.zones=[];zoneState.detection={enabled:false,supported:false,schedules:[]};renderZoneList();$('#zone-empty').hidden=false;$('#zone-empty').textContent='Vorschau wird geladen';const image=$('#zone-preview');image.hidden=true;image.onload=()=>{if(request!==zoneState.request||zoneState.cameraId!==id)return;$('#zone-empty').hidden=true;image.hidden=false;resizeCanvas();};image.onerror=()=>{if(request!==zoneState.request||zoneState.cameraId!==id)return;$('#zone-empty').textContent='Keine Vorschau verfügbar – die Quelle bleibt unverändert.';resizeCanvas();};image.src=`/api/admin/cameras/${encodeURIComponent(id)}/preview?t=${Date.now()}`;try{const [data,detection]=await Promise.all([api(`/api/admin/cameras/${encodeURIComponent(id)}/zones`),api(`/api/admin/cameras/${encodeURIComponent(id)}/detection`)]);if(request!==zoneState.request||zoneState.cameraId!==id)return;zoneState.revision=data.revision;const settings=new Map((detection.zones||[]).map(item=>[item.zoneId,item]));zoneState.zones=data.zones.map(zone=>({...zone,detection:settings.get(zone.id)||defaultZoneDetection(zone.id)}));zoneState.detection={enabled:detection.enabled,supported:detection.supported,schedules:detection.schedules||[]};renderCameraDetection();renderZoneList();drawZones();}catch(error){if(request===zoneState.request)toast(`Zonen konnten nicht geladen werden: ${error.code}`);}}
  function renderCameraDetection(){const supported=zoneState.detection.supported;$('#detection-camera-enabled').checked=zoneState.detection.enabled;$('#detection-camera-enabled').disabled=!supported;$('#detection-camera-support').textContent=supported?'Dauerstream · unterstützt':'On-Demand/Snapshot · wird nicht geweckt';renderDetectionSchedules($('#detection-camera-schedules'),zoneState.detection.schedules,renderCameraDetection);}
  function resizeCanvas(){const canvas=$('#zone-canvas'),rect=canvas.getBoundingClientRect(),dpr=Math.min(devicePixelRatio||1,2);canvas.width=Math.max(1,Math.round(rect.width*dpr));canvas.height=Math.max(1,Math.round(rect.height*dpr));drawZones();}
  function zoneImageRect(){const canvas=$('#zone-canvas'),image=$('#zone-preview'),rect=canvas.getBoundingClientRect(),dpr=canvas.width/Math.max(1,rect.width);if(image.hidden||!image.naturalWidth||!image.naturalHeight)return{x:0,y:0,width:canvas.width,height:canvas.height,dpr};const scale=Math.min(rect.width/image.naturalWidth,rect.height/image.naturalHeight),width=image.naturalWidth*scale*dpr,height=image.naturalHeight*scale*dpr;return{x:(canvas.width-width)/2,y:(canvas.height-height)/2,width,height,dpr};}
  function drawPolygon(context,points,kind,draft=false){if(!points.length)return;const area=zoneImageRect();context.beginPath();points.forEach((point,index)=>{const x=area.x+point.x*area.width,y=area.y+point.y*area.height;index?context.lineTo(x,y):context.moveTo(x,y);});if(!draft&&points.length>2)context.closePath();context.strokeStyle=kind==='alarm'?'#ffbd63':'#6aa7ff';context.fillStyle=kind==='alarm'?'#ffbd6326':'#6aa7ff26';context.lineWidth=3*area.dpr;if(!draft)context.fill();context.stroke();points.forEach(point=>{context.beginPath();context.arc(area.x+point.x*area.width,area.y+point.y*area.height,5*area.dpr,0,Math.PI*2);context.fillStyle=context.strokeStyle;context.fill();});}
  function drawZones(){const canvas=$('#zone-canvas'),context=canvas.getContext('2d');context.clearRect(0,0,canvas.width,canvas.height);zoneState.zones.filter(zone=>zone.enabled).forEach(zone=>drawPolygon(context,zone.points,zone.kind));drawPolygon(context,zoneState.draft,zoneState.kind,true);}
  function addZonePoint(event){const canvas=$('#zone-canvas'),rect=canvas.getBoundingClientRect(),area=zoneImageRect(),dpr=area.dpr,x=(event.clientX-rect.left)*dpr,y=(event.clientY-rect.top)*dpr;if(x<area.x||x>area.x+area.width||y<area.y||y>area.y+area.height){toast('Bitte einen Punkt innerhalb des Kamerabilds setzen');return;}zoneState.draft.push({x:(x-area.x)/area.width,y:(y-area.y)/area.height});drawZones();}
  function addZoneCoordinate(){const x=Number($('#zone-x').value),y=Number($('#zone-y').value);if(!Number.isFinite(x)||!Number.isFinite(y)||x<0||x>100||y<0||y>100){toast('Koordinaten müssen zwischen 0 und 100 liegen');return;}zoneState.draft.push({x:x/100,y:y/100});drawZones();toast('Zonenpunkt hinzugefügt');}
  function completeZone(){if(zoneState.draft.length<3){toast('Mindestens drei Punkte erforderlich');return;}const id=crypto.randomUUID();zoneState.zones.push({id,name:$('#zone-name').value.trim()||'Zone',kind:zoneState.kind,points:[...zoneState.draft],enabled:true,detection:defaultZoneDetection(id)});zoneState.draft=[];renderZoneList();drawZones();}
  function renderZoneList(){const list=$('#zone-list');list.replaceChildren();zoneState.zones.forEach((zone,index)=>{zone.detection=zone.detection||defaultZoneDetection(zone.id);const row=document.createElement('div');row.className='zone-entry';row.dataset.kind=zone.kind;row.innerHTML=`<i class="zone-color"></i><span>${escapeHtml(zone.name)} · ${zone.kind==='alarm'?'Alarm':'Alarmfrei'}</span><label class="zone-enabled"><input data-zone-active type="checkbox" ${zone.enabled?'checked':''}> Aktiv</label><button data-delete-zone aria-label="Zone löschen">×</button>`;$('[data-zone-active]',row).addEventListener('change',event=>{zone.enabled=event.currentTarget.checked;drawZones();});$('[data-delete-zone]',row).addEventListener('click',()=>{zoneState.zones.splice(index,1);renderZoneList();drawZones();});if(zone.kind==='alarm'){const details=document.createElement('details');details.className='zone-detection-details';details.innerHTML=`<summary>Erkennung für diese Zone</summary><div class="zone-detection-grid"><label class="check-label"><input data-field="enabled" type="checkbox" ${zone.detection.enabled?'checked':''}> Bewegungserkennung aktiv</label><label>Empfindlichkeit<input data-field="sensitivity" type="number" min="1" max="100" value="${zone.detection.sensitivity}"></label><label>Mindestfläche (%)<input data-field="minAreaPercent" type="number" min=".1" max="100" step=".1" value="${zone.detection.minAreaPercent}"></label><label>Bestätigung (s)<input data-field="confirmationSeconds" type="number" min=".1" max="60" step=".1" value="${zone.detection.confirmationSeconds}"></label><label>Ruhe bis Ende (s)<input data-field="quietSeconds" type="number" min=".5" max="300" step=".5" value="${zone.detection.quietSeconds}"></label><label>Sperrzeit (s)<input data-field="cooldownSeconds" type="number" min="0" max="3600" step="1" value="${zone.detection.cooldownSeconds}"></label><label class="check-label"><input data-field="snapshotEnabled" type="checkbox" ${zone.detection.snapshotEnabled?'checked':''}> Verschlüsseltes Beweisbild speichern</label></div><div class="detection-schedules"></div><button data-add-schedule type="button">Zonen-Zeitfenster hinzufügen</button>`;$$('[data-field]',details).forEach(input=>input.addEventListener('change',()=>{zone.detection[input.dataset.field]=input.type==='checkbox'?input.checked:Number(input.value);}));const renderSchedules=()=>renderDetectionSchedules($('.detection-schedules',details),zone.detection.schedules,renderSchedules);renderSchedules();$('[data-add-schedule]',details).addEventListener('click',()=>addDetectionSchedule(zone.detection.schedules,renderSchedules));row.append(details);}list.append(row);});}
  async function saveZones(){const button=$('#zone-save');if(button.disabled)return;button.disabled=true;button.setAttribute('aria-busy','true');try{for(const schedule of [...zoneState.detection.schedules,...zoneState.zones.flatMap(zone=>zone.detection?.schedules||[])])if(schedule.endMinute===schedule.startMinute)throw new ApiError(422,'zeitfenster-darf-nicht-leer-sein');const result=await adminApi(`/api/admin/cameras/${encodeURIComponent(zoneState.cameraId)}/zones`,{method:'PUT',body:JSON.stringify({revision:zoneState.revision,zones:zoneState.zones.map(({detection,...zone})=>zone)})});zoneState.revision=result.revision;await adminApi(`/api/admin/cameras/${encodeURIComponent(zoneState.cameraId)}/detection`,{method:'PUT',body:JSON.stringify({enabled:zoneState.detection.enabled,schedules:zoneState.detection.schedules,zones:zoneState.zones.map(zone=>({...zone.detection,zoneId:zone.id}))})});toast('Zonen und Erkennung wurden gespeichert');}catch(error){toast(`Speichern fehlgeschlagen: ${error.code}`);}finally{button.disabled=false;button.removeAttribute('aria-busy');}}

  const EVENT_STATUS_LABELS={pending:'Wird beobachtet',open:'Offen',resolved:'Behoben'};
  function eventTime(value){return value?new Intl.DateTimeFormat('de-DE',{dateStyle:'short',timeStyle:'short'}).format(new Date(value)):'–';}
  function eventDuration(value){let seconds=Math.max(0,Number(value)||0);const days=Math.floor(seconds/86400);seconds%=86400;const hours=Math.floor(seconds/3600);seconds%=3600;const minutes=Math.floor(seconds/60);if(days)return`${days} T ${hours} Std`;if(hours)return`${hours} Std ${minutes} Min`;return`${minutes} Min`;}
  function renderEvents(data){
    const summary=data.summary||{};$('#event-summary').innerHTML=`<span><strong>${Number(summary.open||0)}</strong> offen</span><span><strong>${Number(summary.pending||0)}</strong> in Beobachtung</span><span><strong>${Number(summary.resolved||0)}</strong> behoben</span>`;
    const list=$('#event-list');list.replaceChildren();
    for(const event of data.events||[]){
      const article=document.createElement('article');article.className='event-entry';article.dataset.status=event.status;
      article.innerHTML=`<i class="event-marker" aria-hidden="true"></i><div><h4>${escapeHtml(event.title)}</h4><p>${escapeHtml(event.description)}</p><p><strong>Empfehlung:</strong> ${escapeHtml(event.recommendation)}</p><div class="event-meta"><span>Beginn ${escapeHtml(eventTime(event.startedAt))}</span><span>Dauer ${escapeHtml(eventDuration(event.durationSeconds))}</span><span>Zuletzt ${escapeHtml(eventTime(event.lastSeenAt))}</span>${event.cameraId?`<span>Kamera ${escapeHtml(event.cameraName||event.cameraId)}</span>`:''}${event.accountId?`<span>Cloud-Konto ${escapeHtml(event.accountLabel||event.accountId)}</span>`:''}</div></div><span class="event-state">${escapeHtml(EVENT_STATUS_LABELS[event.status]||event.status)}</span>`;
      if(event.type==='zone.motion'&&event.details?.snapshotAvailable){const button=document.createElement('button');button.textContent='Beweisbild öffnen';button.addEventListener('click',()=>window.open(`/api/motion-events/${encodeURIComponent(event.id)}/snapshot`,'_blank','noopener'));$('div',article).append(button);}
      list.append(article);
    }
    if(!list.children.length)list.innerHTML='<div class="empty-state"><h3>Keine Ereignisse</h3><p>Für diesen Filter liegen keine Betriebsereignisse vor.</p></div>';
  }
  async function loadEvents(){try{const params=new URLSearchParams({status:$('#event-filter').value}),type=$('#event-type-filter').value;if(type)params.set('eventType',type);renderEvents(await api(`/api/events?${params}`));}catch(error){$('#event-list').innerHTML=`<div class="empty-state">Ereignisse konnten nicht geladen werden: ${escapeHtml(error.code)}</div>`;}}
  const DETECTION_STATE_LABELS={offline:'Nicht erreichbar',starting:'Startet',learning:'Anlernphase',active:'Aktiv',paused:'Pausiert',degraded:'Eingeschränkt',error:'Fehler'};
  async function loadDetectionStatus(){try{const data=await api('/api/detection/status');appState.detection=data;$('#detection-mode').value=data.mode;$('#detection-worker-state').textContent=DETECTION_STATE_LABELS[data.worker?.state]||data.worker?.state||'Unbekannt';$('#detection-active-cameras').textContent=String(data.worker?.activeCameras||0);$('#detection-delay').textContent=data.worker?.processingDelayMs!=null?`${data.worker.processingDelayMs} ms`:'–';$('#detection-cpu').textContent=data.worker?.cpuPercent!=null?`${Number(data.worker.cpuPercent).toFixed(1)} %`:'–';$('#detection-memory').textContent=data.worker?.memoryBytes!=null?`${(Number(data.worker.memoryBytes)/1048576).toFixed(0)} MB`:'–';$('#detection-open-events').textContent=String(data.openMotionEvents||0);$('#detection-last-error').textContent=data.worker?.lastError?`Letzter Workerfehler: ${data.worker.lastError}`:`${data.configuredCameras||0} Kameras und ${data.configuredZones||0} Zonen vorbereitet · Zeitzone ${data.timezone}`;}catch(error){$('#detection-worker-state').textContent=`Fehler: ${error.code}`;}}
  async function saveDetectionMode(){try{const mode=$('#detection-mode').value;await adminApi('/api/owner/detection',{method:'PUT',body:JSON.stringify({mode})});toast(mode==='off'?'Erkennung ausgeschaltet':mode==='observe'?'Beobachtungsmodus aktiv':'Alarmierung scharf geschaltet');await loadDetectionStatus();}catch(error){if(error.code!=='reauth-cancelled')toast(`Betriebsart nicht geändert: ${error.code}`);}}
  function playMotionSound(){if(localStorage.getItem('pkws-motion-sound')!=='1')return;try{const context=new (window.AudioContext||window.webkitAudioContext)(),oscillator=context.createOscillator(),gain=context.createGain();oscillator.frequency.value=880;gain.gain.value=.08;oscillator.connect(gain);gain.connect(context.destination);oscillator.start();gain.gain.exponentialRampToValueAtTime(.001,context.currentTime+.5);oscillator.stop(context.currentTime+.5);}catch{}}
  function showMotionAlert(event){appState.motionAlert=event;$('#motion-alert-title').textContent=`${event.cameraName||'Kamera'} · ${event.zoneName||'Alarmzone'}`;$('#motion-alert-time').textContent=`Erkannt ${eventTime(event.startedAt)}`;$('#motion-alert-banner').hidden=false;playMotionSound();}
  function updateMotionAlerts(){const enabled=$('#motion-browser-alerts').checked;localStorage.setItem('pkws-motion-alerts',enabled?'1':'0');appState.motionSource?.close();appState.motionSource=null;if(!enabled||!appState.csrf)return;const source=new EventSource('/api/detection/events/stream',{withCredentials:true});source.addEventListener('zone.motion',message=>{try{showMotionAlert(JSON.parse(message.data));}catch{}});appState.motionSource=source;}
  function initializeMotionAlerts(){const alerts=localStorage.getItem('pkws-motion-alerts')==='1',sound=localStorage.getItem('pkws-motion-sound')==='1';$('#motion-browser-alerts').checked=alerts;$('#motion-browser-sound').checked=sound;updateMotionAlerts();}
  function renderWebhooks(){
    const list=$('#webhook-list');list.replaceChildren();
    for(const target of appState.webhookTargets){
      const article=document.createElement('article');article.className='webhook-entry';article.dataset.enabled=String(target.enabled);
      const delivery=target.lastDeliveryStatus?`Letzte Zustellung: ${target.lastDeliveryStatus}${target.lastErrorCode?` · ${target.lastErrorCode}`:''}`:'Noch keine Zustellung';
      article.innerHTML=`<div><h4>${escapeHtml(target.label)}</h4><code>${escapeHtml(target.url)}</code><p>${target.enabled?'Aktiv':'Deaktiviert'} · ${escapeHtml(delivery)}</p></div><div class="webhook-actions"><button data-action="test">Testen</button><button data-action="edit">Bearbeiten</button><button data-action="toggle">${target.enabled?'Deaktivieren':'Aktivieren'}</button><button data-action="rotate">Geheimnis erneuern</button><button data-action="delete">Löschen</button></div>`;
      $('[data-action=test]',article).addEventListener('click',()=>testWebhook(target));$('[data-action=edit]',article).addEventListener('click',()=>openWebhookDialog(target));$('[data-action=toggle]',article).addEventListener('click',()=>toggleWebhook(target));$('[data-action=rotate]',article).addEventListener('click',()=>rotateWebhookSecret(target));$('[data-action=delete]',article).addEventListener('click',()=>deleteWebhook(target));list.append(article);
    }
    if(!list.children.length)list.innerHTML='<div class="empty-state">Noch keine Webhooks eingerichtet.</div>';
  }
  async function loadWebhooks(){if(!appState.permissions.manageUsers)return;try{const data=await api('/api/owner/webhooks');appState.webhookTargets=data.targets||[];renderWebhooks();}catch(error){$('#webhook-list').innerHTML=`<div class="empty-state">Webhooks konnten nicht geladen werden: ${escapeHtml(error.code)}</div>`;}}
  function renderDisplayDeviceProfiles(){
    const list=$('#display-device-profiles');list.replaceChildren();const options=new Map(appState.displayDeviceProfileOptions.map(item=>[item.id,item])),selected=appState.displayDeviceDraftProfiles.filter(id=>options.has(id)),remaining=appState.displayDeviceProfileOptions.filter(item=>!selected.includes(item.id)).map(item=>item.id);
    [...selected,...remaining].forEach(profileId=>{const profile=options.get(profileId),checked=selected.includes(profileId),index=selected.indexOf(profileId),row=document.createElement('div');row.className='device-profile-option';const label=document.createElement('label'),input=document.createElement('input'),name=document.createElement('span');input.type='checkbox';input.checked=checked;name.textContent=profile.name;label.append(input,name);const moves=document.createElement('div');moves.className='profile-camera-moves';for(const [direction,text] of [[-1,'↑'],[1,'↓']]){const button=document.createElement('button');button.type='button';button.textContent=text;button.disabled=!checked||(direction<0?index===0:index===selected.length-1);button.addEventListener('click',()=>{const from=appState.displayDeviceDraftProfiles.indexOf(profileId),to=from+direction;if(to<0||to>=appState.displayDeviceDraftProfiles.length)return;[appState.displayDeviceDraftProfiles[from],appState.displayDeviceDraftProfiles[to]]=[appState.displayDeviceDraftProfiles[to],appState.displayDeviceDraftProfiles[from]];renderDisplayDeviceProfiles();});moves.append(button);}input.addEventListener('change',()=>{if(input.checked)appState.displayDeviceDraftProfiles.push(profileId);else appState.displayDeviceDraftProfiles=appState.displayDeviceDraftProfiles.filter(id=>id!==profileId);renderDisplayDeviceProfiles();});row.append(label,moves);list.append(row);});
    if(!appState.displayDeviceProfileOptions.length)list.innerHTML='<div class="empty-state">Legen Sie zuerst ein Anzeigeprofil an.</div>';
  }
  function renderDisplayDevices(){
    const list=$('#display-device-list');list.replaceChildren();
    appState.displayDevices.forEach(device=>{const row=document.createElement('article');row.className='display-device-row';row.dataset.enabled=String(device.enabled);const details=document.createElement('div'),actions=document.createElement('div');details.innerHTML=`<strong>${escapeHtml(device.name)}</strong><p>${device.enabled?'Aktiv':'Deaktiviert'} · ${device.paired?'gekoppelt':'nicht gekoppelt'} · ${device.profiles.map(item=>escapeHtml(item.name)).join(' → ')||'kein Profil'}</p>`;actions.className='display-device-actions';for(const [label,handler] of [['Bearbeiten',()=>openDisplayDeviceDialog(device)],['Koppeln',()=>createPairingCode(device)],['Widerrufen',()=>revokeDisplayDevice(device)],['Löschen',()=>deleteDisplayDevice(device)]]){const button=document.createElement('button');button.type='button';button.textContent=label;button.addEventListener('click',handler);actions.append(button);}row.append(details,actions);list.append(row);});
    if(!appState.displayDevices.length)list.innerHTML='<div class="empty-state">Noch keine Anzeigegeräte angelegt.</div>';
  }
  async function loadDisplayDevices(){
    if(appState.user?.role!=='owner')return;
    try{const data=await api('/api/owner/display-devices');appState.displayDevices=data.devices||[];appState.displayDeviceProfileOptions=data.profileOptions||[];renderDisplayDevices();}catch(error){$('#display-device-list').innerHTML=`<div class="empty-state">Anzeigegeräte konnten nicht geladen werden: ${escapeHtml(error.code)}</div>`;}
  }
  function openDisplayDeviceDialog(device=null){
    const form=$('#display-device-form');form.reset();form.elements.deviceId.value=device?.id||'';form.elements.name.value=device?.name||'';form.elements.enabled.checked=device?.enabled??true;appState.displayDeviceDraftProfiles=[...(device?.profileIds||[])];$('#display-device-title').textContent=device?'Anzeigegerät bearbeiten':'Anzeigegerät anlegen';$('#display-device-error').textContent='';renderDisplayDeviceProfiles();$('#display-device-dialog').showModal();
  }
  async function saveDisplayDevice(event){
    event.preventDefault();const form=event.currentTarget,id=form.elements.deviceId.value,body={name:form.elements.name.value.trim(),enabled:form.elements.enabled.checked,profileIds:appState.displayDeviceDraftProfiles};
    try{await adminApi(id?`/api/owner/display-devices/${encodeURIComponent(id)}`:'/api/owner/display-devices',{method:id?'PUT':'POST',body:JSON.stringify(body)});$('#display-device-dialog').close();await loadDisplayDevices();toast('Anzeigegerät gespeichert');}catch(error){if(error.code!=='reauth-cancelled')$('#display-device-error').textContent=`Speichern fehlgeschlagen: ${error.code}`;}
  }
  async function createPairingCode(device){
    try{const result=await adminApi(`/api/owner/display-devices/${encodeURIComponent(device.id)}/pairing-code`,{method:'POST'});$('#pairing-code').textContent=result.code;$('#display-route').textContent=`${location.origin}/display.html`;$('#pairing-code-dialog').showModal();}catch(error){if(error.code!=='reauth-cancelled')toast(`Kopplungscode fehlgeschlagen: ${error.code}`);}
  }
  async function revokeDisplayDevice(device){
    if(!confirm(`Alle Sitzungen von „${device.name}“ widerrufen?`))return;try{await adminApi(`/api/owner/display-devices/${encodeURIComponent(device.id)}/revoke`,{method:'POST'});await loadDisplayDevices();toast('Gerätesitzungen widerrufen');}catch(error){if(error.code!=='reauth-cancelled')toast(`Widerruf fehlgeschlagen: ${error.code}`);}
  }
  async function deleteDisplayDevice(device){
    if(!confirm(`Anzeigegerät „${device.name}“ löschen?`))return;try{await adminApi(`/api/owner/display-devices/${encodeURIComponent(device.id)}`,{method:'DELETE'});await loadDisplayDevices();toast('Anzeigegerät gelöscht');}catch(error){if(error.code!=='reauth-cancelled')toast(`Löschen fehlgeschlagen: ${error.code}`);}
  }
  function loadOperations(){loadDetectionStatus();loadEvents();loadWebhooks();loadDisplayDevices();}
  function showWebhookSecret(secret){$('#webhook-secret').textContent=secret;$('#webhook-secret-dialog').showModal();}
  function openWebhookDialog(target=null){
    const form=$('#webhook-form');form.reset();form.elements.targetId.value=target?.id||'';form.elements.label.value=target?.label||'';form.elements.url.value=target?.url||'';form.elements.enabled.checked=target?.enabled??true;
    const selected=new Set(target?.eventTypes||[]);$$('input[name=eventType]',form).forEach(input=>input.checked=!target||selected.has('*')||selected.has(input.value));$('#webhook-title').textContent=target?'Webhook bearbeiten':'Webhook hinzufügen';$('#webhook-error').textContent='';$('#webhook-dialog').showModal();
  }
  async function saveWebhook(event){
    event.preventDefault();const form=event.currentTarget,targetId=form.elements.targetId.value,eventTypes=$$('input[name=eventType]:checked',form).map(input=>input.value);if(!eventTypes.length){$('#webhook-error').textContent='Bitte mindestens einen Ereignistyp auswählen.';return;}
    const payload={label:form.elements.label.value.trim(),url:form.elements.url.value.trim(),enabled:form.elements.enabled.checked,eventTypes};
    try{const result=await adminApi(targetId?`/api/owner/webhooks/${encodeURIComponent(targetId)}`:'/api/owner/webhooks',{method:targetId?'PATCH':'POST',body:JSON.stringify(payload)});$('#webhook-dialog').close();await loadWebhooks();toast('Webhook gespeichert');if(result.secret)showWebhookSecret(result.secret);}catch(error){if(error.code!=='reauth-cancelled')$('#webhook-error').textContent=`Speichern fehlgeschlagen: ${error.code}`;}
  }
  async function testWebhook(target){try{const result=await adminApi(`/api/owner/webhooks/${encodeURIComponent(target.id)}/test`,{method:'POST'});toast(result.status==='delivered'?'Testnachricht zugestellt':`Test eingeplant · ${result.errorCode||result.status}`);await loadWebhooks();}catch(error){if(error.code!=='reauth-cancelled')toast(`Webhook-Test fehlgeschlagen: ${error.code}`);}}
  async function toggleWebhook(target){try{await adminApi(`/api/owner/webhooks/${encodeURIComponent(target.id)}`,{method:'PATCH',body:JSON.stringify({enabled:!target.enabled})});await loadWebhooks();}catch(error){if(error.code!=='reauth-cancelled')toast(`Änderung fehlgeschlagen: ${error.code}`);}}
  async function rotateWebhookSecret(target){if(!confirm(`Webhook-Geheimnis für „${target.label}“ erneuern? Das bisherige Geheimnis wird sofort ungültig.`))return;try{const result=await adminApi(`/api/owner/webhooks/${encodeURIComponent(target.id)}/rotate-secret`,{method:'POST'});showWebhookSecret(result.secret);}catch(error){if(error.code!=='reauth-cancelled')toast(`Erneuern fehlgeschlagen: ${error.code}`);}}
  async function deleteWebhook(target){if(!confirm(`Webhook „${target.label}“ löschen?`))return;try{await adminApi(`/api/owner/webhooks/${encodeURIComponent(target.id)}`,{method:'DELETE'});await loadWebhooks();toast('Webhook gelöscht');}catch(error){if(error.code!=='reauth-cancelled')toast(`Löschen fehlgeschlagen: ${error.code}`);}}
  async function createBackup(event){
    event.preventDefault();const form=event.currentTarget,passphrase=form.elements.passphrase.value;if(passphrase!==form.elements.confirmation.value){$('#backup-error').textContent='Die Passphrasen stimmen nicht überein.';return;}const submit=form.querySelector('[type=submit]');submit.disabled=true;$('#backup-error').textContent='';
    try{const response=await ownerFetch('/api/owner/backups',{method:'POST',body:JSON.stringify({passphrase})}),blob=await response.blob(),disposition=response.headers.get('Content-Disposition')||'',match=/filename="([^"]+)"/.exec(disposition),name=match?.[1]||`camera-hub-${VERSION}.pkwsbackup`,url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=name;document.body.append(link);link.click();link.remove();URL.revokeObjectURL(url);form.reset();$('#backup-dialog').close();toast('Verschlüsselte Sicherung heruntergeladen');}catch(error){if(error.code!=='reauth-cancelled')$('#backup-error').textContent=`Sicherung fehlgeschlagen: ${error.code}`;}finally{submit.disabled=false;}
  }
  function restoreFormData(form){const data=new FormData();data.append('archive',form.elements.archive.files[0]);data.append('passphrase',form.elements.passphrase.value);return data;}
  function resetRestoreValidation(){appState.restoreValidated=false;$('#restore-preview').hidden=true;$('#restore-preview').textContent='';$('#restore-submit').textContent='Archiv prüfen';}
  async function restoreBackup(event){
    event.preventDefault();const form=event.currentTarget,submit=$('#restore-submit');if(!form.elements.archive.files[0])return;submit.disabled=true;$('#restore-error').textContent='';
    try{if(!appState.restoreValidated){const response=await ownerFetch('/api/owner/backups/validate',{method:'POST',body:restoreFormData(form)}),result=await response.json();$('#restore-preview').textContent=`Gültige Sicherung · Camera Hub ${result.manifest.appVersion} · Schema ${result.schemaVersion} · erstellt ${eventTime(result.manifest.createdAt)}`;$('#restore-preview').hidden=false;appState.restoreValidated=true;submit.textContent='Jetzt wiederherstellen';return;}if(!confirm('Diese Sicherung jetzt übernehmen? Alle angemeldeten Geräte werden anschließend abgemeldet.'))return;const response=await ownerFetch('/api/owner/backups/restore',{method:'POST',body:restoreFormData(form)}),result=await response.json();toast(`Wiederhergestellt · Rückfallpunkt ${result.restorePoint}`);setTimeout(()=>location.reload(),1200);}catch(error){resetRestoreValidation();if(error.code!=='reauth-cancelled')$('#restore-error').textContent=`Wiederherstellung fehlgeschlagen: ${error.code}`;}finally{submit.disabled=false;}
  }

  function refreshDiagnostics(){const video=document.createElement('video');$('#diag-secure').textContent=window.isSecureContext?'Ja':'Nein';$('#diag-sw').textContent='serviceWorker'in navigator?(navigator.serviceWorker.controller?'Aktiv':'Verfügbar'):'Nicht verfügbar';$('#diag-webrtc').textContent='RTCPeerConnection'in window?'Verfügbar':'Nicht verfügbar';$('#diag-hls').textContent=video.canPlayType('application/vnd.apple.mpegurl')?'Nativ':'Gateway-Fallback';$('#diag-backend').textContent=appState.csrf?'Angemeldet':'Nicht angemeldet';$('#diag-origin').textContent=location.origin;$('#diag-version').textContent=VERSION;}

  function clearTransientDialogState(dialog){
    if(dialog.id==='cloud-import-dialog')appState.cloudImportContext=null;
    if(dialog.id==='discovery-auth-dialog'){
      const form=$('#discovery-auth-form');
      form.elements.username.value='';
      form.elements.password.value='';
      appState.discoveryDevice=null;
    }
  }

  function bindEvents(){
    $('#menu-button').addEventListener('click',()=>$('#app-menu').classList.contains('is-open')?closeMenu():openMenu());$('#menu-close').addEventListener('click',()=>closeMenu());$('#menu-backdrop').addEventListener('click',()=>closeMenu());$$('.nav-item').forEach(item=>item.addEventListener('click',()=>showView(item.dataset.view)));
    document.addEventListener('keydown',(event)=>{if(event.key==='Escape'&&appState.wallMode){event.preventDefault();exitWallMode();return;}if(event.key==='Escape'&&$('#app-menu').classList.contains('is-open'))closeMenu();if(event.key==='Tab'&&$('#app-menu').classList.contains('is-open')){const focusable=$$('button:not([disabled])',$('#app-menu'));const first=focusable[0],last=focusable.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}}});
    $$('dialog').forEach(dialog=>dialog.addEventListener('cancel',event=>{if(dialog.dataset.static==='true'||dialog.querySelector('form[aria-busy="true"]')){event.preventDefault();return;}clearTransientDialogState(dialog);if(dialog.id==='reauth-dialog')reauthResolver?.(false);}));
    $('#auth-form').addEventListener('submit',async(event)=>{event.preventDefault();const setup=$('#auth-dialog').dataset.setup==='true',body={username:$('#auth-user').value,password:$('#auth-password').value};try{const result=await api(setup?'/api/auth/setup':'/api/auth/login',{method:'POST',body:JSON.stringify(body)});applyAccess(result);$('#auth-password').value='';$('#auth-dialog').close();$('#app').hidden=false;await loadDisplayProfiles();applyDisplayProfileFromHash();if(currentRouteNeedsCameras())await loadCameras();else await loadHealth();refreshDiagnostics();const requestedView=hashRoute().view;if(requestedView==='wall')enterWallMode(false);else if(['recordings','discover','manage','zones','users','system'].includes(requestedView))showView(requestedView);}catch(error){$('#auth-error').textContent=error.code==='login-failed'?'Anmeldung fehlgeschlagen.':`Fehler: ${error.code}`;}});
    $('#reauth-form').addEventListener('submit',async(event)=>{event.preventDefault();try{const result=await api('/api/auth/reauth',{method:'POST',body:JSON.stringify({password:$('#reauth-password').value})});appState.elevatedUntil=result.elevatedUntil;$('#reauth-dialog').close();reauthResolver?.(true);}catch{$('#reauth-error').textContent='Passwort nicht bestätigt.';}});$$('[data-close-dialog]').forEach(button=>button.addEventListener('click',()=>{const dialog=button.closest('dialog');if(dialog.querySelector('form[aria-busy="true"]'))return;clearTransientDialogState(dialog);dialog.close();if(dialog.id==='reauth-dialog')reauthResolver?.(false);}));
    $('#logout').addEventListener('click',async()=>{clearTimeout(appState.scanTimer);appState.scanTimer=null;appState.scanId=null;appState.motionSource?.close();appState.motionSource=null;exitWallMode();try{await api('/api/auth/logout',{method:'POST'});}catch{}appState.csrf='';appState.user=null;appState.permissions={};appState.camerasLoaded=false;suspend();$('#app').hidden=true;showAuth(false);closeMenu(false);});
    const enterWall=$('#enter-wall-mode'),exitWall=$('#exit-wall-mode');if(enterWall&&exitWall){enterWall.addEventListener('click',()=>enterWallMode(true));exitWall.addEventListener('click',()=>exitWallMode());}document.addEventListener('pointermove',revealWallControls,{passive:true});document.addEventListener('touchstart',revealWallControls,{passive:true});window.addEventListener('resize',updateWallGridLayout,{passive:true});document.addEventListener('fullscreenchange',()=>{if(appState.wallMode&&!document.fullscreenElement)exitWallMode({leaveFullscreen:false});else updateWallGridLayout();});
    $('#display-profile-select').addEventListener('change',event=>selectDisplayProfile(event.currentTarget.value));$('#wall-profile-select').addEventListener('change',event=>selectDisplayProfile(event.currentTarget.value));$('#manage-display-profiles').addEventListener('click',openDisplayProfileDialog);$('#profile-editor-select').addEventListener('change',event=>renderProfileEditor(event.currentTarget.value));$('#display-profile-form').addEventListener('submit',saveDisplayProfile);$('#delete-display-profile').addEventListener('click',deleteDisplayProfile);$('#add-profile-schedule').addEventListener('click',addProfileSchedule);$('#copy-profile-live').addEventListener('click',()=>copyProfileLink('overview'));$('#copy-profile-wall').addEventListener('click',()=>copyProfileLink('wall'));
    $('#refresh-all').addEventListener('click',loadHealth);$('#detail-back').addEventListener('click',closeDetail);$('#detail-reconnect').addEventListener('click',()=>{if(!appState.detail)return;['snapshot','explicit'].includes(appState.detail.camera.displayMode)?startSnapshot(appState.detail,true):connect(appState.detail,appState.detail.path,appState.detail.mode,true);});$('#detail-start-explicit').addEventListener('click',startExplicitLive);$('#detail-clips-refresh').addEventListener('click',()=>loadBlinkClips());$('#detail-recordings-open').addEventListener('click',()=>{const id=appState.detail?.camera.id;closeDetail({updateHistory:false});appState.recordings.cameraId=id||'';showView('recordings');});$('#detail-fallback').addEventListener('click',()=>{if(!appState.detail)return;$('#detail-quality').textContent='Substream';connect(appState.detail,appState.detail.camera.lowPath,'low',true);});$('#detail-hls-toggle').addEventListener('click',()=>{if(!appState.detail)return;closeReader(appState.detail,false);$('#detail-video').hidden=true;const state=appState.detail,frame=$('#detail-hls'),camera=state.camera,useHigh=camera.highPath!==camera.lowPath,isMain=useHigh||String(camera.detailQuality||'').toLocaleLowerCase('de-DE').includes('hauptstream');state.hlsChecks=0;state.hlsLiveLabel=isMain?'Live · HLS-Hauptstream':'Live · HLS';frame.hidden=false;frame.src=hlsUrl(useHigh?camera.highPath:camera.lowPath);mark(state,'loading',isMain?'HLS-Hauptstream wird aufgebaut · kann bis zu 20 s dauern':'HLS-Fallback wird aufgebaut');});$('#detail-hls').addEventListener('load',()=>{const state=appState.detail;if(state)watchHlsPlayback(state,state.generation);});$('#detail-message').addEventListener('click',()=>appState.detail?.camera.explicitLiveOnly?startExplicitLive():resumePlayback(appState.detail));$('#detail-video').addEventListener('click',()=>resumePlayback(appState.detail));$('#detail-audio').addEventListener('click',toggleDetailAudio);$('#detail-fullscreen').addEventListener('click',()=>{const shell=$('#detail-shell'),video=$('#detail-video');if(shell.requestFullscreen)shell.requestFullscreen();else video.webkitEnterFullscreen?.();});
    $('#recording-date').addEventListener('change',loadCameraRecordings);$('#recording-previous-day').addEventListener('click',()=>shiftRecordingDate(-1));$('#recording-next-day').addEventListener('click',()=>shiftRecordingDate(1));$('#recording-refresh').addEventListener('click',()=>loadRecordingSources(true));$('#recording-stop').addEventListener('click',stopRecordingPlayback);$('#recording-player').addEventListener('ended',stopRecordingPlayback);$('#recording-player').addEventListener('error',()=>{if(appState.recordings.leaseId)$('#recording-player-label').textContent='Medienwiedergabe wurde unterbrochen';});
    $$('[data-ptz-x]').forEach(button=>{button.addEventListener('pointerdown',event=>{event.preventDefault();button.setPointerCapture?.(event.pointerId);startPTZ(button);});for(const name of ['pointerup','pointercancel','pointerleave'])button.addEventListener(name,stopPTZ);button.addEventListener('keydown',event=>{if((event.key===' '||event.key==='Enter')&&!event.repeat){event.preventDefault();startPTZ(button);}});button.addEventListener('keyup',event=>{if(event.key===' '||event.key==='Enter')stopPTZ();});button.addEventListener('blur',stopPTZ);});$('[data-ptz-stop]').addEventListener('click',stopPTZ);$('#ptz-presets').addEventListener('change',gotoPreset);
    $('#start-scan').addEventListener('click',startScan);$('#cancel-scan').addEventListener('click',cancelScan);$('#manual-add').addEventListener('click',()=>openCameraDialog());$('#discovery-auth-form').addEventListener('submit',probeDiscovery);$('#test-source').addEventListener('click',testSource);$('#camera-form').addEventListener('submit',addCamera);for(const name of ['input','change'])$('#camera-form').addEventListener(name,()=>{$('#camera-form').dataset.tested='false';$('#source-test').textContent='Verbindungsdaten geändert · bitte erneut testen.';});$('#credential-mode').addEventListener('change',updateCredentialFields);$('#connection-test-button').addEventListener('click',testConnection);$('#connection-form').addEventListener('submit',saveConnection);for(const name of ['input','change'])$('#connection-form').addEventListener(name,()=>{$('#connection-form').dataset.tested='false';$('#connection-test').dataset.state='';$('#connection-test').textContent='Verbindungsdaten geändert · bitte erneut prüfen.';});$('#connection-activate').addEventListener('click',activateConnection);$('#capability-refresh').addEventListener('click',refreshCapabilities);$('#zone-camera').addEventListener('change',loadZoneCamera);$('#zone-canvas').addEventListener('pointerdown',addZonePoint);$('#zone-add-coordinate').addEventListener('click',addZoneCoordinate);$$('[data-zone-kind]').forEach(button=>button.addEventListener('click',()=>{$$('[data-zone-kind]').forEach(item=>item.classList.remove('is-active'));button.classList.add('is-active');zoneState.kind=button.dataset.zoneKind;}));$('#zone-undo').addEventListener('click',()=>{zoneState.draft.pop();drawZones();});$('#zone-complete').addEventListener('click',completeZone);$('#detection-camera-enabled').addEventListener('change',event=>zoneState.detection.enabled=event.currentTarget.checked);$('#add-camera-detection-schedule').addEventListener('click',()=>addDetectionSchedule(zoneState.detection.schedules,renderCameraDetection));$('#zone-save').addEventListener('click',saveZones);window.addEventListener('resize',resizeCanvas);
    $('#add-czeview-account').addEventListener('click',()=>{$('#czeview-account-form').reset();$('#czeview-account-title').textContent='CZEview-Konto hinzufügen';$('#czeview-account-form').elements.countryCode.value='DE';$('#czeview-account-form').elements.phoneCode.value='49';$('#czeview-account-form').elements.sourceApp.value='141';$('#czeview-account-error').textContent='';$('#czeview-account-dialog').showModal();});$('#czeview-account-form').addEventListener('submit',saveCzeviewAccount);$('#cloud-import-form').addEventListener('submit',importCloudCamera);
    $('#add-blink-account').addEventListener('click',()=>{$('#blink-account-form').reset();$('#blink-account-title').textContent='Blink-Konto hinzufügen';$('#blink-account-error').textContent='';$('#blink-account-dialog').showModal();});$('#blink-account-form').addEventListener('submit',saveBlinkAccount);$('#blink-verify-form').addEventListener('submit',verifyBlinkAccount);
    $('#configure-netatmo').addEventListener('click',()=>{const form=$('#netatmo-config-form');form.reset();form.elements.redirectUri.value=`${location.origin}/api/cloud/oauth/netatmo/callback`;$('#netatmo-config-error').textContent='';$('#netatmo-config-dialog').showModal();});$('#netatmo-config-form').addEventListener('submit',saveNetatmoConfig);
    $('#add-netatmo-account').addEventListener('click',()=>{$('#netatmo-account-form').reset();$('#netatmo-account-error').textContent='';$('#netatmo-account-dialog').showModal();});$('#netatmo-account-form').addEventListener('submit',authorizeNetatmo);
    $('#add-user').addEventListener('click',()=>{$('#user-form').reset();$('#user-error').textContent='';$('#user-dialog').showModal();});$('#user-form').addEventListener('submit',createUser);$('#password-form').addEventListener('submit',saveUserPassword);$('#change-own-password').addEventListener('click',()=>{$('#own-password-form').reset();$('#own-password-error').textContent='';$('#own-password-dialog').showModal();});$('#own-password-form').addEventListener('submit',changeOwnPassword);
    $('#event-filter').addEventListener('change',loadEvents);$('#event-type-filter').addEventListener('change',loadEvents);$('#save-detection-mode').addEventListener('click',saveDetectionMode);$('#motion-browser-alerts').addEventListener('change',updateMotionAlerts);$('#motion-browser-sound').addEventListener('change',event=>{localStorage.setItem('pkws-motion-sound',event.currentTarget.checked?'1':'0');if(event.currentTarget.checked)playMotionSound();});$('#motion-alert-dismiss').addEventListener('click',()=>{$('#motion-alert-banner').hidden=true;});$('#motion-alert-open').addEventListener('click',()=>{const id=appState.motionAlert?.cameraId;$('#motion-alert-banner').hidden=true;if(id)openDetail(id);});$('#create-backup').addEventListener('click',()=>{$('#backup-form').reset();$('#backup-error').textContent='';$('#backup-dialog').showModal();});$('#backup-form').addEventListener('submit',createBackup);$('#restore-backup').addEventListener('click',()=>{$('#restore-form').reset();$('#restore-error').textContent='';resetRestoreValidation();$('#restore-dialog').showModal();});$('#restore-form').addEventListener('submit',restoreBackup);for(const name of ['input','change'])$('#restore-form').addEventListener(name,resetRestoreValidation);$('#add-webhook').addEventListener('click',()=>openWebhookDialog());$('#webhook-form').addEventListener('submit',saveWebhook);$('#copy-webhook-secret').addEventListener('click',()=>copyText($('#webhook-secret').textContent,'Geheimnis kopiert','Geheimnis kopieren'));$('#add-display-device').addEventListener('click',()=>openDisplayDeviceDialog());$('#display-device-form').addEventListener('submit',saveDisplayDevice);$('#copy-pairing-code').addEventListener('click',()=>copyText($('#pairing-code').textContent,'Kopplungscode kopiert','Kopplungscode kopieren'));
    document.addEventListener('visibilitychange',()=>document.hidden?suspend():resume());window.addEventListener('pagehide',suspend);window.addEventListener('pageshow',resume);window.addEventListener('focus',resume);window.addEventListener('blur',stopPTZ);window.addEventListener('offline',suspend);window.addEventListener('online',resume);window.addEventListener('hashchange',()=>applyLiveHashNavigation().catch(()=>toast('Ansicht konnte nicht gewechselt werden')));
  }

  window.addEventListener('load',async()=>{
    bindEvents();refreshDiagnostics();appState.observer=new IntersectionObserver(entries=>entries.forEach(entry=>{const state=appState.states.get(entry.target.dataset.cameraId);if(!state)return;state.visible=entry.isIntersecting;if(appState.detail)return;if(state.visible)['snapshot','explicit'].includes(state.camera.displayMode)?startSnapshot(state,true):connect(state,state.camera.lowPath,'low',true);else closeReader(state);}),{threshold:.2,rootMargin:'100px'});
    try{await initializeAuth();}catch{showAuth(false);}
    if('serviceWorker'in navigator){let reloadingForUpdate=false;navigator.serviceWorker.addEventListener('controllerchange',()=>{if(reloadingForUpdate)return;reloadingForUpdate=true;location.reload();});navigator.serviceWorker.register('./sw.js').then(refreshDiagnostics).catch(()=>{});}
    const initial=location.hash.slice(1),initialView=hashRoute().view;if(initialView==='wall'&&appState.csrf)enterWallMode(false);else if(['recordings','discover','manage','zones','users','system'].includes(initialView)&&appState.csrf){showView(initialView);if(initial.includes('netatmo=connected'))toast('Netatmo-Konto wurde verbunden');}
  });
})();
