(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let mode = 'chat';
  let state = { documents: [], events: [] };
  let selectedId = null;
  let busy = true;
  const conversations = { chat: [], rag: [] };
  const labels = { clean: 'ACEPTADO', blocked: 'BLOQUEADO', error: 'NO INCORPORADO' };

  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }
  function showError(message = '') {
    $('app-error').hidden = !message;
    $('app-error').textContent = message;
  }
  function setBusy(value) {
    busy = value;
    document.querySelectorAll('button, input').forEach(element => { element.disabled = value; });
    $('upload-form').setAttribute('aria-busy', String(value));
  }
  async function api(path, body) {
    const options = body === undefined ? {} : {
      method: 'POST', headers: { 'X-CSRF-Token': state.csrf },
      body: body instanceof FormData ? body : JSON.stringify(body),
    };
    if (body !== undefined && !(body instanceof FormData)) options.headers['Content-Type'] = 'application/json';
    const response = await fetch(path, options);
    let data;
    try { data = await response.json(); }
    catch { throw new Error('El servidor no devolvió JSON. Revisa los logs y vuelve a intentar.'); }
    if (!response.ok) throw new Error(data.error || `Error HTTP ${response.status}`);
    return data;
  }
  async function refresh() {
    state = await api('/api/state');
    const simulated = state.scan_mode === 'simulation';
    $('scan-mode').textContent = simulated ? 'SIMULACIÓN · sin SDK' : 'SDK REAL · análisis al cargar';
    $('scan-mode').className = `environment ${simulated ? 'simulated' : 'live'}`;
    $('simulation-banner').hidden = !simulated;
    $('simulation-sample').hidden = !simulated;
    $('answer-engine').textContent = state.engine;
    render();
  }
  function render() {
    const rag = mode === 'rag';
    document.querySelectorAll('[data-mode]').forEach(button => {
      const active = button.dataset.mode === mode;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    $('page-title').replaceChildren(node('span', rag ? 'Tu conocimiento, protegido.' : 'Tus archivos. Tu asistente.'));
    $('page-title').append(document.createElement('br'), node('span', rag ? 'Desde la primera ingesta.' : 'Una capa más de seguridad.'));
    // The first line uses the primary heading color.
    $('page-title').firstChild.className = 'heading-first';
    $('page-description').textContent = rag
      ? 'Analiza documentos antes de extraer texto, crear fragmentos y alimentar una base RAG. Consulta después con fuentes trazables.'
      : 'Demuestra cómo File Security analiza los adjuntos antes de convertirlos en contexto para un chatbot.';
    $('upload-eyebrow').textContent = rag ? '01 / INGESTA DE CONOCIMIENTO' : '01 / ADJUNTAR';
    $('upload-title').textContent = rag ? 'Antes de indexar.' : 'Antes de preguntar.';
    $('upload-description').textContent = rag
      ? 'Solo los documentos aceptados se convierten en fragmentos y vectores de términos para la recuperación.'
      : 'El adjunto solo llega al chat si pasa el análisis y se puede extraer su texto.';
    $('upload-button').textContent = rag ? 'Analizar e incorporar al RAG →' : 'Analizar y adjuntar →';
    $('documents-title').textContent = rag ? 'Base de conocimiento' : 'Contexto del chat';
    $('scope-note').textContent = rag
      ? 'Hasta 30 documentos por sesión. Índice local TF-IDF persistido en SQLite; no usa embeddings semánticos.'
      : 'Un adjunto activo. Una nueva carga aceptada reemplaza el contexto anterior; un rechazo lo conserva.';
    $('chat-title').textContent = rag ? 'Knowledge assistant' : 'Document assistant';
    $('scope-badge').textContent = rag ? 'RAG' : 'CHAT';
    $('last-stage').replaceChildren(document.createTextNode(rag ? 'Indexar al RAG' : 'Contexto del chat'),
      node('small', 'Disponible para consultar'));
    renderDocuments();
    renderEvents();
    renderConversation();
  }
  function renderDocuments() {
    const docs = state.documents.filter(document => document.mode === mode);
    $('documents').replaceChildren();
    if (!docs.length) $('documents').append(node('p', 'Todavía no hay documentos aceptados.', 'empty-small'));
    docs.forEach(document => {
      const row = node('div', undefined, 'document');
      const info = node('div', undefined, 'document-content');
      info.append(node('strong', document.name), node('small', `${document.chunks} fragmentos · SHA-256 ${document.sha256.slice(0, 12)}…`));
      row.append(node('span', document.name.split('.').pop().toUpperCase(), 'file-icon'), info);
      $('documents').append(row);
    });
  }
  function selectEvent(event) {
    selectedId = event.correlation_id;
    const data = event.sdk_response === null ? { error: event.error, correlation_id: event.correlation_id } : event.sdk_response;
    $('sdk-response').value = JSON.stringify(data, null, 2);
    $('response-badge').textContent = event.scan_mode === 'simulation' ? 'SIMULADO' : 'SDK REAL';
    const stages = ['received', 'scanned', 'extracted', 'indexed'];
    const reached = new Set(event.stages);
    if (reached.has('attached')) reached.add('indexed');
    document.querySelectorAll('.pipeline-step').forEach(step => {
      const stage = step.dataset.stage;
      const stopped = !event.indexed && (event.scan_status === 'clean' ? stage === 'extracted' : stage === 'scanned');
      step.classList.toggle('complete', reached.has(stage) && !stopped);
      step.classList.toggle('stopped', stopped);
      step.classList.toggle('pending', !reached.has(stage) && !stopped);
    });
    document.querySelectorAll('.event-button').forEach(button => {
      const selected = button.dataset.id === selectedId;
      button.classList.toggle('selected', selected);
      button.setAttribute('aria-pressed', String(selected));
    });
  }
  function renderEvents() {
    const events = state.events.filter(event => event.mode === mode);
    $('events').replaceChildren();
    $('counters').replaceChildren();
    [['clean', 'aceptados'], ['blocked', 'bloqueados'], ['error', 'con error']].forEach(([status, label]) => {
      const count = node('span');
      count.append(node('strong', String(events.filter(event => event.status === status).length)), document.createTextNode(label));
      $('counters').append(count);
    });
    if (!events.length) {
      $('events').append(node('p', 'Carga un documento para ver su trazabilidad.', 'empty-small'));
      $('sdk-response').value = '';
      $('response-badge').textContent = 'SIN ANÁLISIS';
      document.querySelectorAll('.pipeline-step').forEach(step => { step.classList.remove('complete', 'stopped', 'pending'); });
      return;
    }
    events.forEach(event => {
      const button = node('button', undefined, 'event-button');
      button.type = 'button';
      button.dataset.id = event.correlation_id;
      const text = node('span', undefined, 'event-text');
      text.append(node('strong', event.filename), node('small', `${new Date(event.created).toLocaleTimeString()} · ${event.elapsed_ms} ms · ${event.indexed ? `${event.chunks} fragmentos disponibles` : 'No llegó al contexto / índice'}`));
      if (event.error) text.append(node('small', event.error));
      button.append(node('span', undefined, `status-dot ${event.status}`), text, node('span', labels[event.status], 'event-status'));
      button.addEventListener('click', () => selectEvent(event));
      $('events').append(button);
    });
    selectEvent(events.find(event => event.correlation_id === selectedId) || events[0]);
  }
  function renderConversation() {
    const log = $('messages');
    const messages = conversations[mode];
    log.replaceChildren();
    if (!messages.length) {
      const welcome = node('div', undefined, 'welcome');
      welcome.append(node('span', '↗', 'welcome-icon'), node('h3', mode === 'rag' ? 'Tu base empieza aquí.' : 'Empieza con un archivo.'),
        node('p', 'Carga un documento aceptado y haz una pregunta. Verás la respuesta y los fragmentos recuperados de tus fuentes.'));
      log.append(welcome);
    }
    messages.forEach(message => {
      const bubble = node('div', undefined, `message ${message.role}`);
      if (message.role === 'assistant') bubble.append(node('span', message.engine || 'ASISTENTE', 'message-label'));
      bubble.append(document.createTextNode(message.text));
      (message.sources || []).forEach((source, index) => {
        const details = node('details', undefined, 'source-details');
        details.append(node('summary', `[${index + 1}] ${source.name} · fragmento ${source.position + 1} · score ${source.score}`),
          node('p', source.text), node('div', `SHA-256: ${source.sha256} · scanId: ${source.scan_id || 'sin ID'} · chunk: ${source.id}`, 'source-meta'));
        bubble.append(details);
      });
      log.append(bubble);
    });
    log.scrollTop = log.scrollHeight;
  }
  async function upload(file) {
    if (busy) return;
    if (!file || !/\.(txt|md|pdf)$/i.test(file.name)) { showError('Selecciona un archivo TXT, MD o PDF.'); return; }
    if (!file.size || file.size >= 8 * 1024 * 1024) { showError('El archivo debe tener contenido y ser menor de 8 MiB.'); return; }
    showError();
    setBusy(true);
    $('upload-status').textContent = 'Analizando con File Security… El documento todavía no llega al asistente.';
    try {
      const body = new FormData();
      body.append('mode', mode);
      body.append('file', file);
      const { event } = await api('/api/upload', body);
      selectedId = event.correlation_id;
      await refresh();
      $('upload-status').textContent = event.indexed
        ? `${event.duplicate ? 'Ya estaba incorporado' : 'Documento incorporado'} · ${event.chunks} fragmentos disponibles.`
        : event.status === 'blocked' ? 'Archivo bloqueado. No se extrajo ni se incorporó al asistente.' : 'No se pudo incorporar el archivo. Revisa la actividad del análisis.';
      if (event.error) showError(event.error);
      if (event.indexed && mode === 'chat') { conversations.chat = []; renderConversation(); }
    } catch (error) { showError(error.message); $('upload-status').textContent = 'La carga no pudo completarse.'; }
    finally { setBusy(false); }
  }
  document.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => {
    if (busy) return;
    mode = button.dataset.mode;
    selectedId = null;
    $('upload-status').textContent = '';
    showError(); render();
  }));
  $('file').addEventListener('change', () => {
    const file = $('file').files[0];
    $('selected-file').hidden = !file;
    $('selected-file').textContent = file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KiB` : '';
  });
  $('upload-form').addEventListener('submit', event => { event.preventDefault(); upload($('file').files[0]); });
  ['dragenter', 'dragover'].forEach(type => $('dropzone').addEventListener(type, event => { event.preventDefault(); if (!busy) $('dropzone').classList.add('dragging'); }));
  ['dragleave', 'drop'].forEach(type => $('dropzone').addEventListener(type, event => { event.preventDefault(); $('dropzone').classList.remove('dragging'); }));
  $('dropzone').addEventListener('drop', event => {
    if (busy) return;
    if (event.dataTransfer.files.length !== 1) { showError('Carga un documento por vez.'); return; }
    $('file').files = event.dataTransfer.files;
    $('file').dispatchEvent(new Event('change'));
    upload(event.dataTransfer.files[0]);
  });
  document.querySelectorAll('[data-sample]').forEach(button => button.addEventListener('click', async () => {
    if (busy) return;
    setBusy(true); showError();
    try {
      const response = await fetch(`/api/samples/${button.dataset.sample}`);
      if (!response.ok) throw new Error('No se pudo cargar el ejemplo.');
      const file = new File([await response.blob()], button.dataset.sample, { type: 'text/plain' });
      setBusy(false);
      await upload(file);
    } catch (error) { showError(error.message); setBusy(false); }
  }));
  document.querySelectorAll('[data-question]').forEach(button => button.addEventListener('click', () => {
    $('question').value = button.dataset.question;
    $('question-form').requestSubmit();
  }));
  $('question-form').addEventListener('submit', async event => {
    event.preventDefault();
    const question = $('question').value.trim();
    if (busy || !question) return;
    showError(); setBusy(true);
    conversations[mode].push({ role: 'user', text: question });
    const pending = { role: 'assistant', text: 'Consultando los documentos aceptados…' };
    conversations[mode].push(pending);
    renderConversation(); $('question').value = '';
    try {
      const data = await api('/api/ask', { mode, question });
      Object.assign(pending, { text: data.answer, sources: data.sources, engine: data.engine });
    } catch (error) { pending.text = error.message; showError(error.message); }
    finally { renderConversation(); setBusy(false); $('question').focus(); }
  });
  $('reset-button').addEventListener('click', async () => {
    if (busy) return;
    setBusy(true); showError();
    try {
      await api('/api/reset', { mode });
      conversations[mode] = []; selectedId = null;
      $('upload-status').textContent = '';
      $('file').value = ''; $('selected-file').hidden = true;
      await refresh();
    } catch (error) { showError(error.message); }
    finally { setBusy(false); }
  });
  setBusy(true);
  refresh().then(() => setBusy(false)).catch(error => { showError(error.message); });
})();
