/**
 * Sentinel — UI Neo-Brutalist + analyse 100% locale.
 * Aucune donnée n'est transmise. Seule requête : GET anonyme du scams.json
 * toutes les 6h pour mettre à jour la liste des arnaques en cours.
 */

const SCAMS_JSON_URL = 'scams.json';
const SCAMS_REFRESH_MS = 6 * 60 * 60 * 1000;
const SCAMS_CACHE_KEY = 'sentinel:scams';
const LOGS_KEY = 'sentinel:logs';
const LOGS_MAX = 50;

// ══════════════════════════════════════════════════════════
// TABS
// ══════════════════════════════════════════════════════════

function setTab(name) {
  // Mobile nav : active = bg cyan + border + shadow blanc (style Stitch exact)
  document.querySelectorAll('#nav-mobile .tab-link').forEach(a => {
    const active = a.dataset.tab === name;
    if (active) {
      a.classList.add('bg-primary-container', 'text-on-primary-container', 'border-border-width-thin', 'border-primary', 'shadow-[2px_2px_0px_0px_#ffffff]');
      a.classList.remove('text-secondary');
      a.querySelector('span.material-symbols-outlined')?.setAttribute('style', "font-variation-settings: 'FILL' 1;");
      a.querySelector('span:not(.material-symbols-outlined)')?.classList.add('font-bold');
    } else {
      a.classList.remove('bg-primary-container', 'text-on-primary-container', 'border-border-width-thin', 'border-primary', 'shadow-[2px_2px_0px_0px_#ffffff]');
      a.classList.add('text-secondary');
      a.querySelector('span.material-symbols-outlined')?.removeAttribute('style');
      a.querySelector('span:not(.material-symbols-outlined)')?.classList.remove('font-bold');
    }
  });

  // Desktop nav : active = text-primary + border-bottom cyan
  document.querySelectorAll('#nav-desktop .tab-link').forEach(a => {
    const active = a.dataset.tab === name;
    if (active) {
      a.classList.add('text-primary', 'border-b-border-width-thin', 'border-primary');
      a.classList.remove('text-on-surface-variant', 'dark:text-on-surface-variant');
    } else {
      a.classList.remove('text-primary', 'border-b-border-width-thin', 'border-primary');
      a.classList.add('text-on-surface-variant', 'dark:text-on-surface-variant');
    }
  });

  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  window.scrollTo(0, 0);

  if (name === 'shield') loadScams();
  if (name === 'logs') renderLogs();
}

document.querySelectorAll('.tab-link').forEach(a => {
  a.addEventListener('click', e => { e.preventDefault(); setTab(a.dataset.tab); });
});

// ══════════════════════════════════════════════════════════
// ANALYSE
// ══════════════════════════════════════════════════════════

function analyze() {
  const input = document.getElementById('threat-input').value.trim();
  const zone = document.getElementById('verdict-zone');
  if (!input) { zone.innerHTML = ''; updateEngine('EN ATTENTE', 'warning', '#fce442'); return; }

  updateEngine('ANALYSE...', 'sync', '#00fbfb');

  const type = detectInputType(input);
  let score = 0;
  const reasons = [];
  const matchedTypes = new Set();

  for (const r of RULES.keywords) {
    if (r.re.test(input)) { score += r.score; reasons.push(r.reason); matchedTypes.add('KEYWORD'); }
  }
  for (const r of RULES.urlPatterns) {
    if (r.re.test(input)) { score += r.score; reasons.push(r.reason); matchedTypes.add('URL'); }
  }
  if (type === 'phone') {
    for (const r of RULES.phonePatterns) {
      if (r.re.test(input) && r.score > 0) { score += r.score; reasons.push(r.reason); matchedTypes.add('PHONE'); }
    }
  }
  for (const c of RULES.combos) {
    if (c.triggers.every(t => input.toLowerCase().includes(t))) {
      score += c.score; reasons.push(c.reason); matchedTypes.add('COMBO');
    }
  }

  // Patterns dynamiques (scams.json)
  const dyn = loadCachedScams();
  if (dyn?.patterns) {
    for (const r of dyn.patterns) {
      try {
        const re = new RegExp(r.re, r.flags || 'i');
        if (re.test(input)) { score += r.score || 2; reasons.push(`${r.reason} (signalé récemment)`); matchedTypes.add('LIVE-FEED'); }
      } catch {}
    }
  }

  let verdict;
  if (score >= 5) {
    verdict = { level: 'danger', title: 'DANGER', subtitle: 'ARNAQUE PROBABLE',
      icon: 'warning', actions: 'NE PAS CLIQUER.\nNE PAS APPELER.\nSUPPRIMER.',
      engineLabel: 'MENACE DÉTECTÉE', engineColor: '#ff3a3a', engineIcon: 'gpp_bad' };
  } else if (score >= 2) {
    verdict = { level: 'warn', title: 'ATTENTION', subtitle: 'SIGNAUX SUSPECTS',
      icon: 'warning', actions: 'VÉRIFIE LA SOURCE.\nNE PAS AGIR DANS L\'URGENCE.',
      engineLabel: 'MÉFIANCE', engineColor: '#fce442', engineIcon: 'priority_high' };
  } else {
    verdict = { level: 'ok', title: 'CLEAR', subtitle: 'AUCUNE MENACE CONNUE',
      icon: 'verified_user', actions: 'AUCUN SIGNAL DÉTECTÉ.\nRESTE PRUDENT — UNE NOUVELLE ARNAQUE PEUT PASSER.',
      engineLabel: 'OPÉRATIONNEL', engineColor: '#00ff7a', engineIcon: 'verified_user' };
  }

  updateEngine(verdict.engineLabel, verdict.engineIcon, verdict.engineColor);
  renderVerdict(verdict, input, type, score, reasons, [...matchedTypes]);
  saveLog({ input, type, score, verdict: verdict.level, reasons, ts: Date.now() });
}

function updateEngine(label, icon, color) {
  document.getElementById('engine-status').textContent = label;
  const i = document.getElementById('engine-icon');
  i.textContent = icon;
  i.style.color = color;
  document.getElementById('engine-status-card').style.borderColor = color;
}

function renderVerdict(v, input, type, score, reasons, matchedTypes) {
  const zone = document.getElementById('verdict-zone');
  const panelClass = v.level === 'danger' ? 'danger-panel' : v.level === 'warn' ? 'warn-panel' : 'ok-panel';
  const sourceSample = escapeHtml(input.slice(0, 120) + (input.length > 120 ? '…' : ''));
  const inputTypeLabel = { phone: 'NUMÉRO', url: 'LIEN', email: 'EMAIL', message: 'TEXTE' }[type];

  zone.innerHTML = `
    <div class="brutal-border ${panelClass} px-6 py-8 text-center mt-6">
      <div class="brutal-border-thin inline-block px-3 py-1 mb-4" style="border-color:#131313">
        <span class="font-label-mono text-xs uppercase tracking-widest">SCAN TERMINÉ</span>
      </div>
      <div class="font-display-lg text-display-lg leading-none mb-3" style="font-size: clamp(48px, 14vw, 80px)">${v.title}</div>
      <div class="font-label-mono text-label-mono uppercase tracking-widest">${v.subtitle}</div>
    </div>

    <div class="flex items-start gap-2 mt-6 mb-2">
      <span class="material-symbols-outlined text-2xl" style="color:${v.level==='danger'?'#ff3a3a':v.level==='warn'?'#fce442':'#00ff7a'}">${v.icon}</span>
      <div class="font-label-mono text-label-mono uppercase">ACTION REQUISE</div>
    </div>
    <div class="font-headline-md text-headline-md text-primary uppercase whitespace-pre-line mb-6">${v.actions}</div>

    <div class="brutal-border-thin bg-surface-container-low p-4 mb-3">
      <div class="flex justify-between items-center border-b-border-width-thin border-surface-container-highest pb-2 mb-2">
        <h3 class="font-label-mono text-label-mono uppercase text-primary-container">SIGNAL TYPE</h3>
        <span class="material-symbols-outlined text-primary-container">label</span>
      </div>
      <div class="font-label-mono text-sm text-primary uppercase">▸ ${escapeHtml(inputTypeLabel)} — SCORE ${score}/10</div>
      <div class="font-body-md text-on-surface-variant mt-1">${matchedTypes.length ? matchedTypes.join(' · ') : 'AUCUN MOTIF DÉCLENCHÉ'}</div>
    </div>

    ${reasons.length > 0 ? `
    <div class="brutal-border-thin bg-surface-container-low p-4 mb-3">
      <div class="flex justify-between items-center border-b-border-width-thin border-surface-container-highest pb-2 mb-2">
        <h3 class="font-label-mono text-label-mono uppercase text-primary-container">MOTIFS DÉTECTÉS</h3>
        <span class="material-symbols-outlined text-primary-container">list_alt</span>
      </div>
      <ul class="flex flex-col gap-2">
        ${reasons.map(r => `<li class="font-body-md text-on-surface flex gap-2"><span class="text-primary-container">▸</span>${escapeHtml(r)}</li>`).join('')}
      </ul>
    </div>` : ''}

    <div class="brutal-border-thin bg-surface-container-low p-4 mb-6">
      <div class="flex justify-between items-center border-b-border-width-thin border-surface-container-highest pb-2 mb-2">
        <h3 class="font-label-mono text-label-mono uppercase text-primary-container">SOURCE ANALYSIS</h3>
        <span class="material-symbols-outlined text-primary-container">code</span>
      </div>
      <div class="font-label-mono text-xs text-on-surface-variant break-all">[RAW_INPUT] : "${sourceSample}"</div>
    </div>

    <div class="flex flex-col gap-3">
      <button class="brutal-border-thin bg-surface-container px-4 py-3 font-label-mono text-label-mono uppercase text-primary flex items-center justify-center gap-2 active:opacity-50" onclick="markHandled()">
        <span class="material-symbols-outlined text-base">check_circle</span>
        ${v.level === 'danger' ? 'J\'AI SUPPRIMÉ' : v.level === 'warn' ? 'NOTÉ' : 'COMPRIS'}
      </button>
      <button class="brutal-btn bg-primary-container text-on-primary-fixed border-border-width-thick border-primary px-8 py-4 font-label-mono text-base uppercase font-bold tracking-widest brutal-btn-shadow flex items-center justify-center gap-2" onclick="resetScan()">
        <span class="material-symbols-outlined">restart_alt</span>
        NOUVEAU SCAN
      </button>
    </div>
  `;
  zone.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function resetScan() {
  document.getElementById('threat-input').value = '';
  document.getElementById('verdict-zone').innerHTML = '';
  updateEngine('EN ATTENTE', 'warning', '#fce442');
  document.getElementById('threat-input').focus();
}

function markHandled() {
  document.getElementById('verdict-zone').innerHTML = `
    <div class="brutal-border bg-surface-container-low p-6 text-center mt-6">
      <span class="material-symbols-outlined text-primary-container" style="font-size:48px">verified</span>
      <div class="font-label-mono text-label-mono text-primary-container uppercase mt-2">CONFIRMÉ</div>
      <button class="brutal-btn bg-primary-container text-on-primary-fixed border-border-width-thick border-primary px-8 py-4 mt-4 font-label-mono text-base uppercase font-bold tracking-widest brutal-btn-shadow inline-flex items-center gap-2" onclick="resetScan()">
        <span class="material-symbols-outlined">restart_alt</span>NOUVEAU SCAN
      </button>
    </div>
  `;
}

// ══════════════════════════════════════════════════════════
// SHIELD : Arnaques actives (fetch JSON)
// ══════════════════════════════════════════════════════════

function loadCachedScams() {
  try { return JSON.parse(localStorage.getItem(SCAMS_CACHE_KEY) || 'null'); }
  catch { return null; }
}

async function loadScams(force = false) {
  const cached = loadCachedScams();
  const now = Date.now();
  const stale = !cached || force || (now - (cached._fetchedAt || 0)) > SCAMS_REFRESH_MS;
  if (cached) renderShield(cached);
  if (!stale) return;

  try {
    const res = await fetch(SCAMS_JSON_URL, { cache: 'no-cache' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    data._fetchedAt = now;
    localStorage.setItem(SCAMS_CACHE_KEY, JSON.stringify(data));
    renderShield(data);
  } catch (e) {
    if (!cached) {
      document.getElementById('shield-list').innerHTML = emptyCard('FEED INDISPONIBLE',
        'Impossible de récupérer la liste actuelle des arnaques. Réessaie plus tard.');
    }
  }
}

function renderShield(data) {
  const updated = document.getElementById('shield-updated');
  if (data._fetchedAt) {
    const d = new Date(data._fetchedAt);
    updated.textContent = `MAJ: ${d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}`;
  }
  const list = document.getElementById('shield-list');
  if (!data.alerts?.length) {
    list.innerHTML = `<div class="brutal-border-thin bg-surface-container-low p-6 text-center"><div class="font-label-mono text-label-mono uppercase text-primary mb-1">AUCUNE ALERTE</div><div class="font-body-md text-on-surface-variant">Aucune arnaque active signalée actuellement.</div></div>`;
    return;
  }

  const labelByKind = { sms: 'SMS', call: 'APPEL', mail: 'EMAIL', url: 'SITE' };
  const badgeBg = { sms: '#00fbfb', call: '#ff3a3a', mail: '#fce442', url: '#ff3a3a' };
  const badgeFg = { sms: '#003737', call: '#ffffff', mail: '#131313', url: '#ffffff' };
  const borderByKind = { sms: '#ffffff', call: '#ff3a3a', mail: '#fce442', url: '#ff3a3a' };

  // Format exact des cartes alertes_brutal Stitch :
  // Header avec titre uppercase + badge
  // Tableau 2 colonnes : VECTEUR/CIBLE/RISQUE/STATUS
  // Citation en italique encadrée
  // Footer "ANALYSER SOURCE →" cliquable
  list.innerHTML = data.alerts.map((a, i) => `
    <article class="brutal-border-thin bg-surface-container-low" style="border-color:${borderByKind[a.kind] || '#ffffff'}">
      <header class="flex justify-between items-center px-4 py-3 border-b-border-width-thin border-surface-container-highest">
        <h3 class="font-headline-md text-2xl text-primary uppercase tracking-tighter font-bold">${escapeHtml(a.title.toUpperCase())}</h3>
        <span class="font-label-mono text-[10px] uppercase px-2 py-1 tracking-widest font-bold" style="background:${badgeBg[a.kind]};color:${badgeFg[a.kind]}">${labelByKind[a.kind] || a.kind.toUpperCase()}</span>
      </header>
      <table class="w-full font-label-mono text-xs uppercase">
        <tr class="border-b border-surface-container-highest"><td class="px-4 py-2 text-on-surface-variant w-1/3">VECTEUR</td><td class="px-4 py-2 text-primary-container text-right">${escapeHtml(a.vector || labelByKind[a.kind])}</td></tr>
        <tr class="border-b border-surface-container-highest"><td class="px-4 py-2 text-on-surface-variant">CIBLE</td><td class="px-4 py-2 text-primary text-right">${escapeHtml(a.target || 'FR / PARTICULIERS')}</td></tr>
        <tr><td class="px-4 py-2 text-on-surface-variant">RISQUE</td><td class="px-4 py-2 text-right font-bold" style="color:${riskColor(a.risk)}">${escapeHtml((a.risk || 'ÉLEVÉ').toUpperCase())}</td></tr>
      </table>
      ${a.example ? `<div class="mx-4 my-3 px-3 py-2 border-l-4 bg-surface-container-lowest" style="border-color:#fce442"><p class="font-body-md text-secondary italic">« ${escapeHtml(a.example)} »</p></div>` : ''}
      ${a.description ? `<p class="font-body-md text-on-surface-variant px-4 pb-3">${escapeHtml(a.description)}</p>` : ''}
      <footer class="flex justify-between items-center px-4 py-3 border-t-border-width-thin border-surface-container-highest">
        <button class="font-label-mono text-label-mono text-primary uppercase active:opacity-50" onclick="copyToScan(${i})">ANALYSER SOURCE</button>
        <span class="material-symbols-outlined text-primary">arrow_forward</span>
      </footer>
    </article>
  `).join('');
}

function riskColor(r) {
  const v = (r || '').toUpperCase();
  if (v.includes('CRITIQUE')) return '#ff3a3a';
  if (v.includes('ÉLEV') || v.includes('HIGH')) return '#ff8b8b';
  if (v.includes('MOYEN')) return '#fce442';
  return '#00fbfb';
}

function copyToScan(idx) {
  const cached = loadCachedScams();
  const ex = cached?.alerts?.[idx]?.example;
  if (!ex) return;
  document.getElementById('threat-input').value = ex;
  setTab('scan');
  setTimeout(() => analyze(), 200);
}

function emptyCard(title, sub) {
  return `<div class="brutal-border-thin bg-surface-container-low p-6 text-center">
    <div class="font-label-mono text-label-mono uppercase text-primary mb-1">${escapeHtml(title)}</div>
    <div class="font-body-md text-on-surface-variant">${escapeHtml(sub)}</div>
  </div>`;
}

// ══════════════════════════════════════════════════════════
// LOGS : Historique local
// ══════════════════════════════════════════════════════════

function loadLogs() {
  try { return JSON.parse(localStorage.getItem(LOGS_KEY) || '[]'); }
  catch { return []; }
}

function saveLog(entry) {
  const logs = loadLogs();
  logs.unshift(entry);
  logs.length = Math.min(logs.length, LOGS_MAX);
  try { localStorage.setItem(LOGS_KEY, JSON.stringify(logs)); } catch {}
}

function clearLogs() {
  if (!confirm('Effacer définitivement tout l\'historique local ?')) return;
  localStorage.removeItem(LOGS_KEY);
  renderLogs();
}

function renderLogs() {
  const logs = loadLogs();
  const list = document.getElementById('logs-list');
  if (!logs.length) {
    list.innerHTML = emptyCard('AUCUN SCAN ENREGISTRÉ', 'L\'historique des scans apparaîtra ici. Toutes les données restent sur ton appareil.');
    return;
  }
  const verdictMeta = {
    danger: { label: 'DANGER', bg: '#ff3a3a', fg: '#fff' },
    warn:   { label: 'SUSPECT', bg: '#fce442', fg: '#131313' },
    ok:     { label: 'CLEAR', bg: '#00ff7a', fg: '#131313' },
  };
  list.innerHTML = logs.map(l => {
    const m = verdictMeta[l.verdict] || verdictMeta.ok;
    const d = new Date(l.ts);
    const dateStr = d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
    const inputSample = escapeHtml((l.input || '').slice(0, 80) + (l.input?.length > 80 ? '…' : ''));
    return `
      <div class="brutal-border-thin bg-surface-container-low">
        <div class="flex justify-between items-center px-3 py-2 border-b-border-width-thin border-surface-container-highest">
          <span class="font-label-mono text-[10px] uppercase text-on-surface-variant">${dateStr}</span>
          <span class="font-label-mono text-[10px] uppercase px-2 py-0.5 tracking-widest font-bold" style="background:${m.bg};color:${m.fg}">${m.label}</span>
        </div>
        <div class="px-3 py-2 font-label-mono text-xs text-on-surface-variant break-all">${inputSample || '<vide>'}</div>
      </div>
    `;
  }).join('');
}

// ══════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

document.getElementById('threat-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.ctrlKey) { e.preventDefault(); analyze(); }
});

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

// Boot
setTab('scan');
loadScams();
