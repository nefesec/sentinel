/**
 * Sentinel — logique UI + analyse locale.
 * Toute l'analyse est faite en local. Aucun envoi réseau autre que le fetch
 * périodique du JSON public (toutes les 6h, GET anonyme).
 */

const SCAMS_JSON_URL = 'scams.json';  // chemin relatif (même origine que la page)
const SCAMS_REFRESH_MS = 6 * 60 * 60 * 1000;
const SCAMS_CACHE_KEY = 'sentinel:scams';

// ────── Tabs ──────

document.querySelectorAll('nav.tabs button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav.tabs button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'live') { loadScams(); }
  });
});

// ────── Analyse ──────

function analyze() {
  const input = document.getElementById('input').value.trim();
  const verdictEl = document.getElementById('verdict');
  if (!input) {
    verdictEl.innerHTML = '';
    return;
  }

  const type = detectInputType(input);
  let score = 0;
  const reasons = [];

  // Règles statiques (rules.js)
  for (const r of RULES.keywords) {
    if (r.re.test(input)) {
      score += r.score;
      reasons.push(reasonFmt(r));
    }
  }
  for (const r of RULES.urlPatterns) {
    if (r.re.test(input)) {
      score += r.score;
      reasons.push(reasonFmt(r));
    }
  }
  if (type === 'phone') {
    for (const r of RULES.phonePatterns) {
      if (r.re.test(input)) {
        score += r.score;
        if (r.score > 0) reasons.push(reasonFmt(r));
      }
    }
  }
  for (const c of RULES.combos) {
    const all = c.triggers.every(t => input.toLowerCase().includes(t));
    if (all) {
      score += c.score;
      reasons.push(reasonFmt(c));
    }
  }

  // Patterns dynamiques (scams.json — chargés en cache)
  const dynScams = loadCachedScams();
  if (dynScams && dynScams.patterns) {
    for (const r of dynScams.patterns) {
      try {
        const re = new RegExp(r.re, r.flags || 'i');
        if (re.test(input)) {
          score += r.score || 2;
          reasons.push(`${r.reason} (mise à jour récente)`);
        }
      } catch (_) {}
    }
  }

  // Rendu verdict
  let cssClass, title, advice;
  if (score >= 5) {
    cssClass = 'danger';
    title = 'Arnaque très probable';
    advice = 'Ne clique pas, n\'appelle pas, ne réponds pas. Supprime le message. Si tu doutes, contacte l\'organisme via ses canaux officiels (jamais via le lien/numéro du message).';
  } else if (score >= 2) {
    cssClass = 'warn';
    title = 'Méfiance recommandée';
    advice = 'Plusieurs signaux suspects. Vérifie via une source officielle (site web tapé à la main, numéro au dos de ta carte bancaire, etc.) avant toute action.';
  } else {
    cssClass = 'ok';
    title = 'Aucun signal d\'arnaque connu';
    advice = 'Mais reste prudent : une nouvelle arnaque peut passer. Si quelque chose te semble bizarre, n\'agis pas dans la précipitation.';
  }

  verdictEl.innerHTML = `
    <div class="verdict ${cssClass}">
      <h3>${title}</h3>
      <p class="reason">${advice}</p>
      ${reasons.length > 0 ? `<ul>${reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>` : ''}
    </div>
  `;
}

function reasonFmt(r) {
  return r.reason;
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Permet de lancer la vérif avec Enter (sauf shift+enter pour multi-lignes)
document.getElementById('input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey && e.ctrlKey) {
    e.preventDefault();
    analyze();
  }
});

// ────── Arnaques en cours (fetch JSON) ──────

function loadCachedScams() {
  try {
    const raw = localStorage.getItem(SCAMS_CACHE_KEY);
    if (!raw) return null;
    const data = JSON.parse(raw);
    return data;
  } catch { return null; }
}

async function loadScams(force = false) {
  const cached = loadCachedScams();
  const now = Date.now();
  const stale = !cached || force || (now - (cached._fetchedAt || 0)) > SCAMS_REFRESH_MS;

  // Affiche le cache immédiatement si dispo
  if (cached) renderScams(cached);

  if (!stale) return;

  try {
    const res = await fetch(SCAMS_JSON_URL, { cache: 'no-cache' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    data._fetchedAt = now;
    localStorage.setItem(SCAMS_CACHE_KEY, JSON.stringify(data));
    renderScams(data);
  } catch (e) {
    if (!cached) {
      document.getElementById('scam-list').innerHTML =
        `<p style="color:var(--muted); font-size:14px; padding:20px; text-align:center;">
          Impossible de récupérer la liste actuelle. ${cached ? '' : 'Aucune donnée locale.'}
        </p>`;
    }
  }
}

function renderScams(data) {
  const list = document.getElementById('scam-list');
  const updated = document.getElementById('last-updated');

  if (data._fetchedAt) {
    const d = new Date(data._fetchedAt);
    updated.textContent = `Mis à jour : ${d.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}`;
  }

  if (!data.alerts || data.alerts.length === 0) {
    list.innerHTML = '<p style="color:var(--muted); font-size:14px; padding:20px; text-align:center;">Aucune arnaque active signalée.</p>';
    return;
  }

  list.innerHTML = data.alerts.map(a => `
    <div class="scam-item">
      <h3>${escapeHtml(a.title)}<span class="badge ${a.kind}">${badgeLabel(a.kind)}</span></h3>
      <div class="meta">${a.date ? 'Détecté ' + escapeHtml(a.date) : ''}</div>
      <div class="desc">${escapeHtml(a.description)}</div>
      ${a.example ? `<div class="desc" style="margin-top:8px; font-style:italic; color:var(--muted);">Exemple : « ${escapeHtml(a.example)} »</div>` : ''}
    </div>
  `).join('');
}

function badgeLabel(kind) {
  return { sms: 'SMS', call: 'Appel', mail: 'Email', url: 'Site web' }[kind] || kind;
}

// ────── PWA install + service worker ──────

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

// Charge la liste au démarrage (sans afficher si l'onglet Scanner est actif)
loadScams();
