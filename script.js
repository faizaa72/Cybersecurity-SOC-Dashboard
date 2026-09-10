(() => {
  'use strict';

  /* =========================================================
     DATA
     ========================================================= */
  const SEVERITIES = ['critical', 'high', 'medium', 'low'];
  const SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1 };

  const EVENT_TYPES = [
    { type: 'SSH Brute Force',        sev: 'high' },
    { type: 'SQL Injection Attempt',  sev: 'critical' },
    { type: 'Port Scan Detected',     sev: 'low' },
    { type: 'Malware Beacon (C2)',    sev: 'critical' },
    { type: 'Privilege Escalation',   sev: 'critical' },
    { type: 'Data Exfil Attempt',     sev: 'critical' },
    { type: 'Phishing Link Clicked',  sev: 'high' },
    { type: 'Anomalous Login (GEO)',  sev: 'medium' },
    { type: 'Firewall Rule Triggered',sev: 'low' },
    { type: 'DNS Tunneling Suspected',sev: 'high' },
    { type: 'Failed MFA x5',          sev: 'medium' },
    { type: 'Unpatched CVE Scan',     sev: 'medium' },
    { type: 'DDoS Traffic Spike',     sev: 'high' },
    { type: 'Suspicious Cron Added',  sev: 'medium' },
    { type: 'Lateral Movement (SMB)', sev: 'critical' },
  ];

  const SOURCE_IPS = [
    '203.0.113.44', '198.51.100.12', '45.83.12.201', '91.202.4.18',
    '104.244.79.6', '185.220.101.7', '61.177.172.9', '172.98.64.31',
    '141.98.11.3', '5.188.62.140',
  ];

  const TARGETS = [
    'web-01.acme.internal', 'db-02.acme.internal', 'dc-01.acme.internal',
    'vpn-gw.acme.internal', 'mail-relay.acme.internal', 'api-gw.acme.internal',
    'build-svr.acme.internal', 'hr-portal.acme.internal',
  ];

  const SERVICES = [
    { name: 'IDS / Snort Engine',      status: 'ok' },
    { name: 'SIEM Ingest Pipeline',    status: 'ok' },
    { name: 'EDR Fleet Agent',         status: 'warn' },
    { name: 'Firewall Cluster',        status: 'ok' },
    { name: 'Threat Intel Feed',       status: 'ok' },
    { name: 'Backup Replication',      status: 'err' },
  ];

  const NODES = [
    { name: 'edge-fw-a', status: 'ok' },
    { name: 'edge-fw-b', status: 'ok' },
    { name: 'core-sw-01', status: 'ok' },
    { name: 'vpn-gw-01', status: 'warn' },
  ];

  const STATUS_TAG = { ok: '[OK]', warn: '[WARN]', err: '[ERR]' };
  const STATUS_CLASS = { ok: 'tag-ok', warn: 'tag-warn', err: 'tag-err' };

  /* =========================================================
     STATE
     ========================================================= */
  let alerts = [];
  let alertSeq = 1;
  const activeFilters = new Set(SEVERITIES); // all shown by default
  let searchTerm = '';
  let ackCount = 0;

  /* =========================================================
     HELPERS
     ========================================================= */
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
  const pad2 = (n) => String(n).padStart(2, '0');

  function timeStr(d) {
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }

  function announce(msg) {
    const el = $('#srLive');
    if (el) el.textContent = msg;
  }

  /* =========================================================
     BOOT SEQUENCE
     ========================================================= */
  const BOOT_LINES = [
    'SENTINEL SOC-9 MAINFRAME  v3.4.1',
    'Initializing kernel modules ......... [OK]',
    'Mounting encrypted log volume ....... [OK]',
    'Establishing SIEM uplink ............ [OK]',
    'Loading threat intelligence feed .... [OK]',
    'Authenticating analyst session ...... [OK]',
    'Starting intrusion detection loop ... [OK]',
    '',
    'WELCOME, ANALYST. STAY SHARP.',
  ];

  function runBoot(done) {
    const boot = $('#bootScreen');
    const textEl = $('#bootText');
    let li = 0, ci = 0;
    let out = '';

    function typeNext() {
      if (li >= BOOT_LINES.length) {
        setTimeout(() => {
          boot.classList.add('is-hidden');
          done();
        }, 350);
        return;
      }
      const line = BOOT_LINES[li];
      if (ci <= line.length) {
        out = BOOT_LINES.slice(0, li).join('\n') + (li > 0 ? '\n' : '') + line.slice(0, ci);
        textEl.textContent = out;
        ci++;
        setTimeout(typeNext, line.length === 0 ? 120 : 8);
      } else {
        li++; ci = 0;
        setTimeout(typeNext, 90);
      }
    }
    typeNext();
  }

  /* =========================================================
     CLOCK
     ========================================================= */
  let sessionStart = Date.now();
  function tickClock() {
    const now = new Date();
    $('#clockTime').textContent = timeStr(now);
    const elapsed = Math.floor((Date.now() - sessionStart) / 1000);
    const h = pad2(Math.floor(elapsed / 3600));
    const m = pad2(Math.floor((elapsed % 3600) / 60));
    const s = pad2(elapsed % 60);
    const footerRight = document.querySelector('.footer__right');
    if (footerRight) {
      footerRight.childNodes[0].textContent = `SESSION ${h}:${m}:${s} `;
    }
  }

  /* =========================================================
     COMMAND BAR TYPING LOOP
     ========================================================= */
  const CMD_SAMPLES = [
    'tail -f /var/log/sentinel/ids.log --grep=CRITICAL',
    'sentinel-cli alerts --sort=severity',
    'nmap -sV 10.0.4.0/24 --top-ports 50',
    'sentinel-cli incident ack --id=INC-4471',
  ];
  let cmdIdx = 0;
  function typeCommand() {
    const el = $('#cmdText');
    const full = CMD_SAMPLES[cmdIdx % CMD_SAMPLES.length];
    let i = 0;
    el.textContent = '';
    const typeInterval = setInterval(() => {
      el.textContent = full.slice(0, i);
      i++;
      if (i > full.length) {
        clearInterval(typeInterval);
        setTimeout(() => {
          const eraseInterval = setInterval(() => {
            el.textContent = full.slice(0, i);
            i--;
            if (i < 0) {
              clearInterval(eraseInterval);
              cmdIdx++;
              setTimeout(typeCommand, 400);
            }
          }, 12);
        }, 2200);
      }
    }, 38);
  }

  /* =========================================================
     ALERT GENERATION
     ========================================================= */
  function makeAlert(offsetSeconds = 0) {
    const ev = pick(EVENT_TYPES);
    const t = new Date(Date.now() - offsetSeconds * 1000);
    return {
      id: alertSeq++,
      sev: ev.sev,
      type: ev.type,
      src: pick(SOURCE_IPS),
      tgt: pick(TARGETS),
      time: t,
      status: 'open',
      ack: false,
    };
  }

  function seedAlerts(n) {
    const list = [];
    for (let i = 0; i < n; i++) {
      list.push(makeAlert(i * 47 + Math.floor(Math.random() * 30)));
    }
    alerts = list;
  }

  function sortAlerts() {
    alerts.sort((a, b) => {
      if (a.ack !== b.ack) return a.ack ? 1 : -1;
      if (SEV_WEIGHT[b.sev] !== SEV_WEIGHT[a.sev]) return SEV_WEIGHT[b.sev] - SEV_WEIGHT[a.sev];
      return b.time - a.time;
    });
  }

  /* =========================================================
     RENDER: ALERT QUEUE
     ========================================================= */
  function renderAlerts() {
    sortAlerts();
    const listEl = $('#alertList');
    listEl.innerHTML = '';

    let visibleCount = 0;

    alerts.forEach((a) => {
      const matchesSev = activeFilters.has(a.sev);
      const term = searchTerm.trim().toLowerCase();
      const matchesSearch = !term ||
        a.type.toLowerCase().includes(term) ||
        a.src.toLowerCase().includes(term) ||
        a.tgt.toLowerCase().includes(term);

      const li = document.createElement('li');
      li.className = 'alert-row' + (a.ack ? ' is-ack' : '') +
        (!matchesSev || !matchesSearch ? ' is-hidden' : '');
      li.dataset.id = a.id;

      const statusLabel = a.ack ? 'ACK\u2019D' : (a.sev === 'low' ? 'MONITORING' : 'OPEN');
      const statusClass = a.ack ? 'status-ack' : (a.sev === 'low' ? 'status-mon' : 'status-open');

      li.innerHTML = `
        <span class="col col--sev" data-label="SEV"><span class="badge badge--${a.sev}">${a.sev.slice(0,4).toUpperCase()}</span></span>
        <span class="col col--time" data-label="TIME">${timeStr(a.time)}</span>
        <span class="col col--type" data-label="EVENT">${a.type}</span>
        <span class="col col--src" data-label="SOURCE">${a.src}</span>
        <span class="col col--tgt" data-label="TARGET">${a.tgt}</span>
        <span class="col col--status ${statusClass}" data-label="STATUS">${statusLabel}</span>
        <span class="col col--action" data-label="ACTION">
          <button class="ack-btn" ${a.ack ? 'disabled' : ''} data-id="${a.id}">${a.ack ? 'DONE' : '[ ACK ]'}</button>
        </span>
      `;
      if (!li.classList.contains('is-hidden')) visibleCount++;
      listEl.appendChild(li);
    });

    updateCounts();
    $('#alertCountNote').textContent =
      `${visibleCount} shown \u00b7 ${alerts.filter(a => !a.ack).length} open \u00b7 ${alerts.filter(a => a.ack).length} acknowledged`;
  }

  function updateCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(a => { if (!a.ack) counts[a.sev]++; });
    $('#countCrit').textContent = counts.critical;
    $('#countHigh').textContent = counts.high;
    $('#countMed').textContent = counts.medium;
    $('#countLow').textContent = counts.low;
  }

  function ackAlert(id) {
    const a = alerts.find(x => x.id === Number(id));
    if (!a || a.ack) return;
    a.ack = true;
    ackCount++;
    renderAlerts();
    computeThreatScore();
    announce(`Alert ${a.type} from ${a.src} acknowledged.`);
  }

  /* =========================================================
     RENDER: TIMELINE
     ========================================================= */
  function renderTimelineEntry(a, prepend) {
    const tl = $('#timeline');
    const li = document.createElement('li');
    li.className = 'timeline-item';
    li.innerHTML = `
      <span class="timeline-item__time">${timeStr(a.time)}</span>
      <span class="timeline-item__rail">
        <span class="timeline-item__dot timeline-item__dot--${a.sev}"></span>
        <span class="timeline-item__line"></span>
      </span>
      <span class="timeline-item__body">${a.type} <span class="timeline-item__tag">${a.src} \u2192 ${a.tgt}</span></span>
    `;
    if (prepend) {
      tl.prepend(li);
    } else {
      tl.appendChild(li);
    }
    // cap timeline length
    while (tl.children.length > 40) tl.removeChild(tl.lastChild);
  }

  function seedTimeline() {
    const tl = $('#timeline');
    tl.innerHTML = '';
    const ordered = [...alerts].sort((a, b) => b.time - a.time);
    ordered.forEach(a => renderTimelineEntry(a, false));
  }

  /* =========================================================
     THREAT SCORE + METERS
     ========================================================= */
  function computeThreatScore() {
    const open = alerts.filter(a => !a.ack);
    const score = Math.min(100, open.reduce((sum, a) => sum + SEV_WEIGHT[a.sev] * 6, 0));
    $('#threatValue').textContent = String(score).padStart(2, '0');

    const barWidth = 20;
    const filled = Math.round((score / 100) * barWidth);
    $('#threatBar').textContent = '[' + '|'.repeat(filled) + '.'.repeat(barWidth - filled) + ']';

    const scoreEl = $('#threatValue');
    const barEl = $('#threatBar');
    const verdictEl = $('#threatVerdict');
    let verdict, color;
    if (score >= 70) { verdict = 'CRITICAL \u2014 IMMEDIATE ACTION REQUIRED'; color = 'var(--error)'; }
    else if (score >= 40) { verdict = 'ELEVATED \u2014 ACTIVE MONITORING'; color = 'var(--secondary)'; }
    else { verdict = 'STABLE \u2014 BASELINE ACTIVITY'; color = 'var(--primary)'; }
    verdictEl.textContent = verdict;
    scoreEl.style.color = color;
    scoreEl.style.textShadow = 'none';
    barEl.style.color = color;
    verdictEl.style.color = color;

    $('#statIncidents').textContent = String(alerts.filter(a => SEV_WEIGHT[a.sev] >= 3).length);
    $('#statBlocked').textContent = String(120 + Math.floor(Math.random() * 40));
    $('#statMttr').textContent = `${6 + Math.floor(Math.random() * 5)}m`;
  }

  function randomMeter(el, min, max) {
    const width = 10;
    const val = min + Math.random() * (max - min);
    const filled = Math.round((val / 100) * width);
    el.textContent = '[' + '|'.repeat(Math.min(width, Math.max(0, filled))) + '.'.repeat(Math.max(0, width - filled)) + ']';
  }

  function tickMeters() {
    randomMeter($('#meterNetwork'), 20, 85);
    randomMeter($('#meterAuth'), 10, 60);
    randomMeter($('#meterEgress'), 15, 70);
  }

  /* =========================================================
     RENDER: SYSTEMS + NODES
     ========================================================= */
  function renderServices() {
    const ul = $('#serviceList');
    ul.innerHTML = '';
    SERVICES.forEach(s => {
      const li = document.createElement('li');
      li.className = 'service-row';
      li.innerHTML = `<span class="service-row__name">${s.name}</span><span class="${STATUS_CLASS[s.status]}">${STATUS_TAG[s.status]}</span>`;
      ul.appendChild(li);
    });
  }

  function renderNodes() {
    const ul = $('#nodeList');
    ul.innerHTML = '';
    NODES.forEach(n => {
      const li = document.createElement('li');
      li.className = 'node-row';
      li.innerHTML = `<span class="node-row__name">${n.name}</span><span class="${STATUS_CLASS[n.status]}">${STATUS_TAG[n.status]}</span>`;
      ul.appendChild(li);
    });
  }

  /* =========================================================
     SEVERITY FILTER + SEARCH INTERACTIONS
     ========================================================= */
  function toggleFilter(sev) {
    if (activeFilters.has(sev)) {
      if (activeFilters.size === 1) return; // keep at least one visible
      activeFilters.delete(sev);
    } else {
      activeFilters.add(sev);
    }
    $$('.sev-btn').forEach(btn => {
      btn.classList.toggle('is-active', activeFilters.has(btn.dataset.sev));
    });
    renderAlerts();
  }

  function resetFilters() {
    SEVERITIES.forEach(s => activeFilters.add(s));
    $$('.sev-btn').forEach(btn => btn.classList.add('is-active'));
    searchTerm = '';
    $('#alertSearch').value = '';
    renderAlerts();
  }

  /* =========================================================
     LIVE ALERT SIMULATION
     ========================================================= */
  function injectNewAlert() {
    const a = makeAlert(0);
    alerts.unshift(a);
    renderAlerts();
    renderTimelineEntry(a, true);
    computeThreatScore();
    if (a.sev === 'critical' || a.sev === 'high') {
      announce(`New ${a.sev} severity alert: ${a.type} from ${a.src}.`);
    }
    scheduleNextAlert();
  }

  function scheduleNextAlert() {
    const delay = 6000 + Math.random() * 9000;
    setTimeout(injectNewAlert, delay);
  }

  /* =========================================================
     KEYBOARD SHORTCUTS
     ========================================================= */
  function bindKeys() {
    document.addEventListener('keydown', (e) => {
      const tag = document.activeElement && document.activeElement.tagName;
      const inField = tag === 'INPUT' || tag === 'TEXTAREA';

      if (e.key === '/' && !inField) {
        e.preventDefault();
        $('#alertSearch').focus();
        return;
      }
      if (e.key === 'Escape') {
        if (inField) document.activeElement.blur();
        resetFilters();
        return;
      }
      if (!inField && ['1', '2', '3', '4'].includes(e.key)) {
        const map = { '1': 'critical', '2': 'high', '3': 'medium', '4': 'low' };
        toggleFilter(map[e.key]);
        return;
      }
      if (!inField && e.key.toLowerCase() === 'a') {
        const firstOpen = alerts.find(x => !x.ack);
        if (firstOpen) ackAlert(firstOpen.id);
      }
    });
  }

  /* =========================================================
     INIT
     ========================================================= */
  function init() {
    seedAlerts(16);
    renderAlerts();
    seedTimeline();
    renderServices();
    renderNodes();
    computeThreatScore();
    tickMeters();

    tickClock();
    setInterval(tickClock, 1000);
    setInterval(tickMeters, 4000);

    typeCommand();
    scheduleNextAlert();
    bindKeys();

    $('#sevFilters').addEventListener('click', (e) => {
      const btn = e.target.closest('.sev-btn');
      if (btn) toggleFilter(btn.dataset.sev);
    });

    $('#alertList').addEventListener('click', (e) => {
      const btn = e.target.closest('.ack-btn');
      if (btn && !btn.disabled) ackAlert(btn.dataset.id);
    });

    $('#alertSearch').addEventListener('input', (e) => {
      searchTerm = e.target.value;
      renderAlerts();
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    runBoot(init);
  });
})();
