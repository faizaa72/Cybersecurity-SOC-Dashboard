# SENTINEL — SOC-9 Threat Monitor

A Security Operations Center (SOC) dashboard concept built in the **Terminal CLI** design system — a high-contrast, monospace, phosphor-green interface styled after a live shell session.

Plain HTML / CSS / JS. No build step, no dependencies beyond a Google Font import.

## Files

```
soc-dashboard/
├── index.html   Markup and layout structure
├── styles.css   Terminal CLI design system (tokens, panes, effects)
├── script.js    Simulated live data + all interactivity
└── README.md
```

## Running it

Open `index.html` directly in any modern browser. That's it — everything runs client-side.

## Layout

The screen is split into four panes, like `tmux`/`vim` windows:

| Pane | Content |
|---|---|
| **Alert Queue** (top-left) | Live, sortable, filterable list of security events |
| **Threat Level** (top-right) | Global risk score, verdict, and rolling stat/meter readouts |
| **Attack Timeline** (bottom-left) | Chronological feed of the same events, newest first |
| **System Status** (bottom-right) | Internal service health + perimeter node status |

A boot sequence plays once on load; a command bar above the grid types out sample `sentinel-cli` / `nmap` commands on a loop for atmosphere.

## UX challenges addressed

**Alert prioritization**
- Alerts auto-sort by severity (`critical → high → medium → low`), then recency.
- Filter buttons (or number keys `1`–`4`) isolate a severity tier; counts update live.
- `/` focuses a search box that matches event type, source, or target.
- One-click / one-key (`a`) acknowledgment moves an alert out of the active queue without deleting the record.

**Attack timelines**
- Every alert also lands in a continuous timeline, so an analyst can reconstruct "what happened when" independent of the triage queue above.
- Severity-coded markers keep critical events visually distinct in the scroll.

**High-pressure usability**
- A single Global Risk Score (0–100) with a plain-language verdict (`STABLE` / `ELEVATED` / `CRITICAL`) — no chart-reading required under stress.
- Full keyboard control (`1`–`4` filter, `/` search, `a` acknowledge, `Esc` reset) so hands never have to leave the keyboard mid-incident.
- New incidents arrive automatically every ~6–15 seconds and are announced via `aria-live` for screen reader users, so nothing has to be polled manually.
- High-contrast green-on-black palette exceeds WCAG AA; focus states are always visible; motion respects `prefers-reduced-motion`.

## Wiring in real data

All state lives in `script.js`. To connect a real feed:

- Replace `seedAlerts()` / `injectNewAlert()` with your API/WebSocket source, keeping the same alert shape: `{ id, sev, type, src, tgt, time, status, ack }`.
- `SERVICES` and `NODES` arrays drive the System Status pane — swap in a real health-check response.
- `computeThreatScore()` currently derives risk from open alert severity counts; replace with your own scoring model if you have one.

## Responsive behavior

Below 980px, the four panes stack vertically and the alert table collapses into labeled rows instead of columns, per the design system's mobile guidance.
