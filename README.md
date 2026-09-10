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
