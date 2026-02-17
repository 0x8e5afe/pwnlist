# Pwnlist - Interactive Checklist for Pentesters

![HTML](https://img.shields.io/badge/HTML-5-E34F26?logo=html5&logoColor=white)
![CSS](https://img.shields.io/badge/CSS-3-1572B6?logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6-F7DF1E?logo=javascript&logoColor=black)
![Steps](https://img.shields.io/badge/Checklist-137%20steps-22c55e)

> Disclaimer
>
> Pwnlist is for educational and authorized security testing only.
> Use it only on systems where you have explicit permission to test.

## What is Pwnlist?

Pwnlist is a browser-based, interactive penetration testing checklist built for pentesting workflows. It turns a large static checklist into a navigable workspace with progress tracking, searchable commands, and quick snippet copy actions.

The app is fully static (`index.html` + `styles.css` + `script.js`) and runs directly in the browser.

![Pwnsheet Screenshot](assets/screenshot.png) 

## Key Features

- 15 phase groups covering end-to-end offensive workflow
- 137 actionable checklist items with practical command snippets
- Persistent progress tracking using `localStorage`
- Group-level completion toggles and progress bar
- Expand all / collapse all controls
- Global command + step search across metadata and snippets
- One-click snippet copy plus auto-copy when selecting snippet text
- Syntax highlighting (Highlight.js + custom shell highlighting)
- Reset workflow with confirmation modal
- Responsive UI for desktop and laptop use

## Checklist Coverage

The checklist spans:

1. Pre-Engagement & Setup
2. Reconnaissance & Enumeration
3. Service-Specific Enumeration
4. Vulnerability Analysis
5. Exploitation
6. Buffer Overflow (Windows x86 Stack BOF)
7. Post-Exploitation
8. Privilege Escalation - Linux
9. Privilege Escalation - Windows
10. Lateral Movement
11. Active Directory & Domain Compromise
12. Persistence & Looting
13. Pivoting & Tunneling
14. File Transfers
15. Proof Collection & Reporting

## Quick Start

```bash
# from this project folder
python3 -m http.server 8000
```

Open `http://localhost:8000` in your browser.

You can also open `index.html` directly, but a local server is recommended.

## How to Use

1. Pick a group from the left navigation.
2. Check off completed tasks as you go.
3. Open "Show snippets" on a task and copy only what you need.
4. Use `Command Search` to filter tasks/snippets quickly.
5. Use `Expand all` / `Collapse all` to manage focus.
6. Use reset when you want to start a fresh run.

Progress and collapsed state are saved automatically in browser storage.

## Project Structure

```text
Checklist/
|- index.html            # App shell and templates
|- styles.css            # UI styling
|- script.js             # Checklist data + rendering + interactions
|- README.md             # Project documentation
```

## Customize Content

Checklist content lives in `script.js` inside `CHECKLIST_DATA`.

Each item supports:

- `phase`
- `step`
- `title`
- `brief_description`
- `feasible_when`
- `snippets[]` with `lang` + `code`

To add or edit content, update objects in `CHECKLIST_DATA` and reload the page.

## Contributing

Contributions are welcome.

- Improve checklist coverage or command quality
- Add missing service enum or privesc paths
- Fix UI/UX bugs and interaction polish
- Improve wording and metadata consistency

Recommended local validation before PR:

1. Verify rendering and filters.
2. Verify snippet copy behavior.
3. Verify persisted state survives refresh.
4. Verify responsive behavior.

## Ethical Use

Unauthorized access to systems is illegal.

Use Pwnlist responsibly, within agreed scope, and in compliance with applicable laws and rules of engagement.

---

<div align="center">

Made with ❤️ by [Giuseppe Toscano](https://gtoscano.me)

[⭐ Star on GitHub](https://github.com/0x8e5afe/pwnlist)

</div>