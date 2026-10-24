# Security

Patchbell is a security tool, so reports about Patchbell itself are welcome.

## Reporting a vulnerability

Please use **Report a vulnerability** in this repository's Security tab rather than a public issue. Include the version, steps to reproduce and impact.

## What Patchbell stores and sends

- Your watchlist, settings and notification history live in `~/.patchbell` (or `$PATCHBELL_HOME`). `config.json` can hold notification tokens and webhook URLs, so it is written with `600` permissions in a `700` directory.
- To check an item, Patchbell sends its product or package name (and for OSV, its version) to the public data sources: NVD, OSV, cve.org, CISA, FIRST (EPSS) and endoflife.date. Nothing else leaves your machine, and there is no Patchbell server or account.
- Notifications go only to the channels you configure.
- `patchbell scan` runs version commands and reads app metadata locally. It adds nothing on its own and sends nothing anywhere. The MCP server only exposes it with `--allow-scan`, because the agent's model provider would see the list.
- Advisory text comes from third parties. The MCP server tells agents to treat it as data, not instructions.

## Accuracy

Patchbell reports what the public records say. They can be wrong or late: NVD sometimes lists the wrong fixed version, and vendors may ship fixes under different version numbers (for example macOS's bundled tools, or distro backports, which `osv:` packages handle). Treat an alert as a strong prompt to check the vendor's advisory, and a quiet check as "nothing known", not "safe".
