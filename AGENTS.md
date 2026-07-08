# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.
- This is a UCC (Splunk Add-on Builder) app: `default/inputs.conf`, `commands.conf`, and `app.conf` are
  generated at build time by `ucc-gen build` from `globalConfig.json` and are not committed to source.
  Look in `globalConfig.json` for input/config schema, not a committed conf file.
- `splunk-sdk` is capped to `>=2.1.1,<3` in `package/lib/requirements.txt` (splunk-sdk 3.x requires
  Python 3.13 only and breaks Splunk's Python 3.9 runtime). Keep this cap when touching dependencies.
- Dual-Python support (`python.required = 3.9, 3.13`) is declared via `meta.supportedPythonVersion` in
  `globalConfig.json`, not a conf file edit. ucc-gen templates it into every generated conf stanza that
  carries `python.version` (`inputs.conf`, `restmap.conf`, etc). Verify with `ucc-gen build` and inspect
  `output/qualtrics_audit/default/*.conf`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
