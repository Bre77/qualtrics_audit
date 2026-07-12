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
- `globalConfig.json` `meta.version` is the sole version source of truth. Past Splunkbase releases were
  sometimes bumped at publish time without committing back, so before bumping, check the live listing
  (`gh api https://splunkbase.splunk.com/api/v1/app/8229/release/`, newest release name) rather than
  trusting the committed value - the new version must be strictly greater than whatever is actually published.
- CI (`.github/workflows/validate.yml`) calls the reusable build+AppInspect workflow hosted in
  `Bre77/splunk_nats` (`.github/workflows/_reusable-build-appinspect.yml@main`) with `use_ucc_gen: true`;
  it is not copied locally. It is credential-free and never publishes - Splunkbase publishing stays a
  separate, human-triggered step.
- `package/lib/exclude.txt` drops `solnlib`/`splunktaucclib`'s optional OpenTelemetry+grpc chain
  (`grpcio`, `protobuf`, `opentelemetry-*`) from the ucc-gen build - those wheels vendor x86_64-only
  native `.so` files that fail AppInspect's `check_aarch64_compatibility`, and this add-on never imports
  that observability path. Mirrors `Bre77/splunk_nats`'s `package/lib/exclude.txt`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
