# HK1 local rehearsal: starts the deliberately vulnerable demo origin (127.0.0.1:8081), the HDD proxy
# (127.0.0.1:8080, mode block) and the admin web UI (127.0.0.1:9090) through the Node launcher.
#
# The launcher is `npm run dev`; this wrapper exists because the HK1 definition of done names `demo/run-local`
# (COLLAB.md). It builds only what is missing, creates the dev data directory and prints the three URLs.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
npm run dev
