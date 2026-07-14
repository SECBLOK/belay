; Belay NSIS installer hooks (wired via tauri.conf.json > bundle.windows.nsis.installerHooks).
;
; NSIS_HOOK_PREINSTALL runs BEFORE the installer overwrites the app files. Belay
; runs a resident daemon (the belay.exe sidecar, and optionally the "Belay" boot
; service). A running belay.exe LOCKS the file, so on an update the copy fails with
; "Error opening file for writing: ...\Belay\belay.exe". Tauri already closes the
; main app window (Belay.exe) but does NOT know about the sidecar daemon, so stop
; it here first.
;
; Everything is best-effort: a not-installed service / not-running process is the
; normal fresh-install case, not an error. `sc stop` needs admin and no-ops when
; the per-user installer isn't elevated - the taskkill still frees the user-owned
; belay.exe that actually locks the per-user install path.
!macro NSIS_HOOK_PREINSTALL
  nsExec::Exec 'sc.exe stop Belay'
  Pop $0
  nsExec::Exec 'taskkill /F /T /IM belay.exe'
  Pop $0
  Sleep 800
!macroend
