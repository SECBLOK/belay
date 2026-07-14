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

; NSIS_HOOK_POSTINSTALL runs AFTER the app files land. Belay now installs
; per-machine (elevated), so we use that one-time admin to (1) pre-create the
; shared data dir with a permissive ACL and (2) register the LocalSystem service
; so protection is active from install. Best-effort: nsExec failures must NOT
; fail the install - the app is fully usable without the service.
;
; The ACL grant is load-bearing. The service's daemon runs as LocalSystem and
; creates C:\ProgramData\Belay; without granting the interactive user write
; access, user-context agent hooks could not append audit.ndjson and cooperative-
; agent telemetry would silently stop (the empty-dashboard symptom). Granting
; Authenticated Users (SID S-1-5-11) Modify, inheritable (OI)(CI), lets either
; SYSTEM or the logged-in user write the audit log.
!macro NSIS_HOOK_POSTINSTALL
  ReadEnvStr $0 ProgramData
  CreateDirectory "$0\Belay"
  nsExec::Exec 'icacls "$0\Belay" /grant "*S-1-5-11:(OI)(CI)M"'
  Pop $1
  nsExec::Exec '"$INSTDIR\belay.exe" install-service --enable --wait-socket 0 --repoint-hook false --exec-path "$INSTDIR\belay.exe"'
  Pop $1
!macroend
