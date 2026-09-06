!macro customUnInstall
  DetailPrint "Stopping and removing the GamePath network service..."
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\deploy\uninstall-windows-service.ps1"'
  Pop $0
!macroend
