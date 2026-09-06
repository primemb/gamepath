!macro customInstall
  DetailPrint "Installing and starting the GamePath network service..."
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\deploy\install-windows-service.ps1" -ProjectRoot "$INSTDIR\resources" -SkipBuild'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The GamePath network service could not be installed. Setup will stop."
    Abort
  ${EndIf}
!macroend

!macro customUnInstall
  DetailPrint "Stopping and removing the GamePath network service..."
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\deploy\uninstall-windows-service.ps1"'
  Pop $0
!macroend
