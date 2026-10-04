!include "LogicLib.nsh"

!macro customUnInstall
  DetailPrint "Stopping AI Firewall processes and cleaning security rules..."
  ${if} ${FileExists} "$INSTDIR\resources\uninstall_cleanup.ps1"
    ExecWait 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\uninstall_cleanup.ps1"'
  ${else}
    ExecWait 'taskkill /F /IM "AI Firewall.exe" /T'
    ExecWait 'taskkill /F /IM "aifirewall-backend.exe" /T'
  ${endif}

  IfSilent skip_appdata
  MessageBox MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION "Do you want to delete all AI Firewall application data, logs, and settings (%APPDATA%\AIFirewall)?" IDNO skip_appdata
    RMDir /r "$APPDATA\AIFirewall"
  skip_appdata:
!macroend
