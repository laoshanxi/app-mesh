!define APP_NAME "appmesh"
!define APP_VERSION "3.0.0"
!define COMPANY_NAME "laoshanxi"
!define INSTALL_DIR "C:\local\${APP_NAME}"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "..\..\build\${APP_NAME}_${APP_VERSION}_windows_x64.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin
SetCompressor lzma
ShowInstDetails show

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Var START_APPMESH
Var NSSM_PATH
Var SILENT_MODE

!macro ExecNssmChecked Command Description
    nsExec::ExecToLog '${Command}'
    Pop $0
    ${If} $0 != 0
        DetailPrint "ERROR: ${Description} failed (exit code $0)"
        MessageBox MB_ICONSTOP "${Description} failed (exit code $0)" /SD IDOK
        Abort
    ${EndIf}
!macroend

!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchAppIfChecked
!define MUI_FINISHPAGE_RUN_TEXT "Start AppMeshService now"

!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Add $INSTDIR\bin to system PATH"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION AddToPath
!define MUI_FINISHPAGE_SHOWREADME_STATE 1 ; Checked by default

!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"

; Pages
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Function .onInit
    ; Detect if silent install (/S) is present in the command line
    StrCpy $SILENT_MODE 0
    
    ; Use built-in silent mode detection
    ${If} ${Silent}
        StrCpy $SILENT_MODE 1
    ${EndIf}
FunctionEnd

Section "Install"
    ; Stop an existing installation before replacing its binaries.
    StrCpy $NSSM_PATH "$INSTDIR\bin\nssm.exe"
    IfFileExists "$NSSM_PATH" 0 install_files
    nsExec::ExecToLog '"$NSSM_PATH" stop AppMeshService'
    nsExec::ExecToLog '"$NSSM_PATH" remove AppMeshService confirm'

install_files:
    SetOutPath "$INSTDIR"
    File /r "..\..\build\package_root\*"
    ; Remove the obsolete packaged definition before the service starts. Its old
    ; application name would otherwise start a second authentication process.
    Delete "$INSTDIR\apps\auth-dex.yaml"

    StrCpy $START_APPMESH "$INSTDIR\bin\appmesh.exe"
    StrCpy $NSSM_PATH "$INSTDIR\bin\nssm.exe"

    ; Generate SSL certs
    DetailPrint "Starting SSL certificate generation"
    nsExec::ExecToLog '"$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\ssl\generate_ssl_cert.ps1"'
    Pop $0
    DetailPrint "PowerShell exit code: $0"
    ${If} $0 != 0
        DetailPrint "ERROR: SSL certificate generation failed"
        MessageBox MB_ICONSTOP "SSL certificate generation failed"
        Abort
    ${Else}
        DetailPrint "SUCCESS: SSL certificate generation completed"
    ${EndIf}
    ; Install service
    !insertmacro ExecNssmChecked '"$NSSM_PATH" install AppMeshService "$START_APPMESH"' "AppMeshService installation"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService AppDirectory "$INSTDIR"' "AppMeshService application-directory configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService Start SERVICE_AUTO_START' "AppMeshService start-mode configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService Type SERVICE_WIN32_OWN_PROCESS' "AppMeshService type configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService Description "App Mesh background service"' "AppMeshService description configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService DependOnService Dhcp Tcpip Netman' "AppMeshService dependency configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService AppStdout "$INSTDIR\install_stdout.log"' "AppMeshService stdout configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService AppStderr "$INSTDIR\install_stderr.log"' "AppMeshService stderr configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService AppExit Default Restart' "AppMeshService restart-policy configuration"
    !insertmacro ExecNssmChecked '"$NSSM_PATH" set AppMeshService AppRestartDelay 5000' "AppMeshService restart-delay configuration"

    ; Windows ships the same protected bundled authentication service as Linux/macOS.
    ; setup.ps1 remains available when an operator intentionally selects an
    ; external issuer instead.
    DetailPrint "The bundled authentication service will start with AppMeshService."
    DetailPrint "Optional external issuer configuration:"
    DetailPrint "  powershell -ExecutionPolicy Bypass -File $INSTDIR\script\setup.ps1 -Issuer https://auth.example.com/oidc"
    DetailPrint "Print the packaged administrator password after startup:"
    DetailPrint "  powershell -ExecutionPolicy Bypass -File $INSTDIR\script\appmesh-auth.ps1 print-initial-password"
    DetailPrint "After startup, run appm logon locally with the packaged administrator; first-admin enrollment is automatic."

    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Check if the user opted to add to PATH (handled by MUI_FINISHPAGE_SHOWREADME_FUNCTION)
    ; The AddToPath function will be called after the section if checked.
    ; Apply silent-mode behavior
    ${If} $SILENT_MODE == 1
        Call AddToPath
        Call LaunchAppIfChecked
    ${EndIf}
SectionEnd

Function LaunchAppIfChecked
    ; start the service if the user checked the box
    !insertmacro ExecNssmChecked '"$INSTDIR\bin\nssm.exe" start AppMeshService' "AppMeshService start"
FunctionEnd

Function AddToPath
    ; This function is called if the user checks the "Add to PATH" checkbox on the finish page.
    ; It uses the EnVar plugin to add the path, avoiding duplicates automatically.
    ; Ensure EnVar.dll is in $PLUGINSDIR or NSIS Plugins directory.
    ; Set target to HKLM as we are installing system-wide
    EnVar::SetHKLM
    ; Add the path value. EnVar::AddValue avoids duplicates.
    ; Using 'PATH' ensures it targets the system PATH variable.
    EnVar::AddValue "PATH" "$INSTDIR\bin"
    ; Pop the result (optional, for debugging/error checking)
    Pop $0
    ; DetailPrint "EnVar::AddValue PATH returned=|$0|" ; Uncomment for debugging
FunctionEnd

Section "Uninstall"
    ; stop and remove the service
    nsExec::ExecToLog '"$INSTDIR\bin\nssm.exe" stop AppMeshService'
    Sleep 1000
    nsExec::ExecToLog '"$INSTDIR\bin\nssm.exe" remove AppMeshService confirm'

    ; Remove $INSTDIR\bin from the system PATH
    ; Set target to HKLM for uninstallation as well
    EnVar::SetHKLM
    ; Delete the path value from the PATH variable.
    EnVar::DeleteValue "PATH" "$INSTDIR\bin"
    ; Pop the result (optional)
    Pop $0
    ; DetailPrint "EnVar::DeleteValue PATH returned=|$0|" ; Uncomment for debugging

    ; delete files and directories
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR"

    ; --- check if /PURGE flag is passed then delete confir dir ---
    StrCpy $CMDLINE "$CMDLINE" ; system var has full cmdline
    ${GetOptions} $CMDLINE "/PURGE" $0
    ${IfNot} $0 == ""
        RMDir /r "$APPDATA\AppMesh"
        RMDir /r "$LOCALAPPDATA\AppMesh"
    ${EndIf}
SectionEnd
