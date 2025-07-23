!define APP_NAME "appmesh"
!define APP_VERSION "2.1.2"
!define COMPANY_NAME "laoshanxi"
!define INSTALL_DIR "C:\local\${APP_NAME}"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "..\..\build\${APP_NAME}_${APP_VERSION}_windows_setup.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin
SetCompressor lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Var START_APPSVC
Var NSSM_PATH
Var SILENT_MODE

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
    SetOutPath "$INSTDIR"
    File /r "..\..\build\appmesh\*"

    StrCpy $START_APPSVC "$INSTDIR\bin\appsvc.exe"
    StrCpy $NSSM_PATH "$INSTDIR\bin\nssm.exe"

    ; create service (remove if exists)
    nsExec::ExecToLog '"$NSSM_PATH" remove AppMeshService confirm'
    nsExec::ExecToLog '"$NSSM_PATH" install AppMeshService "$START_APPSVC"'
    nsExec::ExecToLog '"$NSSM_PATH" set AppMeshService AppDirectory "$INSTDIR"'
    nsExec::ExecToLog '"$NSSM_PATH" set AppMeshService Start SERVICE_AUTO_START'
    nsExec::ExecToLog '"$NSSM_PATH" set AppMeshService Description "App Mesh background service"'
    nsExec::ExecToLog '"$NSSM_PATH" set AppMeshService AppStdout "$INSTDIR\install_stdout.log"'
    nsExec::ExecToLog '"$NSSM_PATH" set AppMeshService AppStderr "$INSTDIR\install_stderr.log"'

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
    nsExec::ExecToLog '"$INSTDIR\bin\nssm.exe" start AppMeshService'
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
SectionEnd
