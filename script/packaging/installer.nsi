!define APP_NAME "appmesh"
!define APP_VERSION "2.1.2"
!define COMPANY_NAME "laoshanxi"
!define INSTALL_DIR "C:\local\${APP_NAME}"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "..\..\build\${APP_NAME}_${APP_VERSION}_setup.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin
SetCompressor lzma

!include "MUI2.nsh"

!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchAppIfChecked
!define MUI_FINISHPAGE_RUN_TEXT "Start appsvc now"
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"

; Pages
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Var START_APPSVC
Var NSSM_PATH

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
SectionEnd

Function LaunchAppIfChecked
    ; start the service if the user checked the box
    nsExec::ExecToLog '"$INSTDIR\bin\nssm.exe" start AppMeshService'
FunctionEnd

Section "Uninstall"
    ; stop and remove the service
    nsExec::ExecToLog '"$INSTDIR\bin\nssm.exe" stop AppMeshService'
    nsExec::ExecToLog '"$INSTDIR\bin\nssm.exe" remove AppMeshService confirm'

    ; delete files and directories
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR"
SectionEnd
