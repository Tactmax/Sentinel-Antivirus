; ============================================================================
;  Sentinel Antivirus - per-user installer (Inno Setup 6.3+)
;
;  Build:
;    "C:\Users\user\AppData\Local\Programs\Inno Setup 6\ISCC.exe" ".\installer\Sentinel.iss"
;
;  Notes:
;   * PrivilegesRequired=lowest - no UAC prompt; everything lives in the
;     installing user's profile.
;   * Self-contained .NET 10 build - no runtime install needed.
;   * The ClamAV engine is NOT bundled. It is downloaded on first run from the
;     app's one-click installer, from the official Cisco Talos GitHub release,
;     with SHA-256 digest verification.
;   * Uninstall keeps %LOCALAPPDATA%\Sentinel (quarantine, history, settings,
;     downloaded engine). Pass /PURGE to the uninstaller to remove it too.
; ============================================================================

#define MyAppName "Sentinel Antivirus"
#define MyAppVersion "1.3.0"
#define MyAppPublisher "Sentinel"
#define MyAppExeName "Sentinel.exe"
#define PublishDir "..\publish\app"

[Setup]
AppId={{7F3C1A62-4B0E-4D2B-9E5A-6C1D2F8B9A01}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppComments=On-demand ClamAV scanner. Keep Microsoft Defender enabled.
DefaultDirName={localappdata}\Programs\Sentinel
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=yes
DisableWelcomePage=no

; Per-user install, no elevation anywhere.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; The self-contained build targets .NET 10, which requires Windows 10 or newer.
MinVersion=10.0

; Single-language installer: never show the language picker.
ShowLanguageDialog=no

; x64 binary; x64compatible also allows install on ARM64 under emulation.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

OutputDir=..\publish\installer
OutputBaseFilename=Sentinel-Setup-{#MyAppVersion}
SetupIconFile=..\Sentinel\Resources\sentinel.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

; Keep a setup log in TEMP to help diagnose failed installs.
SetupLogging=yes

Compression=lzma2/max
SolidCompression=yes
LZMANumBlockThreads=4
WizardStyle=modern
ChangesAssociations=no
CloseApplications=yes
RestartApplications=no

VersionInfoVersion=1.3.0.0
VersionInfoProductVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoProductTextVersion={#MyAppVersion}
VersionInfoDescription={#MyAppName} setup
VersionInfoCompany={#MyAppPublisher}
VersionInfoCopyright=Copyright (C) Sentinel

InfoBeforeFile=InfoBefore.txt
InfoAfterFile=InfoAfter.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#PublishDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Code]
function CmdLineParamExists(const Value: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Value) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

// Normal uninstall leaves %LOCALAPPDATA%\Sentinel alone so the user keeps their
// quarantine, scan history, settings and downloaded engine. Running the
// uninstaller with /PURGE removes that folder as well.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if CmdLineParamExists('/PURGE') then
    begin
      DataDir := ExpandConstant('{localappdata}\Sentinel');
      if DirExists(DataDir) then
        DelTree(DataDir, True, True, True);
    end;
  end;
end;
