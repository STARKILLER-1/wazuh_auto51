function Set-ServiceStartType {
    param (
        [string]$ServiceName,
        [int]$StartType
    )
    
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    
    if (Test-Path $servicePath) {
        Set-ItemProperty -Path $servicePath -Name "Start" -Value $StartType
    } else {
        Write-Host "Service $ServiceName not found."
    }
}

function Set-FirewallProfile {
    param (
        [string]$Profile,
        [string]$Setting,
        [string]$Value
    )
    
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$Profile"
    
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    Set-ItemProperty -Path $path -Name $Setting -Value $Value
}



$servicesToDisable = @("simptcp", "SNMP", "sacsvr", "SSDPSRV", "upnphost", "WMPNetworkSvc", "icssvc", "WpnService", "PushToInstall", "WinRM", "W3SVC", "XboxGipSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "WMSvc")
foreach ($service in $servicesToDisable) {
    Set-ServiceStartType -ServiceName $service -StartType 4
}

$firewallProfiles = @{
    "DomainProfile" = @{
        "EnableFirewall" = "1";
        "DefaultInboundAction" = "1";
        "DefaultOutboundAction" = "0";
        "DisableNotifications" = "1"
    };
    "PrivateProfile" = @{
        "EnableFirewall" = "1";
        "DefaultInboundAction" = "1";
        "DefaultOutboundAction" = "0";
        "DisableNotifications" = "1"
    };
    "PublicProfile" = @{
        "EnableFirewall" = "1";
        "DefaultInboundAction" = "1";
        "DefaultOutboundAction" = "0";
        "DisableNotifications" = "1";
        "AllowLocalPolicyMerge" = "0";
        "AllowLocalIPsecPolicyMerge" = "0"
    }
}

foreach ($profile in $firewallProfiles.Keys) {
    foreach ($setting in $firewallProfiles[$profile].Keys) {
        Set-FirewallProfile -Profile $profile -Setting $setting -Value $firewallProfiles[$profile][$setting]
    }
}

gpupdate /force



# Function to set the start type of a service
function Set-ServiceStartType {
    param (
        [string]$ServiceName,
        [int]$StartType
    )
    
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    
    if (Test-Path $servicePath) {
        Set-ItemProperty -Path $servicePath -Name "Start" -Value $StartType
    } else {
        Write-Host "Service $ServiceName not found."
    }
}

# Function to update security policy settings
function Set-SecurityPolicy {
    param (
        [string]$SettingName,
        [string]$SettingValue
    )
    
    $secpolPath = "$env:TEMP\secpol.cfg"
    
    # Export current security policy
    secedit /export /cfg $secpolPath

    # Read and update the security policy
    $content = Get-Content $secpolPath
    $newContent = $content -replace "$SettingName = .*", "$SettingName = $SettingValue"
    Set-Content -Path $secpolPath -Value $newContent

    # Import the updated security policy
    secedit /import /cfg $secpolPath /overwrite
    Remove-Item $secpolPath
}

# Function to update registry settings
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    # Create the property if it doesn't exist
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value
}

# Apply the security policy changes
Set-SecurityPolicy -SettingName "PasswordHistorySize" -SettingValue "24"
Set-SecurityPolicy -SettingName "MaximumPasswordAge" -SettingValue "365"
Set-SecurityPolicy -SettingName "MinimumPasswordAge" -SettingValue "1"
Set-SecurityPolicy -SettingName "MinimumPasswordLength" -SettingValue "14"
Set-SecurityPolicy -SettingName "PasswordComplexity" -SettingValue "1"
Set-SecurityPolicy -SettingName "LockoutBadCount" -SettingValue "5"
Set-SecurityPolicy -SettingName "LockoutDuration" -SettingValue "15"
Set-SecurityPolicy -SettingName "ResetLockoutCount" -SettingValue "15"
Set-SecurityPolicy -SettingName "NetworkSecurityKerberos" -SettingValue "1"
Set-SecurityPolicy -SettingName "NoLMHash" -SettingValue "1"
Set-SecurityPolicy -SettingName "LmCompatibilityLevel" -SettingValue "5"
Set-SecurityPolicy -SettingName "LDAPClientIntegrity" -SettingValue "1"
Set-SecurityPolicy -SettingName "NTLMMinClientSec" -SettingValue "537395200"
Set-SecurityPolicy -SettingName "NTLMMinServerSec" -SettingValue "537395200"
Set-SecurityPolicy -SettingName "CachedLogonsCount" -SettingValue "4"
Set-SecurityPolicy -SettingName "PasswordExpiryWarning" -SettingValue "14"
Set-SecurityPolicy -SettingName "ForceUnlockLogon" -SettingValue "1"
Set-SecurityPolicy -SettingName "ScRemoveOption" -SettingValue "1"
Set-SecurityPolicy -SettingName "AutoDisconnect" -SettingValue "15"
Set-SecurityPolicy -SettingName "RequireSecuritySignature" -SettingValue "1"
Set-SecurityPolicy -SettingName "EnableSecuritySignature" -SettingValue "1"
Set-SecurityPolicy -SettingName "EnableForcedLogOff" -SettingValue "1"
Set-SecurityPolicy -SettingName "SMBServerNameHardeningLevel" -SettingValue "1"
Set-SecurityPolicy -SettingName "LSAAnonymousNameLookup" -SettingValue "0"
Set-SecurityPolicy -SettingName "RestrictAnonymousSAM" -SettingValue "1"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value "1"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value "2147483644"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value "5"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value "537395200"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value "537395200"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name "ForceKeyProtection" -Value "2"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value "1"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "2"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value "0"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "1"
Set-ServiceStartType -ServiceName "Wecsvc" -StartType "4"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value "3"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "Administrator" -Value "0"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "Guest" -Value "0"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value "0"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value "1"



# Allowed to format and eject removable media
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateDASD" -Value "0"

# Prevent users from installing printer drivers
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value "1"



# Interactive logon: Machine account lockout threshold
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Value "10"

# Interactive logon: Machine inactivity limit
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value "900"

# Interactive logon: Message text for users attempting to log on
# Note: Replace 'Your logon message text here' with the message you want to display.
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "Your logon message text here"

# Interactive logon: Message title for users attempting to log on
# Note: Replace 'Your logon message title here' with the title you want to display.
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "Your logon message title here"

# Interactive logon: Number of previous logons to cache
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "4"

# Interactive logon: Smart card removal behavior
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" -Value "1"

# Microsoft network client: Digitally sign communications (always)
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value "1"

# Microsoft network server: Digitally sign communications (always)
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value "1"

# Microsoft network server: Digitally sign communications (if client agrees)
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value "1"



# Turn off multicast name resolution
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value "0"

# Enable Font Providers
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableWindowsConsumerFeatures" -Value "1"

# Disable insecure guest logons
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value "0"

# Turn off Microsoft Peer-to-Peer Networking Services
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value "1"

# Prohibit installation and configuration of Network Bridge
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value "0"

# Disable IPv6
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value "255"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value "0"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value "3"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value "0"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value "4"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value "1"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Value "2"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value "1"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "1"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value "3"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value "1"
# Turn off downloading of print drivers over HTTP
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value "1"

# Turn off handwriting personalization data sharing
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value "1"

# Turn off handwriting recognition error reporting
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value "1"

# Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value "1"

# Turn off Internet download for Web publishing and online ordering wizards
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoWebServices" -Value "1"

# Turn off printing over HTTP
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value "1"

# Turn off Registration if URL connection is referring to Microsoft.com
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -Value "1"

# Turn off Search Companion content file updates
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -Value "1"

# Turn off the "Order Prints" picture task
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoOnlinePrintsWizard" -Value "1"

# Turn off the "Publish to Web" task for files and folders
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPublishingWizard" -Value "1"

# Turn off the Windows Messenger Customer Experience Improvement Program
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value "0"

# Turn off Windows Customer Experience Improvement Program
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value "0"

# Turn off Windows Error Reporting
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "1"

# Enumeration policy for external devices incompatible with Kernel DMA Protection
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value "2"

# Disallow copying of user input methods to the system account for sign-in
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value "1"

# Block user from showing account details on sign-in
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value "1"

# Do not display network selection UI
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value "1"

# Do not enumerate connected users on domain-joined computers
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value "1"

# Turn off app notifications on the lock screen
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value "1"

# Turn off picture password sign-in
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value "1"

# Allow Clipboard synchronization across devices
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value "0"

# Allow upload of User Activities
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value "0"

# Allow network connectivity during connected-standby (on battery)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value "0"

# Allow network connectivity during connected-standby (plugged in)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value "0"




$servicesToDisable = @(
    "BTAGService",      # Bluetooth Audio Gateway Service
    "bthserv",          # Bluetooth Support Service
    "MapsBroker",       # Downloaded Maps Manager
    "lfsvc",            # Geolocation Service
    "SharedAccess",     # Internet Connection Sharing (ICS)
    "lltdsvc",          # Link-Layer Topology Discovery Mapper
    "MSiSCSI",          # Microsoft iSCSI Initiator Service
    "PNRPsvc",          # Peer Name Resolution Protocol
    "p2psvc",           # Peer Networking Grouping
    "p2pimsvc",         # Peer Networking Identity Manager
    "PNRPAutoReg",      # PNRP Machine Name Publication Service
    "Spooler",          # Print Spooler
    "wercplsupport",    # Problem Reports and Solutions Control Panel Support
    "RasAuto",          # Remote Access Auto Connection Manager
    "SessionEnv",       # Remote Desktop Configuration
    "TermService",      # Remote Desktop Services
    "UmRdpService",     # Remote Desktop Services UserMode Port Redirector
    "RpcLocator",       # Remote Procedure Call (RPC) Locator
    "RemoteRegistry",   # Remote Registry
    "RemoteAccess",     # Routing and Remote Access
    "LanmanServer"
)
foreach ($service in $servicesToDisable) {
    Set-ServiceStartType -ServiceName $service -StartType 4
}

gpupdate /force
