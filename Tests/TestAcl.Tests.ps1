
$Module = Import-Module $PSScriptRoot\..\TestAcl.psm1 -PassThru

Describe 'Convert ACEs' {

    $ReferenceAccessAce = [System.Security.AccessControl.CommonAce]::new(
        'ObjectInherit, ContainerInherit',
        [System.Security.AccessControl.AceQualifier]::AccessAllowed,
        [System.Security.AccessControl.FileSystemRights] 'Modify, Synchronize',
        ([System.Security.Principal.NTAccount] 'Everyone').Translate([System.Security.Principal.SecurityIdentifier]),
        $false,
        $null
    )

    Context 'String -> File Allow ACE [Allow Everyone Read, Write, Delete AppliesTo Folder, SubFolders, and Files]'  {
        $Params = @{
            TestCases = @{ String = 'Allow Everyone Read and Write and Delete to Object, ChildContainers, and ChildObjects' },
                @{String = 'Everyone Read, Write, Delete' },
                @{String = 'Everyone Read, Write, and Delete appliesto ThisFolder, SubFolders, Files' },
                @{String = 'Allow *S-1-1-0 1245599' },
                @{String = 'S-1-1-0 Read and Write, Delete applies to SubFolders, ChildObjects, Object, ThisFolder'  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'ObjectInherit, ContainerInherit',
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                    [System.Security.AccessControl.FileSystemRights] 'Read, Write, Delete, Synchronize',
                    ([System.Security.Principal.NTAccount] 'Everyone').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }

    Context 'String -> File Allow ACE [Allow ''Network Service'' Read AppliesTo SubFolders, and Files]'  {
        $Params = @{
            TestCases = @{ String = 'Allow ''Network Service'' Read to ChildContainers, and ChildObjects' },
                @{String = '"Network Service" Read CC, CO' },
                @{String = 'Network` Service Read appliesto SubFolders and Files' },
                @{String = 'Allow *S-1-5-20 Read ChildContainers, Files, Files' },
                @{String = 'S-1-5-20 Read applies to SubFolders, ChildObjects'  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'ObjectInherit, ContainerInherit, InheritOnly',
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                    [System.Security.AccessControl.FileSystemRights] 'Read, Synchronize',
                    ([System.Security.Principal.NTAccount] 'Network Service').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }

    Context 'String -> File Allow ACE [Allow ''Network Service'' Read AppliesTo Object]'  {
        $Params = @{
            TestCases = @{ String = 'Allow ''Network Service'' Read to Object' },
                @{String = '"Network Service" Read O' },
                @{String = 'Network` Service Read appliesto ThisFolder' },
                @{String = 'Allow *S-1-5-20 Read ThisFile' },
                @{String = 'S-1-5-20 Read applies to Object'  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'None',
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                    [System.Security.AccessControl.FileSystemRights] 'Read, Synchronize',
                    ([System.Security.Principal.NTAccount] 'Network Service').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }

    Context 'String -> File Deny ACE [Deny Everyone Read, Write, Delete AppliesTo Folder, SubFolders, and Files]'  {
        $Params = @{
            TestCases = @{ String = 'Deny Everyone Read and Write and Delete to Object, ChildContainers, and ChildObjects' },
                @{String = 'Deny Everyone Read, Write, Delete' },
                @{String = 'Deny Everyone Read, Write, and Delete appliesto ThisFolder, SubFolders, Files' },
                @{String = 'Deny *S-1-1-0 Read, Write, Delete' },
                @{String = 'Deny S-1-1-0 Read and Write, Delete applies to SubFolders, ChildObjects, Object, ThisFolder'  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'ObjectInherit, ContainerInherit',
                    [System.Security.AccessControl.AceQualifier]::AccessDenied,
                    [System.Security.AccessControl.FileSystemRights] 'Read, Write, Delete',
                    ([System.Security.Principal.NTAccount] 'Everyone').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }
    Context 'String -> File Audit ACE [Audit Success Everyone Read, Write, Delete AppliesTo SubFolders and Files]'  {

        $Params = @{
            TestCases = @{ String = 'Audit Success Everyone Read and Write and Delete to ChildContainers and ChildObjects' },
                @{String = 'Audit S Everyone FileSystemRights:Read, Write, Delete CC, CO' },
                @{String = 'Audit S *S-1-1-0 Read, Write, Delete SubFolders and Files' },
                @{String = 'Audit S S-1-1-0 Read and Write, Delete applies to SubFolders, ChildObjects '  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'ObjectInherit, ContainerInherit, InheritOnly, SuccessfulAccess',
                    [System.Security.AccessControl.AceQualifier]::SystemAudit,
                    [System.Security.AccessControl.FileSystemRights] 'Read, Write, Delete',
                    ([System.Security.Principal.NTAccount] 'Everyone').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }

    Context 'String -> Registry Audit ACE [Audit Failure Everyone RegistryRights: ReadKey Write, Delete AppliesTo SubKeys]'  {

        $Params = @{
            TestCases = @{ String = 'Audit Failure Everyone ReadKey ChildContainers' },
                @{ String = 'Audit Failure Everyone RegistryRights:ReadKey ChildContainers' },
                @{ String = 'Audit Failure Everyone RegistryRights: ReadKey ChildContainers' },
                @{String = 'Audit F Everyone ReadKey CC' },
                @{String = 'Audit f *S-1-1-0 131097 SubKeys' },
                @{String = 'Audit F S-1-1-0 ReadKey applies to SubKeys'  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'ContainerInherit, InheritOnly, FailedAccess',
                    [System.Security.AccessControl.AceQualifier]::SystemAudit,
                    [System.Security.AccessControl.RegistryRights] 'ReadKey',
                    ([System.Security.Principal.NTAccount] 'Everyone').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }
    Context 'String -> File Audit ACE [Audit Success and Failure Everyone RegistryRights: ReadKey Write, Delete AppliesTo SubKeys]'  {

        $Params = @{
            TestCases = @{ String = 'Audit Success,Failure Everyone ReadKey ChildContainers' },
                @{String = 'Audit SF Everyone ReadKey CC' },
                @{String = 'Audit FS *S-1-1-0 131097 SubKeys' },
                @{String = 'Audit Success and Failure S-1-1-0 ReadKey applies to SubKeys'  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'ContainerInherit, InheritOnly, FailedAccess, SuccessfulAccess',
                    [System.Security.AccessControl.AceQualifier]::SystemAudit,
                    [System.Security.AccessControl.RegistryRights] 'ReadKey',
                    ([System.Security.Principal.NTAccount] 'Everyone').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }
    Context 'FileSystemRights handle Synchronize properly' {
        $TestCases = foreach ($AceType in 'Allow', 'Deny', 'Audit') {
            foreach ($Right in ([System.Security.AccessControl.FileSystemRights] | Get-Member -Static -MemberType Property | select -ExpandProperty Name)) {
                if ($AceType -eq 'Deny') {
                    if ($Right -eq 'Synchronize') { continue }
                    $Right += ', Synchronize'
                }
                @{
                    AceType = $AceType
                    FileSystemRight = $Right
                }                
            }
        }
        It '<AceType> Everyone <FileSystemRight>' -TestCases $TestCases -test {
            param(
                [string] $AceType,
                [System.Security.AccessControl.FileSystemRights] $FileSystemRight
            )

            if ($AceType -in 'Allow', 'Deny') {
                "${AceType} Everyone ${FileSystemRight}" | ConvertToAce | Should Be ([System.Security.AccessControl.FileSystemAccessRule]::new(
                    'Everyone',
                    $FileSystemRight,
                    'ObjectInherit, ContainerInherit',
                    'None',
                    $AceType
                ) | ConvertToAce)
            }
            elseif ($AceType -eq 'Audit') {
                "${AceType} S Everyone ${FileSystemRight}" | ConvertToAce | Should Be ([System.Security.AccessControl.FileSystemAuditRule]::new(
                    'Everyone',
                    $FileSystemRight,
                    'ObjectInherit, ContainerInherit',
                    'None',
                    'Success'
                ) | ConvertToAce)
            }
            else {
                throw "Unknown AceType"
            }
        }
    }
    It 'Can take multi-line string' {
        $Aces = '
             "NT SERVICE\TrustedInstaller" FullControl Object
             Users ReadAndExecute, Synchronize Object   # This Synchronize shouldnt be necessary
        ' | ConvertToAce -ErrorAction Stop 
        $Aces.Count | Should Be 2
    }

    It 'ReadAndExecute works (because it has ''and'' in it)' {
        'Audit Success and Failure Everyone ReadAndExecute' | ConvertToAce | Should Be ([System.Security.AccessControl.FileSystemAuditRule]::new('Everyone', 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Success, Failure') | ConvertToAce)
    }
    
    It 'Quoted principal works as first token ["Everyone" ReadAndExecute, Synchronize]' {
        '"Everyone" ReadAndExecute, Synchronize' | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
            'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.AceQualifier]::AccessAllowed,
            [System.Security.AccessControl.FileSystemRights] 'ReadAndExecute, Synchronize',
            'S-1-1-0',
            $false,
            $null
        ))
    }
    
    It 'Works with FileSystemAccessRule' {
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            'Everyone',
            'Modify',
            'ObjectInherit, ContainerInherit',
            'None',
            'Allow'
        ) | ConvertToAce | Should Be $ReferenceAccessAce
    }

    It 'Can specify enumeration, which also changes default inheritance flags' {
        'Audit F Everyone RegistryRights:FullControl' | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
            'FailedAccess, ContainerInherit',
            [System.Security.AccessControl.AceQualifier]::SystemAudit,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            'S-1-1-0',
            $false,
            $null
        ))
        'Audit F Everyone ActiveDirectoryRights:GenericAll' | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
            'FailedAccess, ContainerInherit',
            [System.Security.AccessControl.AceQualifier]::SystemAudit,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            'S-1-1-0',
            $false,
            $null
        ))
    }

    It 'ALL APPLICATION PACKAGES can be translated' {
        <#
        # The fully qualified name including 'APPLICATION PACKAGE AUTHORITY' fails the .NET SID translation. Had
        # to make a helper function just for this guy (and maybe more in the future). Here's a demo of the failure:
        # Fails
        [System.Security.Principal.NTAccount] 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES' | % Translate ([System.Security.Principal.SecurityIdentifier])

        # Works:
        [System.Security.Principal.NTAccount] 'ALL APPLICATION PACKAGES' | % Translate ([System.Security.Principal.SecurityIdentifier])  

        # Notice the reverse direction:
        [System.Security.Principal.SecurityIdentifier] 'S-1-15-2-1' | % Translate ([System.Security.Principal.NTAccount])
        #>
        'Audit S "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" ReadKey' | ConvertToAce | Should Be (([System.Security.AccessControl.RegistryAuditRule]::new(
            'ALL APPLICATION PACKAGES',
            'ReadKey',
            'ObjectInherit, ContainerInherit',
            'None',
            'Success'
        )) | ConvertToAce)
    }

    It 'Wildcard Principals Allowed' {
        $WildcardAce = 'Allow * ReadAndExecute' | ConvertToAce
        $WildcardAce.__WildcardString | Should Be '*'
        $WildcardAce.AccessMask | Should Be 1179817

    }
    
    It 'Multiple Principals Allowed (Single string)' {
        $Aces = 'Everyone, Users, Administrators FullControl Object' | ConvertToAce
        $Aces.Count | Should Be 3
        $Grouped = @($Aces | Group-Object AceQualifier, AccessMask, AceType, InheritanceFlags, PropagationFlags)
        $Grouped.Count | Should Be 1
        $Sids = $Grouped.Group | Select-Object -ExpandProperty SecurityIdentifier | ForEach-Object ToString
        Compare-Object $Sids 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-32-544' | Should BeNullOrEmpty
    }
    
    It 'Multiple Principals Allowed (Multi-line string)' {
        $Aces = '
            Deny Users, Everyone Modify
            Allow Everyone, Users, Administrators FullControl Object
            Allow Guests Read
        ' | ConvertToAce
        $Aces.Count | Should Be 6
        $Grouped = $Aces | Group-Object AceQualifier, AccessMask, AceType, InheritanceFlags, PropagationFlags
        $Grouped.Count | Should Be 3
        $Sids = $Grouped.Group | Select-Object -ExpandProperty SecurityIdentifier | ForEach-Object ToString
        Compare-Object $Sids 'S-1-1-0', 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-32-545', 'S-1-5-32-544', 'S-1-5-32-546' | Should BeNullOrEmpty
    }

    Context 'Test invalid strings' {
        It 'Invalid string: <string>' -TestCases @{ String = 'Audit Everyone Modify' }, 
            @{ String = 'potato' }, 
            @{ String = 'Allow Everyone Modify What are those?'},
            @{ String = 'Allow RegistryRights: RegistryRights: FullControl'},
            @{ String = 'Dney * Write'} -test {
            param([string] $String)        

            { $String | ConvertToAce -ErrorAction Stop } | Should Throw
        }
    }
}

Describe 'Test-Acl' {
    
    Context 'Different Valid Inputs' {
        
        It 'DirectoryInfo: Get-Item C:\Windows' {
            Get-Item C:\Windows | Test-Acl | Should Be $true
        }
        It 'String: C:\Windows' {
            'C:\Windows' | Test-Acl | Should Be $true
            Test-Acl C:\Windows | Should Be $true
        }
        It 'FileInfo: Get-ChildItem (First file in C:\Windows)' {
            Get-ChildItem C:\Windows -File | Select-Object -First 1 | Test-Acl | Should Be $true
        }
        It 'String: (First file in C:\Windows)' {
            $FileInfo = Get-ChildItem C:\Windows -File | Select-Object -First 1
            $FileInfo.FullName | Test-Acl | Should Be $true
            Test-Acl $FileInfo.FullName | Should Be $true
        }
        It 'RegistryKey: Get-Item HKLM:\SOFTWARE' {
            Get-Item HKLM:\SOFTWARE | Test-Acl | Should Be $true
        }
        It 'String: HKLM:\SOFTWARE' {
            'HKLM:\SOFTWARE' | Test-Acl | Should Be $true
            Test-Acl HKLM:\SOFTWARE | Should Be $true
        }
        It 'Works with FileInfo and DirectoryInfo objects' {
            { Get-Item C:\Windows | Test-Acl -ErrorAction Stop } | Should Not Throw
        }
    }

    Context 'Inheritance and object flags on SDs that don''t support them' {
        It '-RequiredAces works with inheritance flags set on ACEs when SD doesn''t support containers' {
            $SD = New-Object System.Security.AccessControl.FileSecurity
            $SD.SetSecurityDescriptorSddlForm('D:AI(A;;FA;;;BA)(A;ID;FA;;;SY)')

            # RequiredAces tries to add ACEs, and if a SD doesn't support inheritance flags, they need to
            # be removed. We don't want a user of the function to have to deal with that, though, so we'll
            # have the helper functions do it internally
            {
                $SD | Test-Acl -RequiredAces '
                    Allow Administrators, SYSTEM FullControl
                ' -ErrorAction Stop
            } | Should Not Throw
        }
        It '-RequiredAces works with object flags set on ACEs when SD doesn''t support them' {
            $SD = New-Object System.Security.AccessControl.FileSecurity
            $SD.SetSecurityDescriptorSddlForm('D:AI(A;;FA;;;BA)(A;ID;FA;;;SY)')

            # RequiredAces tries to add ACEs, and if a SD doesn't support inheritance flags, they need to
            # be removed. We don't want a user of the function to have to deal with that, though, so we'll
            # have the helper functions do it internally
            {
                $SD | Test-Acl -RequiredAces "
                    Allow Administrators, SYSTEM FullControl $([guid]::Empty),$([guid]::Empty)
                " -ErrorAction Stop
            } | Should Not Throw
        }
    }

    Context '-AllowedAces' {
        $SD = Get-Acl C:\Windows
        It 'Passes with SD is played back' {
            Get-Item C:\Windows | Test-Acl -AllowedAces $SD.Access | Should Be $true
        }

        It 'Fails with SD -1 is played back' {
            Get-Item C:\Windows | Test-Acl -AllowedAces ($SD.Access | select -skip 1) |  Should Be $false
        }
    }
    Context '-RequiredAces' {
        It 'RequiredTest' {
            Get-Item C:\Windows | Test-Acl -RequiredAces '
                "NT SERVICE\TrustedInstaller" FullControl Object
                Users ReadAndExecute, Synchronize Object   # This Synchronize shouldnt be necessary
            '
        }
    }

    Context 'GenericRights on DirectorySecurity' {
        $SD = New-Object System.Security.AccessControl.DirectorySecurity
        $SD.SetSecurityDescriptorSddlForm('O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)')
        
        It '-AllowedAces (Synchronize Right Manually Specified)' {
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER' FullControl
                SYSTEM FullControl
                Administrators FullControl
                Users ReadAndExecute, Synchronize
                'NT Service\TrustedInstaller' FullControl
                'ALL APPLICATION PACKAGES' ReadAndExecute, Synchronize
                'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute, Synchronize
            " | Should Be $true
        }
        It '-AllowedAces (Synchronize Right Manually Specified; Multiple principals defined)' {
            $SD | Test-Acl -AllowedAces "
                Allow 'CREATOR OWNER', SYSTEM, Administrators, 'NT Service\TrustedInstaller' FullControl
                Allow Users, 'ALL APPLICATION PACKAGES', 'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute, Synchronize
            " | Should Be $true
        }
        It '-AllowedAces (Synchronize Right Manually Specified; Multiple principals defined w/o AceType)' {
            # Used to have an issue w/ first token being an array
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER', SYSTEM, Administrators, 'NT Service\TrustedInstaller' FullControl
                Users, 'ALL APPLICATION PACKAGES', 'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute, Synchronize
            " | Should Be $true
        }
        It '-AllowedAces (with wildcards, multiple principals, and no Synchronize right)' {
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER', SYSTEM, Administrators, 'NT Service\TrustedInstaller' FullControl
                Allow * ReadAndExecute
            " | Should Be $true
        }
        It '-AllowedAces (Synchronize Right not Specified)' {
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER' FullControl
                SYSTEM FullControl
                Administrators FullControl
                Users ReadAndExecute
                'NT Service\TrustedInstaller' FullControl
                'ALL APPLICATION PACKAGES' ReadAndExecute
                'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute
            " | Should Be $true
        }
        It '-AllowedAces with wildcard (Synchronize Right not Specified)' {
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER' FullControl
                SYSTEM FullControl
                Administrators FullControl
                'NT Service\TrustedInstaller' FullControl
                Allow * ReadAndExecute
            " | Should Be $true
        }
        It '-AllowedAces (Synchronize Right Manually Specified) fails when expected' {
            $Result = $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER' FullControl O, CC
                SYSTEM FullControl
                Administrators FullControl
                Users ReadAndExecute, Synchronize
                'NT Service\TrustedInstaller' FullControl
                'ALL APPLICATION PACKAGES' ReadAndExecute, Synchronize
                'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute, Synchronize
            " -Detailed

            $Result.Result | Should Be $false
            $Result.ExtraAces | Should Be ([System.Security.AccessControl.CommonAce]::new(
                'ObjectInherit, InheritOnly',
                'AllowedAccess',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                'S-1-3-0',
                $false,
                $null
            ))
        }
        It '-AllowedAces (GenericRights not translated with -NoGenericRightsTranslation switch)' {
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER' FullControl
                SYSTEM FullControl
                Administrators FullControl
                Users ReadAndExecute, Synchronize
                'NT Service\TrustedInstaller' FullControl
                'ALL APPLICATION PACKAGES' ReadAndExecute, Synchronize
                'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute, Synchronize
            " -NoGenericRightsTranslation | Should Be $false
        }
        It '-AllowedAces (GenericRights not translated with -NoGenericRightsTranslation switch; GenericRights in ACEs pass)' {
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER' 268435456
                SYSTEM 268435456
                SYSTEM FullControl
                Administrators FullControl
                Administrators 268435456
                Users ReadAndExecute, Synchronize
                Users -1610612736
                'NT Service\TrustedInstaller' FullControl
                'NT Service\TrustedInstaller' 268435456
                'ALL APPLICATION PACKAGES' ReadAndExecute, Synchronize
                'ALL APPLICATION PACKAGES' -1610612736
                'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute, Synchronize
                'ALL RESTRICTED APPLICATION PACKAGES' -1610612736
            " -NoGenericRightsTranslation | Should Be $true
        }
        It '-AllowedAces (GenericRights not translated with -NoGenericRightsTranslation switch; very permissive access masks pass)' {
            $SD | Test-Acl -AllowedAces "
                'CREATOR OWNER' $([int]::MaxValue)  # This wouldn't remove GenericRead
                SYSTEM 0xffffffff
                Administrators 0xffffffff
                Users ReadAndExecute, Synchronize
                Users -1610612736
                'NT Service\TrustedInstaller' FullControl
                'NT Service\TrustedInstaller' 268435456
                'ALL APPLICATION PACKAGES' ReadAndExecute, Synchronize
                'ALL APPLICATION PACKAGES' -1610612736
                'ALL RESTRICTED APPLICATION PACKAGES' ReadAndExecute, Synchronize
                'ALL RESTRICTED APPLICATION PACKAGES' -1610612736
            " -NoGenericRightsTranslation | Should Be $true
        }
    }

    It 'Works with -RequiredAces FileSystemAccessRule[]' {
        $ReqAces = [System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM', 'Modify', 'ObjectInherit, ContainerInherit', 'InheritOnly', 'Allow'), 
                    [System.Security.AccessControl.FileSystemAccessRule]::new('Users', 'ReadAndExecute', 'None', 'None', 'Allow')
        Get-Item C:\Windows | Test-Acl -RequiredAces $ReqAces | Should Be $true
    }
}