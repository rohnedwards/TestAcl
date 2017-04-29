
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

    Context 'String -> Allow ACE [Allow Everyone Read, Write, Delete AppliesTo Folder, SubFolders, and Files]'  {
        $Params = @{
            TestCases = @{ String = 'Allow Everyone Read and Write and Delete to Object, ChildContainers, and ChildObjects' },
                @{String = 'Everyone Read, Write, Delete' },
                @{String = 'Everyone Read, Write, and Delete appliesto ThisFolder, SubFolders, Files' },
                @{String = 'Allow *S-1-1-0 Read, Write, Delete' },
                @{String = 'S-1-1-0 Read and Write, Delete applies to SubFolders, ChildObjects, Object, ThisFolder'  }
            Test = {
                param(
                    [string] $String
                )
                $String | ConvertToAce | Should Be ([System.Security.AccessControl.CommonAce]::new(
                    'ObjectInherit, ContainerInherit',
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                    [System.Security.AccessControl.FileSystemRights] 'Read, Write, Delete',
                    ([System.Security.Principal.NTAccount] 'Everyone').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }

    Context 'String -> Allow ACE [Allow ''Network Service'' Read AppliesTo SubFolders, and Files]'  {
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
                    [System.Security.AccessControl.FileSystemRights] 'Read',
                    ([System.Security.Principal.NTAccount] 'Network Service').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }

    Context 'String -> Allow ACE [Allow ''Network Service'' Read AppliesTo Object]'  {
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
                    [System.Security.AccessControl.FileSystemRights] 'Read',
                    ([System.Security.Principal.NTAccount] 'Network Service').Translate([System.Security.Principal.SecurityIdentifier]),
                    $false,
                    $null
                ))
            }
        }
        It '<string>' @Params
    }
    Context 'String -> Deny ACE [Deny Everyone Read, Write, Delete AppliesTo Folder, SubFolders, and Files]'  {
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

    It 'Can take multi-line string' {
        {
        '
             "NT SERVICE\TrustedInstaller" FullControl Object
             Users ReadAndExecute, Synchronize Object   # This Synchronize shouldnt be necessary
        ' | ConvertToAce -ErrorAction Stop -Verbose
        } | Should Not Throw
    }

    It 'ReadAndExecute works (because it has ''and'' in it)' {
        'Audit Success and Failure Everyone ReadAndExecute' | ConvertToAce | Should Be ([System.Security.AccessControl.FileSystemAuditRule]::new('Everyone', 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Success, Failure') | ConvertToAce)
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
}

Describe 'Test-Acl' {
    
    It 'Works with FileInfo and DirectoryInfo objects' {
        { Get-Item C:\Windows | Test-Acl -ErrorAction Stop } | Should Not Throw
    }
    It 'RequiredTest' {
        Get-Item C:\Windows | Test-Acl -RequiredAces '
             "NT SERVICE\TrustedInstaller" FullControl Object
             Users ReadAndExecute, Synchronize Object   # This Synchronize shouldnt be necessary
        '
    }
    It 'Works with RegistryKey objects' {
        { Get-Item HKLM:\SOFTWARE | Test-Acl -ErrorAction Stop } | Should Not Throw
    }
    It 'Passes with No ACE collections' {
        Get-Item C:\Windows | Test-Acl | Should Be $true
    }

    Context 'Fake out C:\Windows' {

        Mock -ModuleName $Module.Name NewCommonSecurityDescriptor {
            return New-Object System.Security.AccessControl.CommonSecurityDescriptor (
                $true, 
                $false,
                'O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)'
            )
        }

        It 'Works with -RequiredAces CommonAce[]' {

            $AceThatExists = [System.Security.AccessControl.CommonAce]::new(
                'ObjectInherit, ContainerInherit, InheritOnly', # AceFlags
                'AccessAllowed', # AceQualifier
                268435456, # AccessMask
                'S-1-3-0', # SID
                $false, # IsCallback
                $null   # Opaque
            )
            $AceThatDoesntExist = [System.Security.AccessControl.CommonAce]::new(
                'ObjectInherit',
                'AccessDenied',
                1,
                'S-1-3-0',
                $false,
                $null
            )

            Get-Item C:\Windows | Test-Acl -RequiredAces $AceThatExists | Should Be $true
            Get-Item C:\Windows | Test-Acl -RequiredAces $AceThatExists, $AceThatDoesntExist | Should Be $false
        }

        It 'Works with -RequiredAces FileSystemAccessRule[]' {
            # THIS ISN'T WORKING RIGHT NOW. LOOKS LIKE THE MOCKING IS MESSING WITH THE CALL TO TEST-ACL AND THE TRANSFORM ON COMMONACE
            $ReqAces = [System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM', 'Modify', 'ObjectInherit, ContainerInherit', 'InheritOnly', 'Allow'), 
                       [System.Security.AccessControl.FileSystemAccessRule]::new('Users', 'ReadAndExecute', 'None', 'None', 'Allow')
            Get-Item C:\Windows | Test-Acl -RequiredAces $ReqAces | Should Be $true
        }
    }
    It 'Works with -RequiredAces FileSystemAccessRule[]' {
        # THIS ISN'T WORKING RIGHT NOW. LOOKS LIKE THE MOCKING IS MESSING WITH THE CALL TO TEST-ACL AND THE TRANSFORM ON COMMONACE
        $ReqAces = [System.Security.AccessControl.FileSystemAccessRule]::new('SYSTEM', 'Modify', 'ObjectInherit, ContainerInherit', 'InheritOnly', 'Allow'), 
                    [System.Security.AccessControl.FileSystemAccessRule]::new('Users', 'ReadAndExecute', 'None', 'None', 'Allow')
        Get-Item C:\Windows | Test-Acl -RequiredAces $ReqAces | Should Be $true
    }
}