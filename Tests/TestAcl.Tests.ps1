
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

    It 'Works with strings' {
        'Allow Everyone Modify to Object, ChildContainers, and ChildObjects' | ConvertToAce | Should Be $ReferenceAccessAce
        'Everyone Modify' | ConvertToAce | Should Be $ReferenceAccessAce
        'Everyone Modify Folder, SubFolders, Files' | ConvertToAce | Should Be $ReferenceAccessAce
        'Allow *S Modify' | ConvertToAce | Should Be $ReferenceAccessAce
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
            Get-Item C:\Windows | Test-Acl -RequiredAces [FileSystemAccessRule]::new('CREATOR OWNER', 268435456, 'ObjectInherit, ContainerInherit', 'InheritOnly', 'Allow'), [FileSystemAccessRule]::new('Users', 'ReadAndExecute', 'None', 'None', 'Allow') | Should Be $true
        }
    }
}