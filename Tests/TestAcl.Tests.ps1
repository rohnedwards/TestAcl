
$Module = Import-Module $PSScriptRoot\..\TestAcl.psm1 -PassThru

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
    It 'Works with -RequiredAces CommonAce[]' {
        Mock -ModuleName $Module.Name NewCommonSecurityDescriptor {
            return New-Object System.Security.AccessControl.CommonSecurityDescriptor (
                $true, 
                $false,
                'O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)'
            )
        }

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
}