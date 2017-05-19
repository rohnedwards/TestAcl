
$Module = Import-Module $PSScriptRoot\..\TestAcl.psm1 -PassThru -Force

InModuleScope $Module.Name {
    Describe 'ConvertToAce' {
        It 'Should Write Error and Ignore Invalid AccessMasks when AccessRightType Specified' {
            $ConvertedAces = '
                Administrators Modify # This should be ignored b/c it''s not a valid RegistryRights enumv alue
                Administrators RegistryRights: FullControl
                Users RegistryRights: ReadKey
            ' | ConvertToAce -AccessRightType System.Security.AccessControl.RegistryRights -ErrorVariable ctaErr -ErrorAction SilentlyContinue

            $ConvertedAces.Count | Should Be 2
            $ctaErr.Count | Should Be 1

            $ConvertedAces = '
                Administrators FileSystemRights: Modify # This is OK, though, because we override at a lower level than the -AccessRightType
                Administrators RegistryRights: FullControl
                Users RegistryRights: ReadKey
            ' | ConvertToAce -AccessRightType System.Security.AccessControl.RegistryRights -ErrorVariable ctaErr -ErrorAction SilentlyContinue

            $ConvertedAces.Count | Should Be 3
            $ctaErr.Count | Should Be 0
        }

        It 'Assigns proper default inheritance flags' {
            $Aces = '
                Administrators ReadAndExecute
                Administrators RegistryRights: ReadKey
                Administrators ActiveDirectoryRights: GenericAll
            ' | ConvertToAce

            $Aces[0].InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
            $Aces[1..2].InheritanceFlags | Should Be 'ContainerInherit'
        }

        It 'Allows inheritance flags to be overridden' {
            $Aces = '
                Administrators ReadAndExecute O
                Administrators RegistryRights: ReadKey O
                Administrators ActiveDirectoryRights: GenericAll O
            ' | ConvertToAce

            $Aces[0..2].InheritanceFlags | Should Be 'None'

            $Aces = '
                Administrators ReadAndExecute CC, CO
                Administrators RegistryRights: ReadKey CC, CO
                Administrators ActiveDirectoryRights: GenericAll CC, CO
            ' | ConvertToAce

            $Aces[0..2].InheritanceFlags | Should Be 'ContainerInherit, ObjectInherit'
            $Aces[0..2].PropagationFlags | Should Be 'InheritOnly'
        }
    }
}