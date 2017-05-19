
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
        }
    }
}