
$Module = Import-Module $PSScriptRoot\..\TestAcl.psm1 -PassThru -Force

InModuleScope $Module.Name {

    Describe 'FindAce (DS Object SD)' {
        $ObjectSddl = 'S:AI(OU;CIIDSA;WPWD;;f30e3bc2-9ff0-11d1-b603-0000f80367c1;WD)(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)'
        $ObjectSD = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $ObjectSD.SetSecurityDescriptorSddlForm($ObjectSddl)
        $SD = $ObjectSD | NewCommonSecurityDescriptor


        $MissingAce = 'Audit F Everyone GenericAll 00000000-0000-0000-0000-000000000000, f30e3bc2-9ff0-11d1-b603-0000f80367c1' | ConvertToAce
        $PresentAce = 'Audit S Everyone WriteProperty, WriteDacl 00000000-0000-0000-0000-000000000000, f30e3bc2-9ff0-11d1-b603-0000f80367c1' | ConvertToAce
        $PresentAceExceptForAutitFlag = 'Audit F Everyone WriteProperty, WriteDacl 00000000-0000-0000-0000-000000000000, f30e3bc2-9ff0-11d1-b603-0000f80367c1' | ConvertToAce
        $PresentAceExtraAuditFlag = 'Audit SF Everyone WriteProperty, WriteDacl 00000000-0000-0000-0000-000000000000, f30e3bc2-9ff0-11d1-b603-0000f80367c1' | ConvertToAce
                        
        It 'Finds present object audit ACEs' {
            $SD | FindAce $PresentAce | Should Not BeNullOrEmpty
            $SD | FindAce $PresentAce -RequiredAccess | Should Not BeNullOrEmpty
            $SD | FindAce $PresentAce -ExactMatch | Should Not BeNullOrEmpty
        }

        It 'Doesn''t find missing object audit ACEs' {
            $SD | FindAce $MissingAce | Should BeNullOrEmpty
        }

        It 'Doesn''t find ACE that''s present except for wrong audit flag' {
            $SD | FindAce $PresentAceExceptForAutitFlag | Should BeNullOrEmpty
        }

        It 'Finds matching ACE with overlapping audit flags when -RequiredAccess and -ExactMatch aren''t used' {
            $SD | FindAce $PresentAceExtraAuditFlag | Should Not BeNullOrEmpty
        }

        It 'Doesn''t find matching ACE with overlapping audit flags when -RequiredAccess or -ExactMatch are used' {
            $SD | FindAce $PresentAceExtraAuditFlag -RequiredAccess | Should BeNullOrEmpty
            $SD | FindAce $PresentAceExtraAuditFlag -ExactMatch | Should BeNullOrEmpty
        }

    }

    Describe 'Minimal ObjectAce RemoveAccess() not working POC' {

        It 'Should Remove ACE whose ObjectAceType and InheritedObjectAceType guids match perfectly, even when an empty GUID ACE also exists (only ObjectType empty)' {

            $ObjectSddl = "D:AI(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)"
            $ObjectSD = [System.DirectoryServices.ActiveDirectorySecurity]::new()
            $ObjectSD.SetSecurityDescriptorSddlForm($ObjectSddl)

            $Result = $ObjectSD | Test-Acl -AllowedAccess "
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, bf967aba-0de6-11d0-a285-00aa003049e2
            " -Detailed 
            $Result.ExtraAces.Count | Should Be 1

            $Result = $ObjectSD | Test-Acl -AllowedAccess "
                Allow Everyone GenericRead O, CC 00000000-0000-0000-0000-000000000000, 4828cc14-1437-45bc-9b07-ad6f015e5f28
            " -Detailed

        }
        
        It 'Should Remove ACE whose ObjectAceType and InheritedObjectAceType guids match perfectly, even when an empty GUID ACE also exists (both ObjectType and InheritedObjectType empty)' {
            <#
here's what I think's happening:
1. RemoveAccess() sees the GenericRead ACE that applies to all objects (empty GUID), and for some reason it's short circuiting out and stopping. I don't know if it's by design since removing the actual ACEs I was hoping to remove in the examples wouldn't remove the effective access, so it just doesn't bother, or if it's a bug. It can probably be fixed by separating all ObjectType ACEs into one ACL...
            #>

            # What if we give the empty GUID a random GUID?
            $ObjectSddl = "D:AI(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;LCRPLORC;;;WD)"
            $ObjectSD = [System.DirectoryServices.ActiveDirectorySecurity]::new()
            $ObjectSD.SetSecurityDescriptorSddlForm($ObjectSddl)

            $Result = $ObjectSD | Test-Acl -AllowedAccess "
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, bf967aba-0de6-11d0-a285-00aa003049e2
            " -Detailed 
            $Result.ExtraAces.Count | Should Be 1

        }

        It 'Should Remove ACE whose ObjectAceType and InheritedObjectAceType guids match perfectly, even when an empty GUID ACE also exists (only InheritedObjectType empty)' {

            # What if we give the empty GUID a random GUID?
            $ObjectSddl = "D:AI(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;LCRPLORC;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;WD)"
            $ObjectSD = [System.DirectoryServices.ActiveDirectorySecurity]::new()
            $ObjectSD.SetSecurityDescriptorSddlForm($ObjectSddl)

            $Result = $ObjectSD | Test-Acl -AllowedAccess "
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, bf967aba-0de6-11d0-a285-00aa003049e2
            " -Detailed 
            $Result.ExtraAces.Count | Should Be 1

        }
    }

    Describe 'Test-Acl with Object ACEs' {
        $ObjectSddl = 'D:AI(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;WD)'
        $ObjectSddl = 'D:AI(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)'
        $ObjectSddl = "D:AI(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;WD)"

        # This one just has the ReadProperty w/ GUIDs (this one, it seems to actually pull the ACEs properly)
        $ObjectSddl = "D:AI(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;WD)"

        # ReadProperty w/ GUIDs with one non-GUID one:
        $ObjectSddl = "D:AI(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;WD)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;WD)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;WD)"
        $ObjectSD = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $ObjectSD.SetSecurityDescriptorSddlForm($ObjectSddl)

        $ConvertedObjectSD = $ObjectSD | NewCommonSecurityDescriptor
        $NewObjectSD = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $NewObjectSD.SetSecurityDescriptorSddlForm($ConvertedObjectSD.GetSddlForm('all'))


        It 'Should find present object ACEs' {
            $ObjectSD | Test-Acl -AllowedAccess "
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, bf967aba-0de6-11d0-a285-00aa003049e2
            " -Detailed | select -expand ExtraAces | Measure-Object | Select-Object -ExpandProperty Count | Should Be 1
            #     Allow Everyone GenericRead O, CC 00000000-0000-0000-0000-000000000000, 4828cc14-1437-45bc-9b07-ad6f015e5f28
            #     Allow Everyone GenericRead O, CC 00000000-0000-0000-0000-000000000000, bf967a9c-0de6-11d0-a285-00aa003049e2
            #     Allow Everyone GenericRead O, CC 00000000-0000-0000-0000-000000000000, bf967aba-0de6-11d0-a285-00aa003049e2
            # " | Should Be $true

            $NewObjectSD | Test-Acl -AllowedAccess "
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 4c164200-20c0-11d0-a768-00aa006e0529, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 5f202010-79a5-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC bc0ac240-79a9-11d0-9020-00c04fc2d4cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 59ba2f42-79a2-11d0-9020-00c04fc2d3cf, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone ReadProperty O, CC 037088f8-0ae1-11d2-b422-00a0c968f939, bf967aba-0de6-11d0-a285-00aa003049e2
                Allow Everyone GenericRead O, CC 00000000-0000-0000-0000-000000000000, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow Everyone GenericRead O, CC 00000000-0000-0000-0000-000000000000, bf967a9c-0de6-11d0-a285-00aa003049e2
                Allow Everyone GenericRead O, CC 00000000-0000-0000-0000-000000000000, bf967aba-0de6-11d0-a285-00aa003049e2
            " | Should Be $true
        }
    }

    Describe ".NET Behavior That Breaks Previous Assumptions" {
        $Sddl = 'D:AI(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;BG)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;BG)(A;CIID;LC;;;BG)'
        $ObjectSD = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $ObjectSD.SetSecurityDescriptorSddlForm($Sddl)

        It "Works around .NET RemoveAccess limitation with 'conflicting' object and inherited types (re-ordering issue)" {

            # This one works with old method for verifying -AllowedAccess (order matters)
            $ObjectSD | Test-Acl -AllowedAccess "
                Allow 'BUILTIN\Guests' ListChildren O, CC
                Allow 'BUILTIN\Guests' GenericRead CC 00000000-0000-0000-0000-000000000000, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow 'BUILTIN\Guests' ReadProperty CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
            " | Should Be $true

            # This one didn't work with old method for verifying -AllowedAccess (again, notice the order)
            $ObjectSD | Test-Acl -AllowedAccess "
                Allow 'BUILTIN\Guests' GenericRead CC 00000000-0000-0000-0000-000000000000, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow 'BUILTIN\Guests' ReadProperty CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow 'BUILTIN\Guests' ListChildren O, CC
            " | Should Be $true
        }

        It "Works around .NET RemoveAccess limitation with 'conflicting' object and inherited types (can't fix by re-ordering ACEs)" {

            # Related to previous "re-order" test; in this case, since the ACE that applies to all object types, inherited object types, and
            # that has an access mask that mingles with the other two ACEs isn't removed, the original handling for -AccessAllowed cannot
            # work.
            $Result = $ObjectSD | Test-Acl -AllowedAccess "
                Allow 'BUILTIN\Guests' GenericRead CC 00000000-0000-0000-0000-000000000000, 4828cc14-1437-45bc-9b07-ad6f015e5f28
                Allow 'BUILTIN\Guests' ReadProperty CC 4c164200-20c0-11d0-a768-00aa006e0529, 4828cc14-1437-45bc-9b07-ad6f015e5f28
            " -Detailed

            $Result.ExtraAccess.Trim() | Should Be "Allow 'BUILTIN\Guests' ListChildren O, CC"
        }
    }
}