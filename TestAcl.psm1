
function Test-Acl {
<#
.SYNOPSIS
Test if a security descriptor contains allowed and/or required access control entries.

.DESCRIPTION
Verifying access control entries (ACEs) that a security descriptor (SD) contains can be a very complicated
process, especially considering all of the different types of securable objects in Windows.

Test-Acl attempts to simplify this process. After providing an -InputObject, which can be either the
securable object, e.g., file, folder, registry key, or a security descriptor object itself, you also provide
an -AllowedAces value and/or a -RequiredAces value. 

The -AllowedAces can be thought of as a whitelist: any
access that these ACEs grant are allowed to be present in the SD, even if they don't match exactly. For example,
you can specify that an ACE granting Users 'Read, Write' to a folder, subfolders, and files is allowed, but the
SD you're testing may only grant Users 'Read' to subfolders. This less-permissive ACE would not cause the test 
(to fail well, unless the -ExactMatch switch is also specified). If, however, the SD had an ACE granting Users
'Read, Delete', the test would fail because 'Delete' isn't contained in the -AllowedAces.

The -AllowedAces string formats can also contain wildcards for principals. This is useful for when you want to
allow certain rights to be allowed, even when you don't know what principals they may be granted to. For example,
maybe you're only looking for objects where users have more than Read access. Specifying the following in the
-AllowedAces would take care of that: Allow * Read

The -RequiredAces is a list of ACEs that MUST be specified. If more access/audit rights (or inheritance flags)
are granted, that's OK. For example, assume you specify the following -RequireAces list:

Allow Users Read SubFolders
Deny Guests Write

With those ACEs specified, that means an SD must have AT LEAST those rights specified. If the SD has an ACE that
grants Users 'FullControl' for the folder, subfolers, and files, that would be fine since it contains the required
rights. If there was a Deny ACE that denied more than 'Write' to guests, that would be fine as long as it applied
to the folder, subfolders, and files (since no inheritance/propagation information was specified, it defaults to
applying to all)

No wildcards are allowed for -RequiredAces.

.NOTES

#>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        # The object that owns the security descriptor that will be tested. This is a
        # flexible parameter that takes many securable objects, e.g., FileInfo, 
        # DirectoryInfo, RegistryKey objects from Get-Item and Get-ChildItem, security
        # descriptors returned from Get-Acl, [more examples go here]
        $InputObject,
        [Parameter()]
        # A list of ACEs that can be present in the security descriptor. If -AllowedAces
        # is provided, then the security descriptor CANNOT contain any ACEs except what's
        # provided in the -AllowedAces collection. The collection can contain ACEs that
        # aren't present in the security descriptor, however.
        [Roe.TransformScript({
            $_ | ConvertToAce
        })]
        [System.Security.AccessControl.CommonAce[]] $AllowedAces,
        [Parameter()]
        # A list of ACEs that MUST be present in the security descriptor. The security
        # descriptor is still allowed to contain ACEs that aren't listed in the
        # -RequiredAces collection. 
        [Roe.TransformScript({
            $_ | ConvertToAce
        })]
        [System.Security.AccessControl.CommonAce[]] $RequiredAces,
        # By default, ACEs aren't required to match the -AllowedAces or -RequiredAces
        # exactly, i.e., the AccessMask and/or InheritanceFlags can differ as long as 
        # the effective access is present. For example, if the security descriptor 
        # being tested has an ACE that grants 'Everyone' 'FullControl' that applies 
        # to 'Object, ChildContainers, and ChildObjects', and Test-Acl is tasked with 
        # checking for the existence of an ACE granting 'Everyone' 'Read' access to 
        # an 'Object', the function would, by default, consider the 'Read' ACE to 
        # match the existing 'FullControl' one. If this switch is specified, though, 
        # the less restrictive ACE would not be considered a match. This should only 
        # apply to -RequiredAce, so this help needs to be rewritten to reflect that.
        [switch] $ExactMatch
    )

    process {
        try {
            $SD = $InputObject | NewCommonSecurityDescriptor -ErrorAction Stop
        }
        catch {
            Write-Error $_
            return
        }

        # Process -RequiredAces first since -AllowedAces test requires ACLs to
        # be emptied out completely
        #
        # The way this works is that we'll remember the Sddl form, and attempt
        # to add each -RequiredAces entry. After adding each ACE, we'll test the
        # Sddl form again. If the SD already effectively contained that ACE, the
        # Sddl form should be unchanged. If we detect a change, we know that the
        # function should exit with a failure.
        #
        # Eventually, we can allow a switch that will still walk through the
        # ACEs, even after a failure is detected. We'd need to reset the SD after
        # each failure, though. This would be useful for validation, though, so
        # instead of just getting a 'This failed' message, you could provide more
        # information about WHY it failed
        $StartingSddlForm = $SD.GetSddlForm('All')
        foreach ($ReqAce in $RequiredAces) {
            $SD | AddAce $ReqAce
            if ($StartingSddlForm -ne $SD.GetSddlForm('All')) {
                return $false
            }
        }

        $AllowedAccessAcesSpecified = $AllowedAuditAcesSpecified = $false
        foreach ($AllowedAce in $AllowedAces) {
            if ($AllowedAces.AceQualifier -in [System.Security.AccessControl.AceQualifier]::AccessAllowed, [System.Security.AccessControl.AceQualifier]::AccessDenied) {
                $AllowedAccessAcesSpecified = $true
            }
            elseif ($AllowedAces.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::SystemAudit) {
                $AllowedAuditAcesSpecified = $true
            }
            
            Write-Debug "Removing ACE"
            $SD | RemoveAce $AllowedAce
        }
$global:__sd = $SD
        if ($AllowedAccessAcesSpecified -and $SD.DiscretionaryAcl.Count -gt 0) {
            Write-Verbose "  -> DACL still contains entries, so there must have been some access not specified in -AllowedAces present"
            return $false
        }

        if ($AllowedAuditAcesSpecified) {
            throw "Audit ACEs aren't allowed yet!"
        }
        
        # If we made it this far, we passed the test!
        return $true
    }
}

$GenericRightsDef = @{
    GenericRead = -2147483648
    GenericWrite = 1073741824
    GenericExecute = 536870912
    GenericAll = 268435456
}

function ToAccessMask {
    <#
        Helper function that helps convert any generic rights present
        into object-specific rights
    #>
    [CmdletBinding()]
    param(
        [int] $AccessMask,
        [System.Collections.IDictionary] $GenericRightsDict
    )
    
    #if ($null -ne ($GenericRightsDict = $SecurityDescriptor.__GenericRights) -and -not $NoGenericRightsTranslation) {
    if ($null -ne $GenericRightsDict) {
        # Check for presence of generic rights, and replace them based on what the dictionary says
        foreach ($GenRight in $GenericRightsDef.Keys) {
            Write-Verbose "Working on ${GenRight}"
            if (-not $GenericRightsDict.Contains($GenRight)) {
                Write-Verbose "  ...not present in GenericRightsDict, so skipping"
                continue
            }
            $Value = $GenericRightsDef[$GenRight]
            if (($AccessMask -band $Value) -eq $Value) {
                Write-Verbose "  ...old mask = ${AccessMask}"
                $AccessMask = $AccessMask -bxor $Value  # Turn that bit off
                $AccessMask = $AccessMask -bor $GenericRightsDict[$GenRight]
                Write-Verbose "  ...new mask = ${AccessMask}"
            }
        }
    }

    return $AccessMask
}

function ToAccessType {
    [CmdletBinding()]
    param(
        [System.Security.AccessControl.AceQualifier] $AceQualifier
    )

    switch ($AceQualifier) {

        AccessAllowed { [System.Security.AccessControl.AccessControlType]::Allow }                
        AccessDenied { [System.Security.AccessControl.AccessControlType]::Deny }
        default {
            throw "Unsupported AceQualifier: ${_}"
        }
    }
}

function AddAce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.AccessControl.CommonSecurityDescriptor] $SecurityDescriptor,
        [Parameter(Mandatory, Position=0)]
        [System.Security.AccessControl.CommonAce] $Ace,
        [switch] $NoGenericRightsTranslation
    )

    process {
        $GenericRightsDict = if ($NoGenericRightsTranslation) { 
            $null
        }
        else {
            $SecurityDescriptor.__GenericRightsDict
        }
        if ($Ace.AuditFlags -eq [System.Security.AccessControl.AuditFlags]::None) {
            # This is an access ACE
            $SecurityDescriptor.DiscretionaryAcl.AddAccess(
                (ToAccessType $Ace.AceQualifier),
                $Ace.SecurityIdentifier,
                (ToAccessMask $Ace.AccessMask -GenericRights $GenericRightsDict),
                $Ace.InheritanceFlags,
                $Ace.PropagationFlags
            )
        }
        else {
            # This is an audit ACE
            $SecurityDescriptor.SystemAcl.AddAudit(
                $Ace.AuditFlags,
                $Ace.SecurityIdentifier,
                (ToAccessMask $Ace.AccessMask -GenericRights $GenericRightsDict),
                $Ace.InheritanceFlags,
                $Ace.PropagationFlags
            )
        }
    }
}

function RemoveAce {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.AccessControl.CommonSecurityDescriptor] $SecurityDescriptor,
        [Parameter(Mandatory, Position=0)]
        [System.Security.AccessControl.CommonAce] $Ace,
        [switch] $NoGenericRightsTranslation
    )

    process {
        $GenericRightsDict = if ($NoGenericRightsTranslation) { 
            $null
        }
        else {
            $SecurityDescriptor.__GenericRightsDict
        }
        if ($Ace.AuditFlags -eq [System.Security.AccessControl.AuditFlags]::None) {
            # This is an access ACE
            $SecurityDescriptor.DiscretionaryAcl.RemoveAccess(
                (ToAccessType $Ace.AceQualifier),
                $Ace.SecurityIdentifier,
                (ToAccessMask $Ace.AccessMask -GenericRights $GenericRightsDict),
                $Ace.InheritanceFlags,
                $Ace.PropagationFlags
            ) | Out-Null
        }
        else {
            # This is an audit ACE
            $SecurityDescriptor.SystemAcl.RemoveAudit(
                $Ace.AuditFlags,
                $Ace.SecurityIdentifier,
                (ToAccessMask $Ace.AccessMask -GenericRights $GenericRightsDict),
                $Ace.InheritanceFlags,
                $Ace.PropagationFlags
            ) | Out-Null
        }
    }
}

function AstToObj {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.ExpressionAst] $Ast
    )    
    
    switch ($Ast.StaticType) {
        
        string {
            # This should handle bare words and quoted strings
            $Ast.Value
        }

        System.Object[] {
            $Ast.Elements.Extent.Text
        }

        default {
            Write-Warning "Unhandled Node StaticType: ${_}"
            $Ast.Extent.Text
        }
    }
}

function ConvertToSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject
    )

    process {

        if ($InputObject -is [System.Security.Principal.SecurityIdentifier]) {
            return $InputObject
        }
        elseif ($InputObject -is [System.Security.Principal.NTAccount]) {
            # Past this if/else block, we just want strings...
            $InputObject = $InputObject.ToString()
        }
        elseif ($InputObject -isnot [string]) {
            Write-Error "Unhandled InputObject type: $($InputObject.GetType().Name)"
            return
        }

        Write-Verbose "ConverToSid: ${InputObject}"
        # Check for known strings that need to be "fixed up"
        $ReplaceRegexes = @(
            '^APPLICATION PACKAGE AUTHORITY\\'
        )
        $BigRegex = $ReplaceRegexes -join '|'
        $InputObject = $InputObject -replace $BigRegex        
        
        Write-Verbose "  -> String value after known replacements: ${InputObject}"

        $Sid = try {
            ([System.Security.Principal.NTAccount] $InputObject).Translate([System.Security.Principal.SecurityIdentifier])
        }
        catch {
            # That didn't work. Was this maybe a SID?
            Write-Verbose "  -> NTAccount to SID translation failed. Trying to cast to SID"
            if ($InputObject -match '^\*?(S-.*)$') {
                $matches[1] -as [System.Security.Principal.SecurityIdentifier]
            }
        }

        # Final test that something is in SID:
        if ($null -eq $SID) {
            Write-Error "Unable to determine SID from '${InputObject}'"
            return
        }

        Write-Verbose "  -> SID: ${SID}"
        return $SID
    }
}
function ConvertToAce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject
    )

    process {

        [System.Security.AccessControl.AceFlags] $AceFlags = [System.Security.AccessControl.AceFlags]::None   
        $AccessMask = 0
        $AceQualifier = $Sid = $null
        $AceFlagsDefined = $false

        switch ($InputObject.GetType()) {

            ([String]) {
                $InputObject = $InputObject -split '\s*\n\s*' | Where-Object { $_ }
                if ($InputObject.Count -gt 1) {
                    $InputObject | ConvertToAce
                    return
                }
                
                Write-Verbose "Original String: ${InputObject}"
                
                # Really want to remove ability to have 'and' in the string. To prevent having to peek at the next node, doing a
                # find on any 'and's that don't have a leading comma, and adding a comma. This makes it so we can always look for
                # an 'and' in the $CurrentNodeText
                $NewInputObject = $InputObject -replace '(?<!\,)\s+and', ', and'
                if ($InputObject -ne $NewInputObject) {
                    $InputObject = $NewInputObject
                    Write-Verbose "  Modified string: ${InputObject}"
                }
                <#
                    Takes this form:
                    [Allow|Deny|Audit (S[uccess]|F[ailure])] 'Principal' Rights1, Rights2 [Object, ChildContainers, ChildObjects]

                    We're going to use the PS AST parser to split the string.
                #>
                $Tokens = $ParseErrors = $null
                
                # We put a & at the beginning of the string to be parsed in case the first token is a double quoted string (remember
                # that we're abusing the PSParser for this purpose, so the & is just a way to make sure that the string is parsed in
                # a consistent manner)
                $Ast = [System.Management.Automation.Language.Parser]::ParseInput("& ${InputObject}", [ref] $Tokens, [ref] $ParseErrors)
                $Nodes = $Ast.FindAll({ $args[0].Parent -is [System.Management.Automation.Language.CommandBaseAst]}, $false)
$global:__nodes = $Nodes
                for ($i = 0; $i -lt $Nodes.Count; $i++) {

                    $CurrentNodeText = AstToObj $Nodes[$i]
                    Write-Verbose "  CurrentNodeText: ${CurrentNodeText}"

                    # May remove this later, but 'and' is allowed; simply replace that element with the
                    # next node (the way this is implemented, two ands together should result in an error):
                    while ($CurrentNodeText[-1] -eq 'and') {
                        Write-Verbose '    -> replacing ''and'' with next node'
                        $CurrentNodeText[-1] = AstToObj $Nodes[++$i]
                        $CurrentNodeText = $CurrentNodeText | ForEach-Object { $_ }
                        Write-Verbose "    -> new CurrentNodeText: ${CurrentNodeText}"
                    }

                    if ($null -eq $AceQualifier -and $CurrentNodeText -match '^(?<type>Allow|Deny|Audit)$') {
                        # AceQualifier is optional, so check to see what the first node is:
                        $AceQualifier = switch ($matches.type) {
                            Allow { [System.Security.AccessControl.AceQualifier]::AccessAllowed }
                            Deny { [System.Security.AccessControl.AceQualifier]::AccessDenied }
                            default { [System.Security.AccessControl.AceQualifier]::SystemAudit }
                        }
                        Write-Verbose "    -> AceQualifier = ${AceQualifier}"
                    }
                    elseif ('SystemAudit' -eq $AceQualifier -and ([System.Security.AccessControl.AceFlags]::AuditFlags.value__ -band $AceFlags.value__) -eq 0) {
                        # At this point, Success, Failure (or SF) are not optional. This node must contain
                        # information about it
#                        if ($CurrentNodeText -match '^(?<success>S(uccess)?)?(\s*\,\s*)?(?<failure>F(ailure)?)?$') {
                        if (($CurrentNodeText -join ' ') -match '^(?<success>S(uccess)?)?\s*(?<failure>F(ailure)?)?$') {
                            if ($matches.success) {
                                $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::SuccessfulAccess
                            }
                            if ($matches.failure) {
                                $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::FailedAccess
                            }
                        }
                        else {
                            Write-Error "Unable to determine audit flags from '${CurrentNodeText}'"
                            return
                        }
                    }
                    elseif ($null -eq $Sid) {
                        # Time to figure out the principal that the ACE should apply to
                        # First, see if we can cast the string to an NTAccount and Translate() to a SID:
                        $SID = try {
                            $CurrentNodeText | ConvertToSid -ErrorAction Stop
                        }
                        catch {
                            Write-Error $_
                            return
                        }

                    }
                    elseif (0 -eq $AccessMask) {
                        # Figure out the AccessMask. First, is this numeric?
                        if ($CurrentNodeText -as [int]) {
                            $AccessMask = $CurrentNodeText
                            continue
                        }
                        
                        # Next, check to see if an enum type helper was specified
                        $PotentialEnumTypes = [System.Security.AccessControl.FileSystemRights], [System.Security.AccessControl.RegistryRights], [System.DirectoryServices.ActiveDirectoryRights]
                        if ($CurrentNodeText[0] -match '^(?<type>[^\:]+)\:(?<therest>.*)') {
                            $Type = $matches.type
                            Write-Warning "Type searching doesn't work right now!!"
                            
                            $CurrentNodeText[0] = $matches.therest
                        }

                        foreach ($CurrentType in $PotentialEnumTypes) {
                            if (($AccessMask = $CurrentNodeText -as $CurrentType)) {
                                break    
                            }
                        }

                        if ([int] $AccessMask -eq 0) {
                            Write-Error "Unable to determine access mask from '${CurrentNodeText}'"
                            return
                        }
                    }
                    elseif (($AceFlags.value__ -band [System.Security.AccessControl.AceFlags]::InheritanceFlags) -eq 0) {
                        
                        Write-Verbose "    -> testing for AceFlags"
                        # My first test case for a string version had a 'to' separating the rights and the AppliesTo. Now that
                        # I'm implementing it, I'm not sure I like that idea, but let's put it in for now. Should we have a
                        # check to make sure if the 'to' (or 'applies to' or 'appliesto') has inheritance and propagation flags
                        # following it? Right now, you could do 'Everyone Modify to', and it would be valid...
                        if ($CurrentNodeText -match '^(applies)?(to)?$') { 
                            Write-Verbose '    -> ignoring'
                            continue 
                        }

                        if (($AppliesTo = $CurrentNodeText -as [Roe.AppliesTo])) {
                            $AceFlagsDefined = $true
                            Write-Verbose "    -> valid AceFlags found; before AceFlags: ${AceFlags}"

                            # Need to make one change. If 'Object' or equivalent is set, we need to take it out of the set bits, and if it's not set, we need to set it. So we're just going to toggle numeric 8
                            $AceFlags = $AceFlags.value__ -bor ($AppliesTo.value__ -bxor 8)
                            Write-Verbose "    -> after AceFlags: ${AceFlags}"
                        }
                        else {
                            Write-Error "Unknown ACE flags: ${CurrentNodeText}"
                            return
                        }
                    }
                }

                # If $AceQualifier wasn't determined earlier, set it to Allowed
                if ($null -eq $AceQualifier) {
                    $AceQualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed
                }

                # Test to see if any inheritance and propagation flags have been set (remember, they were optional). If not, set them for O CC CO
                if (-not $AceFlagsDefined) {
                    $AceFlags = $AceFlags.value__ -bor ([System.Security.AccessControl.AceFlags] 'ObjectInherit, ContainerInherit').value__
                }
            }

            { $InputObject -is [System.Security.AccessControl.AuthorizationRule] } {
                if ($InputObject.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) {
                    $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::ContainerInherit.value__
                }
                if ($InputObject.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) {
                    $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::ObjectInherit.value__
                }
            
                if ($InputObject.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
                    $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::InheritOnly.value__
                }
                if ($InputObject.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) {
                    $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::NoPropagateInherit.value__
                }

                $AccessMask = $InputObject.GetType().GetProperty('AccessMask', [System.Reflection.BindingFlags] 'NonPublic, Instance').GetValue($InputObject)

                try {
                    $Sid = $InputObject.IdentityReference | ConvertToSid -ErrorAction Stop
                }
                catch {
                    Write-Error "Error translating IdentityReference [$($InputObject.IdentityReference)] to SID: ${_}"
                    return
                }
            }

            { $InputObject -is [System.Security.AccessControl.ObjectAccessRule] -or $InputObject -is [System.Security.AccessControl.ObjectAuditRule] } {
                throw "Object Rules not supported yet!"
            }

            { $InputObject -is [System.Security.AccessControl.AccessRule] } {
                $AceQualifier = if ($InputObject.AccessControlType -eq 'Allow') {
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed
                }
                else {
                    [System.Security.AccessControl.AceQualifier]::AccessDenied
                }

            }

            { $InputObject -is [System.Security.AccessControl.AuditRule] } {
                $AceQualifier = [System.Security.AccessControl.AceQualifier]::SystemAudit
                
                if ($InputObject.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) {
                    $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::SuccessfulAccess
                }
                if ($InputObject.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure) {
                    $AceFlags = $AceFlags.value__ -bor [System.Security.AccessControl.AceFlags]::FailedAccess
                }
            }

            default {
                Write-Error "Unsupported type: ${_}"
                return
            }
        }
    
        New-Object System.Security.AccessControl.CommonAce (
            $AceFlags,
            $AceQualifier,
            $AccessMask,
            $Sid,
            $false,
            $null
        )
    }
}

function NewCommonSecurityDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject,
        [switch] $Audit
    )
    
    process {
        $Sddl = $GenericRightsDict = $null
        $IsContainer = $IsDs = $false

        if ($InputObject -is [System.Security.AccessControl.ObjectSecurity]) {
            Write-Verbose "InputObject is [ObjectSecurity]"
            $Sddl = $InputObject.GetSecurityDescriptorSddlForm('All')
            
            # Use some reflection to get at the info we need for the common SD:
            $BF = [System.Reflection.BindingFlags] 'NonPublic, Instance'
            $IsContainer = $InputObject.GetType().GetProperty('IsContainer', $BF).GetValue($InputObject)
            $IsDS = $InputObject.GetType().GetProperty('IsDS', $BF).GetValue($InputObject)

            $AccessRightType = $InputObject.AccessRightType

            if ($Audit) {
                Write-Warning "Should we test for presence of SACL??"
            }
        }
        elseif (($Path = if ($InputObject -is [string]) { $InputObject } elseif ($null -ne $InputObject.PsPath) { $InputObject.PsPath })) {

            Write-Verbose "Contains 'PsPath' property"
            # Try Get-Acl:
            try {
                Get-Acl -ErrorAction Stop -Path $Path | & $MyInvocation.MyCommand -Audit:$Audit
            }
            catch {
                Write-Error "Error while calling Get-Acl: ${_}"                    
            }
            return
        }
        else {
            Write-Error "Unsupported object: ${_}"
            return
        }

        # We have a whitelist of AccessRightTypes that we know what generic rights mean. If this is $null, that's not an issue, it
        # just means there won't be a generic rights dictionary
        $GenericRightsDict = switch ($AccessRightType) {
            
            ([System.Security.AccessControl.FileSystemRights]) {
                Write-Verbose "File/Folder generic rights dictionary"
                @{
                    GenericRead = [System.Security.AccessControl.FileSystemRights] 'Read, Synchronize'
                    GenericWrite = [System.Security.AccessControl.FileSystemRights] 'Write, ReadPermissions, Synchronize'
                    GenericExecute = [System.Security.AccessControl.FileSystemRights] 'ExecuteFile, ReadAttributes, ReadPermissions, Synchronize'
                    GenericAll = [System.Security.AccessControl.FileSystemRights] 'FullControl'
                }
            }

            default {
                Write-Verbose "No generic rights dictionary"
                $null
            }
        }

        # If we've made it here, we have enough information to create a security descriptor
        $ReferenceSD = New-Object System.Security.AccessControl.CommonSecurityDescriptor $IsContainer, $IsDs, $Sddl
        $NewSD = New-Object System.Security.AccessControl.CommonSecurityDescriptor $IsContainer, $IsDs, 'D:S:'

        # Tuck the generic rights dictionary inside the SD object (AddAce and RemoveAce will know what to do with it)
        $NewSD | Add-Member -NotePropertyMembers @{
            __GenericRightsDict = $GenericRightsDict
        }

        foreach ($Ace in $ReferenceSD.DiscretionaryAcl) {
            $NewSD | AddAce $Ace
        }

        foreach ($Ace in $ReferenceSD.SystemAcl) {
            $NewSD | AddAce $Ace
        }

        return $NewSD
    }
}

Add-Type @'
    using System;
    namespace Roe {
        [Flags()]
        public enum AppliesTo {
            ChildObjects = 1,
            CO = 1,
            Files = 1,
            ChildContainers = 2,
            CC = 2,
            SubFolders = 2,
            ChildKeys = 2,
            SubKeys = 2,
            Object = 8,
            ThisFile = 8,
            ThisFolder = 8,
            ThisKey = 8,
            This = 8,
            O = 8
        }
    }
'@

Add-Type @'
    using System.Collections;    // Needed for IList
    using System.Management.Automation;
    using System.Collections.Generic;
    namespace Roe {
        public sealed class TransformScriptAttribute : ArgumentTransformationAttribute {
            string _transformScript;
            public TransformScriptAttribute(string transformScript) {
                _transformScript = string.Format(@"
                    # Assign $_ variable
                    $_ = $args[0]
 
                    # The return value of this needs to match the C# return type so no coercion happens
                    $FinalResult = New-Object System.Collections.ObjectModel.Collection[psobject]
                    $ScriptResult = {0}
 
                    # Add the result and output the collection
                    $FinalResult.Add((,$ScriptResult))
                    $FinalResult", transformScript);
            }
 
            public override object Transform(EngineIntrinsics engineIntrinsics, object inputData) {
                var results = engineIntrinsics.InvokeCommand.InvokeScript(
                    _transformScript,
                    true,   // Run in its own scope
                    System.Management.Automation.Runspaces.PipelineResultTypes.None,  // Just return as PSObject collection
                    null,
                    inputData
                );
                if (results.Count > 0) {
                    return results[0].ImmediateBaseObject;
                }
                return inputData;  // No transformation
            }
        }
    }
'@