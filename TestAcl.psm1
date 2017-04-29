
function Test-Acl {

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
        $StartingSddlForm = $SD.GetSddlForm('All')
        foreach ($ReqAce in $RequiredAces) {
            $SD | AddAce $ReqAce
            if ($StartingSddlForm -ne $SD.GetSddlForm('All')) {
                return $false
            }
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

function AddAce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.AccessControl.CommonSecurityDescriptor] $SecurityDescriptor,
        [Parameter(Mandatory, Position=0)]
        [System.Security.AccessControl.CommonAce] $Ace,
        [switch] $NoGenericRightsTranslation
    )

    begin {
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
    }

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

        switch ($InputObject.GetType()) {

            ([String]) {
                Write-Verbose "Original String: ${InputObject}"
                
                # Really want to remove ability to have 'and' in the string. To prevent having to peek at the next node, doing a
                # find on any 'and's that don't have a leading comma, and adding a comma. This makes it so we can always look for
                # an 'and' in the $CurrentNodeText
                $NewInputObject = $InputObject -replace '(?<!\,\s*)and', ', and'
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
                $Ast = [System.Management.Automation.Language.Parser]::ParseInput($InputObject, [ref] $Tokens, [ref] $ParseErrors)
                $Nodes = $Ast.FindAll({ $args[0].Parent -is [System.Management.Automation.Language.CommandBaseAst]}, $false)

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
                            ([System.Security.Principal.NTAccount] $CurrentNodeText).Translate([System.Security.Principal.SecurityIdentifier])
                        }
                        catch {
                            # That didn't work. Was this maybe a SID?
                            if ($CurrentNodeText -match '^\*?(S-.*)$') {
                                $matches[1] -as [System.Security.Principal.SecurityIdentifier]
                            }
                        }

                        # Final test that something is in SID:
                        if ($null -eq $SID) {
                            Write-Error "Unable to determine SID from '${CurrentNodeText}'"
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
                            # Need to make one change. If 'Object' or equivalent is set, we need to take it out of the set bits, and if it's not set, we need to set it. So we're just going to toggle numeric 8
                            Write-Verbose "    -> valid AceFlags found; before AceFlags: ${AceFlags}"
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
                if (($AceFlags.value__ -band [System.Security.AccessControl.AceFlags]::InheritanceFlags) -eq 0) {
                    $AceFlags = $AceFlags.value__ -bor ([System.Security.AccessControl.AceFlags] 'ObjectInherit, ContainerInherit').value__
                }
            }

            { $InputObject -is [System.Security.AccessControl.AccessRule] } {
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

                $AceQualifier = if ($InputObject.AccessControlType -eq 'Allow') {
                    [System.Security.AccessControl.AceQualifier]::AccessAllowed
                }
                else {
                    [System.Security.AccessControl.AceQualifier]::AccessDenied
                }

                try {
                    $Sid = $InputObject.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                }
                catch {
                    Write-Error "Error getting SID: ${_}"
                    return
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

        switch ($InputObject.GetType().FullName) {

            { $_ -in 'System.IO.FileInfo', 'System.IO.DirectoryInfo' } {
                $Sddl = $InputObject | Get-Acl -Audit:$Audit | Select-Object -ExpandProperty Sddl
                $GenericRightsDict = @{
                    GenericRead = [System.Security.AccessControl.FileSystemRights] 'Read, Synchronize'
                    GenericWrite = [System.Security.AccessControl.FileSystemRights] 'Write, ReadPermissions, Synchronize'
                    GenericExecute = [System.Security.AccessControl.FileSystemRights] 'ExecuteFile, ReadAttributes, ReadPermissions, Synchronize'
                    GenericAll = [System.Security.AccessControl.FileSystemRights] 'FullControl'
                }
            }

            System.IO.DirectoryInfo {
                $IsContainer = $true
            }

            default {
                Write-Error "Unsupported object: ${_}"
                return
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