
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
        [System.Security.AccessControl.CommonAce[]] $AllowedAces,
        [Parameter()]
        # A list of ACEs that MUST be present in the security descriptor. The security
        # descriptor is still allowed to contain ACEs that aren't listed in the
        # -RequiredAces collection. 
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