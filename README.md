# Test-Acl
This project is a proof of concept for a new command that will eventually make it into the PowerShellAccessControl module (PAC module). It does not depend on any other modules, so you can grab the TestAcl.psm1 file and import it without worrying about dependencies. The module file defines a PowerShell v5 requirement, but that's only because it hasn't been tested on lower versions. It should run just fine on lower versions with slight modifications (I've gotten really bad about letting v5+ syntax features creep in).

Since this is a proof of concept, expect the syntax and features to change over time.

For an intro/primer into Windows access control, please see this [video](https://www.youtube.com/watch?v=G4bptl-H8PU&t=2s). It will help you're having trouble following the acronyms below.

The main goals of Test-Acl are to:
* **Test for whitelisted access (-AccessAllowed)**

  When -AccessAllowed is used, Test-Acl makes sure that any access defined in the DACL or SACL (if an audit ACE is provided) of an SD is contained in the ACEs specified via the -AccessAllowed parameter.

  By default, any access specified is allowed to be more permissive than what's actually present. This means if there are entries granting 'Read' access to the 'Users' group on a folder that apply to 'SubFolders' only, and you've specified an ACE to -AllowedAccess that grants 'FullControl' access to the 'Users' group for 'Folder, SubFolders, and Files', the ACE granting 'Read' would be considered an allowed ACE and wouldn't cause the test to fail. The not yet implemented -ExactMatch switch will change this behavior.

  Deny ACEs in a DACL are ignored unless a Deny ACE is included in the -AccessAllowed since you don't normally want the test to fail because the DACL is more restrictive than you're testing for.

  Examples:

  ```powershell
  <# Assume the following DACL:
  AceType Principal           AccessMask                                InheritedFrom   AppliesTo
  ------- ---------           ----------                                -------------   ---------
  Deny    Guests              FullControl                               <not inherited> O CC CO
  Allow   Authenticated Users Modify, Synchronize                       <not inherited>   CC CO
  Allow   Authenticated Users CreateDirectories/AppendData, Synchronize <not inherited> O
  Allow   SYSTEM              FullControl                               <not inherited> O CC CO
  Allow   Administrators      FullControl                               <not inherited> O CC CO
  Allow   Users               ReadAndExecute, Synchronize               <not inherited> O CC CO
  #>

  # Notice how this passes, even though no Deny rights are specified:
  PS> Test-Acl .\subfolder -AllowedAccess '
    Allow SYSTEM, Administrators FullControl
    Allow * ReadAndExecute
    Allow "Authenticated Users" Modify
  '
  
  True

  # This one fails, though, since a Deny right is specified, and, even though it's
  # for Guests, it doesn't include all access/applies to for what's actually on
  # the ACL
  PS> Test-Acl .\subfolder -AllowedAccess '
    Deny Guests Read      # Changing this to FullControl would make the test pass
    Allow * FullControl   # This is a more permissive version of the previous test
  '
  
  # -Detailed switch shows what made the test fail:
  PS> $Result = Test-Acl .\subfolder -AllowedAccess '
    Deny Guests Read
    Allow * ReadAndExecute
    Allow Administrators, SYSTEM FullControl
  ' -Detailed
  
  PS> $Result.Result
  False

  PS> $Result.ExtraAccess
        
  Deny 'BUILTIN\Guests' FileSystemRights: ExecuteFile, DeleteSubdirectoriesAndFiles, Write, Delete, ChangePermissions, TakeOwnership, Synchronize O, CC, CO
  Allow 'NT AUTHORITY\Authenticated Users' FileSystemRights: Write, Delete CC, CO
  Allow 'NT AUTHORITY\Authenticated Users' FileSystemRights: AppendData O
  ``` 

* **Test for required access (-RequiredAccess)**

  When -RequiredAccess is used, Test-Acl ensures that a DACL or SACL contains the effective rights defined in each rule (if -ExactMatch is used, the EXACT rules must be defined instead of the effective rights).
  
  This is very useful for testing for Deny and Audit ACEs, but can still be used to test for Allow ACEs.

  ```powershell
  <# Assume the following DACL and SACL:

  AceType Principal           AccessMask                                InheritedFrom   AppliesTo
  ------- ---------           ----------                                -------------   ---------
  Deny    Guests              FullControl                               <not inherited> O CC CO
  Allow   Authenticated Users Modify, Synchronize                       <not inherited>   CC CO
  Allow   Authenticated Users CreateDirectories/AppendData, Synchronize <not inherited> O
  Allow   SYSTEM              FullControl                               <not inherited> O CC CO
  Allow   Administrators      FullControl                               <not inherited> O CC CO
  Allow   Users               ReadAndExecute, Synchronize               <not inherited> O CC CO
  Audit F Everyone            FullControl                               <not inherited> O CC CO
  #>

  # This requires an elevated session to get the SACL since an audit ACE is included
  PS> Test-Acl .\subfolder -RequiredAccess '
    Deny Guests Read
    Audit F Everyone Delete, DeleteSubdirectoriesAndFiles  # Notice we''re not requiring FullControl
  '

  True

  # Finally, a test that we expect to fail:
  PS> $Result = Test-Acl .\subfolder -RequiredAccess '
    Users Modify
  ' -Detailed

  PS> $Result.Result

  False

  # Notice that it shows we're missing Write, Delete since Users already had ReadAndExecute
  PS> $Result.MissingAccess
  
  Allow 'BUILTIN\Users' FileSystemRights: Write, Delete O, CC, CO


  # Let's repeat that last test, except say that we only require Modify on the folder (O)
  PS> $Result = Test-Acl .\subfolder -RequiredAccess '
    Users Modify O
  ' -Detailed | select -ExpandProperty MissingAccess

  Allow 'BUILTIN\Users' FileSystemRights: Write, Delete O
  ```

  
* **Test for blacklisted access (-DisallowedAccess)**

  When -DisallowedAccess is used, Test-Acl ensures that the DACL and/or SACL don't contain the rights specified in the rule collection.

  This is the opposite of -RequiredAccess. If you want make sure a principal doesn't have any access at all, you specify 'FullControl' for their rights along with the 'Applies To' information. If, on the other hand, you want to allow 'Modify' to a principal, but not allow 'FullControl', you need to list the difference: 

  ```powershell
  PS> [System.Security.AccessControl.FileSystemRights]::FullControl -band (-bnot [System.Security.AccessControl.FileSystemRights]::Modify)
  
  DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership, Synchronize
  ```

  So you'd test for 'DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership', since the presence of any of those rights would violate your rules. Some examples:

  ```powershell
  # Assume same DACL from above
  PS> Test-Acl .\subfolder -DisallowedAccess '
    "Authenticated Users" DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership CC, CO
    Everyone FullControl
  '

  True
  
  # This fails because Authenticated Users has ListDirectory/ReadData for CC, CO
  PS> Test-Acl .\subfolder -DisallowedAccess '
    "Authenticated Users" ListDirectory
  ' -Detailed | select Result, DisallowedAccess

  Result DisallowedAccess                                                          
  ------ ----------------                                                          
  False Allow 'NT AUTHORITY\Authenticated Users' FileSystemRights: ReadData CC, CO

  
  # This passes because O doesn't have ListDirectory/ReadData allowed for Authenticated Users
  PS> Test-Acl .\subfolder -DisallowedAccess '
    "Authenticated Users" ListDirectory O
  '

  True

  ```
  

You may have noticed that those parameters are taking strings to represent the ACEs. Here's the format:
1. **AceType:** Allow|Deny|Audit *[Optional]*
   * Allow is assumed if you don't specify an AceType
   * If you specify 'Audit', you MUST specify audit flags. Any of these would be valid:
      ```
      Audit S
      Audit SF'
      Audit S, F
      Audit Success, Failure
      Audit Failure
      ```
1. **Principal:** A username, SID, or even a string with an asterisk for a wildcard. You can also comma separate principals. If the principal contains a space or special character, either escape them with a backtick or quote them. Examples:
   ```
   Allow Everyone
   Audit SF 'DOMAIN\*'
   Deny User1, User2, User3
   Allow S-1-5-11
   ```
1. **AccessMask:** Either a numeric access mask, or a string representation of a known rights enumeration, e.g., FileSystemRights, RegistryRights, ActiveDirectoryRights. Enumerations will be searched in that order. If you want to specify an enumeration type to use, you can put that before the comma separated rights. Examples:
   ```
   # FileSystemRights:
   Deny Guests FullControl
   Allow Users Read, Write

   # RegistryRights:
   Allow Users ReadKey
   Audit F Everyone RegistryRights: FullControl
   ```

1. **Applies To:** Any combination of Object, ChildContainers, or ChildObjects (there are actually several strings that are allowed here: [Roe.AppliesTo] | gm -Static -MemberType Properties | select -ExpandProperty Name):

   ```
   Deny Guests FullControl O, CC, CO
   Allow Users Read ChildContainers, ChildObjects
   Audit S Everyone Delete O and CC and CO
   ```

1. **ObjectAceType and InheritedObjectAceType: [Only used for Active Directory]** At the very end, you can put two comma separated guids to specify ObjectAceType and InheritedObjectAceType guids. More on this in a future update

The plan is for this to eventually support any securable object (as long as you can get the SDDL or binary form of the security descriptor). It currently supports files, folders, registry keys, and AD objects (even though the string format for the AD objects will need to be extended to support string representations of object classes, property/property sets, validated writes, and extended rights)