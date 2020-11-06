# Get-RBCD-Threaded
Tool to discover Resource-Based Constrained Delegation attack paths in Active Directory Environments

Based almost entirely on wonderful blog posts "Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory" by [Elad Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) and "A Case Study in Wagging the Dog: Computer Takeover" by [harmj0y](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/). Read these two blog posts if you actually want to understand what is going on here. I honestly only half understand it all myself (and that's being generous).

I don't know how to C# well so I figured out how to communicate with a domain in C# by reading through the source code of [SharpSploit](https://github.com/cobbr/SharpSploit) and [SharpView](https://github.com/tevora-threat/SharpView).

## How it works
Get-RBCD-Thread will query all Active Directory users, groups (minus privileged groups like "Domain Admins" and "BUILTIN\Administrators"), and computer objects in your current domain and compile a list of their SIDs. Get-RBCD-Threaded will then query AD for all DACLs on the computer objects in the domain. Each ACE in the DACLs will be checked to see if one of the user/group/computer SIDS has either "GenericAll", "GenericWrite", "WriteOwner", or "WriteDacl" privileges on the computer object, or if the SIDS have "WriteProp" permissions on the ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity attribute (GUID:3f78c3e5-f79a-46bd-a0b8-9d18116ddc79). If it does, then, well, you my friend are on your way to a Resource-Based Constrained Delegation attack!

## Usage
Compile in Visual Studio. This uses Parallel.ForEach to spead up searching through the DACL object, so .NET v4 is minimum required.

### Options
-u|-username=, Username to authenticate as

-p|-password=, Password for the user

-d|-domain=, Fully qualified domain name to authenticate to

-s|-searchforest, Discover domains and forests through trust relationships. Enumerate all domains and forests

-pwdlastset=, Filter computers based on pwdLastSet to remove stale computer objects. If you set this to 90, it will filter out computer objects whose pwdLastSet date is more than 90 days ago

-i|-insecure, Force insecure LDAP connect if LDAPS is causing connection issues.

-o|-outputfile=, Output to a CSV file. Provided full path to file and file name.

-h|-?|-help, Show the help options

You can now specify the username, password, and domain to authenticate to. If u/p/d options are blank, Get-RBCD-Threaded will atempt to authenticate to the domain in your current user context.

-o will output to a CSV file. Provide the full file path and file name to save the output to.

The default search specifies that port 636 be used to force LDAPS. This may cause issues. **If you get an error saying something about the server not being available or similar, try the "-i" flag to remove the 636 port from the connect string.**

"pwdLastSet" has been added as a filtering option. In larger environments you can get a lot of stale computer objects that no longer exist as the "destination" object int he ACL, and can't really be used for the RBCD attack (at least not that I am aware of). Set pwdLastSet to a number of days. Example: "-pwdlastset=90" will filter out any computer objects from your results where the pwdLastSet date is greater or equal to 90 days ago from the current date and time.

Tested in an environment with 20k+ uses, groups, and computers (over 60k total objects). Get-RBCD-Thread took ~60 seconds to complete. By comparison, my hacked together [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev) commands in this [gist](https://gist.github.com/FatRodzianko/e4cf3efc68a700dca7cedbfd5c05c99f) to perform a similar search ran for several hours and never completed.

This tool will not perform the delegation attack for you. You'll need to read Elad Shamir's and harmj0y's blogs to figure out how to do that. This will only help you find possible targets for the RBCD attack.

Example usage from my AD lab:

![alt text](https://raw.githubusercontent.com/FatRodzianko/Get-RBCD-Threaded/master/get-rbcd-threaded.PNG)

## Detections
This tool does nothing more than query Active Directory using LDAP queries, which may not be easy to detect. Netflow could possibly be used to detect large numbers of LDAP queries / traffic to one system.

The other possible way to detect this is through honeypot accounts. The idea would be to create a computer object that some user / group has write privileges to. The RBCD attack relies on modifying a computer object and then delegating kerberos tickets to it. The possible points of detection for the honeypot computer object could be:
1. Monitor modifications to the honeypot computer object, specifically to the "msds-allowedtoactonbehalfofotheridentity" property
1. Monitor for kerberos tickets requested for services on the honeypot computer object, specifically any kerberos tickets for administrator users

I made this tool to help me on penetration tests. However, defenders / blue teams / sysadmins can easily use this to help find weaknesses in their environments and (hopefully) move to remediate them.
