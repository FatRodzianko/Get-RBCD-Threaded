using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security;
using System.Security.AccessControl;
using System.DirectoryServices.ActiveDirectory;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Get_RBCD
{
    public class rbcd
    {
        public string Source { get; set; }
        public string Destination { get; set; }
        public string Privilege { get; set; }
        public rbcd(string source, string destination, string privilege)
        {
            Source = source;
            Destination = destination;
            Privilege = privilege;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var stopWatch = Stopwatch.StartNew();
            string currentDomain = null;
            try
            {
                currentDomain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().ToString();
                Console.WriteLine("This is the current domain: " + currentDomain);
            }
            catch
            {
                Console.WriteLine("Unable to get domain from current user context. Please specify domain to user");
            }

            // Get user domain information
            if (currentDomain != null)
            {
                string searchBase = "LDAP://DC=" + currentDomain.Replace(".", ",DC=");

                //Start searching for all AD users?
                DirectoryEntry adEntry = new DirectoryEntry(searchBase);
                DirectorySearcher userSearch = new DirectorySearcher(adEntry);

                userSearch.Filter = "(&(samAccountType=805306368))";
                userSearch.PropertiesToLoad.Add("objectsid");
                userSearch.PropertiesToLoad.Add("samaccountname");
                userSearch.PageSize = int.MaxValue;
                userSearch.SizeLimit = int.MaxValue;

                Console.WriteLine("Searching for all users...");
                SearchResultCollection userResults = null;
                SearchResult result;
                userResults = userSearch.FindAll();

                var allSids = new List<string>();
                Dictionary<string, string> sidMapping = new Dictionary<string, string>();
                if (userResults != null)
                {
                    Console.WriteLine("There are this many users: " + userResults.Count);
                    for (int counter = 0; counter < userResults.Count; counter++)
                    {
                        result = userResults[counter];
                        var usrId = (byte[])result.Properties["objectsid"][0];
                        var objectID = (new SecurityIdentifier(usrId, 0)).ToString();
                        allSids.Add(objectID.ToString());
                        sidMapping.Add(objectID.ToString(), result.Properties["samaccountname"][0].ToString());


                    }
                }

                // Search for all AD groups
                DirectorySearcher groupSearch = new DirectorySearcher(adEntry);

                groupSearch.Filter = "(&(objectCategory=group))";
                groupSearch.PropertiesToLoad.Add("objectsid");
                groupSearch.PropertiesToLoad.Add("samaccountname");
                groupSearch.PageSize = int.MaxValue;
                groupSearch.SizeLimit = int.MaxValue;

                Console.WriteLine("Searching for all groups...");
                SearchResultCollection groupResults = null;
                SearchResult groupResult;
                groupResults = groupSearch.FindAll();

                if (groupResults != null)
                {
                    Console.WriteLine("There are this many groups: " + groupResults.Count);
                    for (int counter = 0; counter < groupResults.Count; counter++)
                    {
                        groupResult = groupResults[counter];
                        // Filter out groups that have privileges over objects like Domain Admins
                        if (!(groupResult.Properties["samaccountname"][0].ToString().Equals("Domain Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Account Operators") || groupResult.Properties["samaccountname"][0].ToString().Equals("Enterprise Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Administrators") || groupResult.Properties["samaccountname"][0].ToString().Equals("DnsAdmins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Schema Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Key Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Enterprise Key Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Storage Replica Administrators")))
                        {
                            var groupId = (byte[])groupResult.Properties["objectsid"][0];
                            var objectID = (new SecurityIdentifier(groupId, 0)).ToString();
                            allSids.Add(objectID.ToString());
                            sidMapping.Add(objectID.ToString(), groupResult.Properties["samaccountname"][0].ToString());
                        }


                    }
                }

                // Search for all AD Computer SIDs

                // Search for all computer acls?
                Console.WriteLine("Searching for all computers...");
                DirectorySearcher aclSearch = new DirectorySearcher(adEntry);
                aclSearch.Filter = "(&(samAccountType=805306369))";
                var Properties = new[] { "samaccountname", "ntsecuritydescriptor", "objectsid", "dnshostname" };
                aclSearch.PropertiesToLoad.AddRange(Properties);
                aclSearch.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
                aclSearch.SizeLimit = int.MaxValue;
                aclSearch.PageSize = int.MaxValue;
                SearchResultCollection aclResults = aclSearch.FindAll();

                // Include the computer SIDs in allSids
                for (int counter = 0; counter < aclResults.Count; counter++)
                {
                    result = aclResults[counter];
                    var aclId = (byte[])result.Properties["objectsid"][0];
                    var objectID = (new SecurityIdentifier(aclId, 0)).ToString();
                    allSids.Add(objectID.ToString());
                    sidMapping.Add(objectID.ToString(), result.Properties["samaccountname"][0].ToString());

                }

                Console.WriteLine("There are this many computers: " + aclResults.Count);

                List<SearchResult> resultList = new List<SearchResult>();
                foreach (SearchResult acl in aclResults)
                {
                    resultList.Add(acl);
                }

                List<rbcd> rbcdList = new List<rbcd>();
                
                Parallel.ForEach(resultList, (SearchResult aclResult) =>
                {
                    var Object = aclResult.Properties;

                    var computerId = (byte[])aclResult.Properties["objectsid"][0];
                    var computerSid = (new SecurityIdentifier(computerId, 0)).ToString();

                    ActiveDirectorySecurity adsd = new ActiveDirectorySecurity();
                    adsd.SetSecurityDescriptorBinaryForm(Object["ntSecurityDescriptor"][0] as byte[]);
                    AuthorizationRuleCollection arc = adsd.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier));

                    foreach (ActiveDirectoryAccessRule adRule in arc)
                    {
                        string sid = null;
                        sid = adRule.IdentityReference.ToString();
                        
                        string hostname = null;
                        try
                        {
                            hostname = Object["dnshostname"][0].ToString();
                        }
                        catch
                        {
                            continue;
                        }
                        if (hostname == null)
                        {
                            hostname = Object["samaccountname"][0].ToString();
                        }

                        if (adRule.ActiveDirectoryRights == ActiveDirectoryRights.GenericAll)
                        {
                            if (allSids.Contains(sid) && sid != computerSid)
                            {
                                rbcdList.Add(new rbcd(sidMapping[sid], hostname, "GenericAll"));
                                
                            }
                        }
                        else if (adRule.ActiveDirectoryRights.ToString().Contains("GenericWrite"))
                        {
                            if (allSids.Contains(sid) && sid != computerSid)
                            {
                                rbcdList.Add(new rbcd(sidMapping[sid], hostname, "GenericWrite"));
                            }
                        }
                        else if (adRule.ActiveDirectoryRights.ToString().Contains("WriteOwner"))
                        {
                            if (allSids.Contains(sid) && sid != computerSid)
                            {
                                rbcdList.Add(new rbcd(sidMapping[sid], hostname, "WriteOwner"));
                            }
                        }

                    }

                });
                Console.WriteLine("Execution time = {0} seconds", stopWatch.Elapsed.TotalSeconds);
                Console.WriteLine("Number of possible RBCD ACLs: " + rbcdList.Count);
                foreach (rbcd oneRbcd in rbcdList)
                {
                    Console.WriteLine("RBCD ACL:\nSource: " + oneRbcd.Source + "\nDestination: " + oneRbcd.Destination + "\nPrivilege: " + oneRbcd.Privilege + "\n");
                }

            }

        }
    }
}
