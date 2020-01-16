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
using NDesk.Options;
using System.Text;
using System.IO;

namespace Get_RBCD
{
    public class rbcd
    {
        public string Source { get; set; }
        public string SourceDomain { get; set; }
        public string Destination { get; set; }
        public string Privilege { get; set; }
        public rbcd(string source, string sourceDomain, string destination, string privilege)
        {
            Source = source;
            SourceDomain = sourceDomain;
            Destination = destination;
            Privilege = privilege;
        }
    }

    public class sidMap
    {
        public string ObjectSID { get; set; }
        public string SamAccountName { get; set; }
        public string DomainName { get; set; }

        public sidMap(string objectSID, string samAccountName, string domainName)
        {
            ObjectSID = objectSID;
            SamAccountName = samAccountName;
            DomainName = domainName;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var stopWatch = Stopwatch.StartNew();

            //parse user options
            string username = null;
            string password = null;
            string domain = null;
            string outputfile = null;
            bool ldapInSecure = false;
            bool help = false;
            bool searchForest = false;

            var options = new OptionSet()
            {
                {"u|username=", "Username to authenticate as", v => username = v },
                {"p|password=", "Password for the user", v => password = v },
                {"d|domain=", "Fully qualified domain name to authenticate to", v => domain = v},
                {"s|searchforest", "Enumerate all domains and forests", v => searchForest = true },
                {"o|outputfile=", "Output to a CSV file. Please provided full path to file and file name.", v => outputfile = v },
                {"i|insecure", "Force insecure LDAP connect if LDAPS is causing connection issues.", v => ldapInSecure = true },
                { "h|?|help", "Show this help", v => help = true }
            };

            string currentDomain = null;
            string searchBase = null;
            DirectoryEntry adEntry = null;
            DirectoryContext domainContext = null;

            try
            {
                options.Parse(args);
                if (help)
                {
                    options.WriteOptionDescriptions(Console.Out);
                    System.Environment.Exit(1);
                }

                //Get the domain to use for authentication / enumeration
                if (domain != null)
                {
                    Console.WriteLine(format: "Using the specified domain {0}", domain);
                    currentDomain = domain;
                }
                else
                {
                    try
                    {
                        currentDomain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().ToString();
                        Console.WriteLine("This is the current domain: " + currentDomain);
                    }
                    catch
                    {
                        Console.WriteLine("Unable to get domain from current user context. Please specify domain to user");
                        System.Environment.Exit(1);
                    }
                }
                // Set the search base after the domain is confirmed
                searchBase = "LDAP://DC=" + currentDomain.Replace(".", ",DC=");
                Console.WriteLine("The LDAP search base is " + searchBase);

                string ldapConnect = null;
                if (ldapInSecure)
                {
                    ldapConnect = "LDAP://" + currentDomain;
                }
                else
                {
                    ldapConnect = "LDAP://" + currentDomain + ":636";
                    Console.WriteLine(ldapConnect);
                }

                // Authenticate the user
                if (username != null && password != null)
                {
                    Console.WriteLine(format: "Credential information submitted. Attempting to authenticate to {0} as {1}", currentDomain, username);
                    Test_Credentials(username, password, currentDomain);
                    adEntry = new DirectoryEntry(ldapConnect, username, password);
                    domainContext = new DirectoryContext(DirectoryContextType.Domain, currentDomain, username, password);
                }
                else
                {
                    adEntry = new DirectoryEntry(ldapConnect);
                    domainContext = new DirectoryContext(DirectoryContextType.Domain, currentDomain);
                }

                // Enumerate the current domain or all trusted domains
                if (searchForest)
                {
                    Console.WriteLine("You want to search all trusted domains and forests!");

                    //Get the current forest
                    string targetForest = Domain.GetDomain(domainContext).Forest.ToString();
                    var forestContext = new DirectoryContext(DirectoryContextType.Forest, targetForest, username, password);
                    var currentForest = Forest.GetForest(forestContext);
                    Console.WriteLine("The current forest is: " + currentForest);

                    //store all the domains enumerated through trusts
                    List<string> domainTrustArray = new List<string>();
                    domainTrustArray.Add(currentDomain);
                    //get all domain trusts
                    var domainTrusts = Domain.GetDomain(domainContext).GetAllTrustRelationships();
                    Console.WriteLine("\nEnumerating all domain trusts...");
                    foreach (TrustRelationshipInformation trust in domainTrusts)
                    {
                        Console.WriteLine(trust.TargetName + " " + trust.TrustType + " " + trust.TrustDirection);
                        domainTrustArray.Add(trust.TargetName);
                    }

                    //start getting all forest trusts
                    Console.WriteLine("\nEnumerating all trusted forests...");
                    foreach (TrustRelationshipInformation trust in currentForest.GetAllTrustRelationships())
                    {
                        Console.WriteLine(trust.TargetName + " " + trust.TrustType + " " + trust.TrustDirection);
                        domainTrustArray.Add(trust.TargetName);
                    }

                    //Set the variables needed to store users, groups, and domains
                    SearchResultCollection aclResults = null;
                    var allSids = new List<string>();
                    List<sidMap> sidMapList = new List<sidMap>();
                    List<SearchResult> resultList = new List<SearchResult>();
                    List<rbcd> rbcdList = new List<rbcd>();
                    
                    //Enumerate through each domain discovered through trust relationships
                    Console.WriteLine(format:"\n{0} domains found. Listing domains", domainTrustArray.Count);
                    
                    foreach (string trustedDomain in domainTrustArray)
                    {
                        Console.WriteLine(trustedDomain);
                        
                        currentDomain = null;
                        currentDomain = trustedDomain;
                        //add if statement to see if username and password were supplied?
                        if (username != null && password != null)
                        {
                            adEntry = new DirectoryEntry("LDAP://" + currentDomain, username, password);
                        }
                        else
                        {
                            adEntry = new DirectoryEntry("LDAP://" + currentDomain);
                        }
                        

                        
                        Get_Users(adEntry, sidMapList, allSids, currentDomain);
                        Get_Groups(adEntry, sidMapList, allSids, currentDomain);
                        aclResults = Get_Computers(adEntry, sidMapList, allSids, currentDomain, aclResults);

                        
                        foreach (SearchResult acl in aclResults)
                        {
                            resultList.Add(acl);
                        }

                    }

                    Get_RBCD_ACLs(resultList, rbcdList, allSids, sidMapList);
                    if (outputfile != null)
                    {
                        bool saved = ExportCsv(rbcdList, outputfile);
                        if (!saved)
                        {
                            Console.WriteLine("\nUnable to save file. Printing to console instead.\n");
                            Print_Acls(rbcdList);
                        }
                    }
                    else
                    {
                        Print_Acls(rbcdList);
                    }
                }
                else
                {
                    Console.WriteLine("Only searching current domain.");
                    var allSids = new List<string>();
                    List<sidMap> sidMapList = new List<sidMap>();
                    SearchResultCollection aclResults = null;
                    List<rbcd> rbcdList = new List<rbcd>();
                    List<SearchResult> resultList = new List<SearchResult>();

                    Get_Users(adEntry, sidMapList, allSids, currentDomain);
                    Get_Groups(adEntry, sidMapList, allSids, currentDomain);
                    aclResults = Get_Computers(adEntry, sidMapList, allSids, currentDomain, aclResults);

                    foreach (SearchResult acl in aclResults)
                    {
                        resultList.Add(acl);
                    }

                    Get_RBCD_ACLs(resultList, rbcdList, allSids, sidMapList);

                    if (outputfile != null)
                    {
                        bool saved = ExportCsv(rbcdList, outputfile);

                        if (!saved)
                        {
                            Console.WriteLine("\nUnable to save file. Printing to console instead.\n");
                            Print_Acls(rbcdList);
                        }
                    }
                    else
                    {
                        Print_Acls(rbcdList);
                    }
                    

                }
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
            }

            Console.WriteLine("Execution time = {0} seconds", stopWatch.Elapsed.TotalSeconds);
        }
        public static void Test_Credentials(string username, string password, string domain)
        {
            try
            {
                PrincipalContext pc = new PrincipalContext(ContextType.Domain, domain);

                try
                {
                    bool isValid = pc.ValidateCredentials(username, password);
                    if (isValid)
                    {
                        Console.WriteLine(string.Format("Authentication to {0} as {1} was successful", domain, username));
                    }
                    else
                    {
                        Console.WriteLine(string.Format("User credentials for {0} are invalid", username));
                        System.Environment.Exit(1);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(" [x] {0}", e.Message);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
            }
        }

        public static void Get_Users(DirectoryEntry adEntry, List<sidMap> sidMapList, List<string> allSids, string currentDomain)
        {
            DirectorySearcher userSearch = new DirectorySearcher(adEntry);

            userSearch.Filter = "(&(samAccountType=805306368))";
            userSearch.PropertiesToLoad.Add("objectsid");
            userSearch.PropertiesToLoad.Add("samaccountname");
            userSearch.PageSize = int.MaxValue;
            userSearch.SizeLimit = int.MaxValue;

            SearchResultCollection userResults = null;
            SearchResult result;
            userResults = userSearch.FindAll();

            if (userResults != null)
            {
                Console.WriteLine(format: "There are {0} users in {1}", userResults.Count, currentDomain);
                for (int counter = 0; counter < userResults.Count; counter++)
                {
                    result = userResults[counter];
                    var usrId = (byte[])result.Properties["objectsid"][0];
                    var objectID = (new SecurityIdentifier(usrId, 0)).ToString();
                    allSids.Add(objectID.ToString());
                    sidMapList.Add(new sidMap(objectID.ToString(), result.Properties["samaccountname"][0].ToString(),currentDomain));
                    
                }
            }
        }

        public static void Get_Groups(DirectoryEntry adEntry, List<sidMap> sidMapList, List<string> allSids, string currentDomain)
        {
            DirectorySearcher groupSearch = new DirectorySearcher(adEntry);

            groupSearch.Filter = "(&(objectCategory=group))";
            groupSearch.PropertiesToLoad.Add("objectsid");
            groupSearch.PropertiesToLoad.Add("samaccountname");
            groupSearch.PageSize = int.MaxValue;
            groupSearch.SizeLimit = int.MaxValue;

            SearchResultCollection groupResults = null;
            SearchResult groupResult;
            groupResults = groupSearch.FindAll();

            if (groupResults != null)
            {
                Console.WriteLine(format:"There are {0} groups  in {1}",groupResults.Count, currentDomain);
                for (int counter = 0; counter < groupResults.Count; counter++)
                {
                    groupResult = groupResults[counter];
                    // Filter out groups that have privileges over objects like Domain Admins
                    if (!(groupResult.Properties["samaccountname"][0].ToString().Equals("Domain Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Account Operators") || groupResult.Properties["samaccountname"][0].ToString().Equals("Enterprise Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Administrators") || groupResult.Properties["samaccountname"][0].ToString().Equals("DnsAdmins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Schema Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Key Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Enterprise Key Admins") || groupResult.Properties["samaccountname"][0].ToString().Equals("Storage Replica Administrators")))
                    {
                        var groupId = (byte[])groupResult.Properties["objectsid"][0];
                        var objectID = (new SecurityIdentifier(groupId, 0)).ToString();
                        allSids.Add(objectID.ToString());
                        sidMapList.Add(new sidMap(objectID.ToString(), groupResult.Properties["samaccountname"][0].ToString(), currentDomain));
                    }


                }
            }
        }

        public static SearchResultCollection Get_Computers(DirectoryEntry adEntry, List<sidMap> sidMapList, List<string> allSids, string currentDomain, SearchResultCollection aclResults)
        {
            DirectorySearcher aclSearch = new DirectorySearcher(adEntry);
            aclSearch.Filter = "(&(samAccountType=805306369))";
            var Properties = new[] { "samaccountname", "ntsecuritydescriptor", "objectsid", "dnshostname" };
            aclSearch.PropertiesToLoad.AddRange(Properties);
            aclSearch.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
            aclSearch.SizeLimit = int.MaxValue;
            aclSearch.PageSize = int.MaxValue;
            SearchResult result;
            aclResults = aclSearch.FindAll();

            // Include the computer SIDs in allSids
            for (int counter = 0; counter < aclResults.Count; counter++)
            {
                result = aclResults[counter];
                var aclId = (byte[])result.Properties["objectsid"][0];
                var objectID = (new SecurityIdentifier(aclId, 0)).ToString();
                allSids.Add(objectID.ToString());
                sidMapList.Add(new sidMap(objectID.ToString(), result.Properties["samaccountname"][0].ToString(), currentDomain));

            }

            Console.WriteLine("There are {0} computers in {1}.", aclResults.Count, currentDomain);
            return aclResults;
        }

        public static void Get_RBCD_ACLs(List<SearchResult> resultList, List<rbcd> rbcdList, List<string> allSids, List<sidMap> sidMapList)
        {
            Console.WriteLine("Enumerate ACLs...");          
            Console.WriteLine("Checking for ACLs with RBCD...");
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
                            var objectSid = sidMapList.FirstOrDefault(o => o.ObjectSID == sid);
                            rbcdList.Add(new rbcd(objectSid.SamAccountName,objectSid.DomainName, hostname, "GenericAll"));

                        }
                    }
                    else if (adRule.ActiveDirectoryRights.ToString().Contains("GenericWrite"))
                    {
                        if (allSids.Contains(sid) && sid != computerSid)
                        {
                            var objectSid = sidMapList.FirstOrDefault(o => o.ObjectSID == sid);
                            rbcdList.Add(new rbcd(objectSid.SamAccountName, objectSid.DomainName, hostname, "GenericWrite"));
                        }
                    }
                    else if (adRule.ActiveDirectoryRights.ToString().Contains("WriteOwner"))
                    {
                        if (allSids.Contains(sid) && sid != computerSid)
                        {
                            var objectSid = sidMapList.FirstOrDefault(o => o.ObjectSID == sid);
                            rbcdList.Add(new rbcd(objectSid.SamAccountName, objectSid.DomainName, hostname, "WriteOwner"));
                        }
                    }

                }

            });
        }

        public static void Print_Acls(List<rbcd> rbcdList)
        {
            
            Console.WriteLine("Number of possible RBCD ACLs: " + rbcdList.Count);
            foreach (rbcd oneRbcd in rbcdList)
            {
                Console.WriteLine("RBCD ACL:\nSource: " + oneRbcd.Source + "\nSource Domain: " + oneRbcd.SourceDomain +"\nDestination: " + oneRbcd.Destination + "\nPrivilege: " + oneRbcd.Privilege + "\n");
            }
        }

        public static bool ExportCsv<T>(List<T> genericList, string fileName)
        {
            Console.WriteLine("Attempting to save file to " + fileName);
            var sb = new StringBuilder();
            var basePath = AppDomain.CurrentDomain.BaseDirectory;
            var finalPath = fileName;
            var header = "";
            var info = typeof(T).GetProperties();

            try
            {
                if (!File.Exists(finalPath))
                {
                    var file = File.Create(finalPath);
                    file.Close();
                    foreach (var prop in typeof(T).GetProperties())
                    {
                        header += prop.Name + ",";
                    }
                    header = header.Substring(0, header.Length - 1);
                    sb.AppendLine(header);
                    TextWriter sw = new StreamWriter(finalPath, true);
                    sw.Write(sb.ToString());
                    sw.Close();
                }
                else
                {
                    Console.WriteLine("File name already exists. Please choose another file path to write to.");
                    return false;
                }
                foreach (var obj in genericList)
                {
                    sb = new StringBuilder();
                    var line = "";
                    foreach (var prop in info)
                    {
                        line += prop.GetValue(obj, null) + ",";
                    }
                    line = line.Substring(0, line.Length - 1);
                    sb.AppendLine(line);
                    TextWriter sw = new StreamWriter(finalPath, true);
                    sw.Write(sb.ToString());
                    sw.Close();
                    
                }
                Console.WriteLine("File written to " + fileName);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
                return false;
            }
        }


    }
}
