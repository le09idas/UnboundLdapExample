import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.migrate.ldapjdk.LDAPSearchResults;
import com.unboundid.ldap.sdk.migrate.ldapjdk.LDAPEntry;
import com.unboundid.ldap.sdk.migrate.ldapjdk.LDAPAttributeSet;
import com.unboundid.ldap.sdk.migrate.ldapjdk.LDAPAttribute;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.SynchronizedSSLSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.ResultCode;
import javax.net.ssl.SSLContext;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.LDAPTestUtils;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import java.io.FileInputStream;
import java.lang.StringBuilder;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.BasicAsyncSearchResultListener;
import java.nio.file.Files;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.io.BufferedWriter;
import java.util.HashMap;

class LDAP_Diff
{

    static int activated = 0;
    static int deactivated = 0;
    static int migrated = 0;
    static int unmigrated = 0;
    static int entry = 0;
    static int noPassword = 0;

    public static String getPasswordFromFile(String path)
    {
        StringBuilder builder = new StringBuilder();
        int character;
        String pass = "";
        try 
        {
            FileInputStream inputStream = new FileInputStream(path);
            while((character = inputStream.read()) != -1)
            {
                    builder.append((char)character);
            }
            pass = builder.toString();
        } 
        catch(Exception e) 
        {
            System.out.println("Error reading file: " + e.getMessage());
            pass = "";
        }
        return pass; 
    }

    public static LDAPConnection startConnectionSSL(String hostname, int port, String bindDN, String password)
    {
        LDAPConnection connection;

        try 
        {
            SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
            SSLSocketFactory socketFactory = sslUtil.createSSLSocketFactory();
            connection = new LDAPConnection(socketFactory,hostname, port, bindDN, password);
        } 
        catch (Exception e) 
        {
            System.out.println("Cannot connect to DS server: " + e.getMessage());
            connection = null;
        }

        return connection;
    }

    public static LDAPConnection startConnectionTLS(String hostname, int port, String bindDN, String password)
    {
        LDAPConnection connection;
        ExtendedResult startTLSResult;
       
        try
        {
            connection = new LDAPConnection(hostname, port, bindDN, password); //, bindDN, password);
        }
        catch (Exception e)
        {
            System.out.println("Cannot connect to DS server: " + e.getMessage());
            connection = null;
        }
        
        
        try
        {
            // Process operations using the connection....
            SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
            SSLContext sslContext = sslUtil.createSSLContext();
            StartTLSExtendedRequest startTLSRequest = new StartTLSExtendedRequest(sslContext);
            startTLSResult = connection.processExtendedOperation(startTLSRequest);
            LDAPTestUtils.assertResultCodeEquals(startTLSResult, ResultCode.SUCCESS);
            
        }
        catch (LDAPException le)
        {
            startTLSResult = new ExtendedResult(le);
        }
        catch (Exception e)
        {
            System.out.println("Something went wrong: " + e.getMessage());
        }

        return connection;
    }

    public static HashMap<String, SearchResultEntry> listToMap(List<SearchResultEntry> list)
    {
        HashMap<String, SearchResultEntry> map = new HashMap<String, SearchResultEntry>();
        for(SearchResultEntry e: list)
        {
            map.put(e.getAttributeValue("uid"), e);
        }
        return map;
    }

    public static void main(String args[])
    {
        System.out.println("Starting LDAP Diff program");
        
        // Establish secure connections to the servers.
        LDAPConnection connectionTLS = startConnectionTLS("", 389, "", getPasswordFromFile(".pwd"));
        LDAPConnection connectionSSL = startConnectionSSL("", 636, "", getPasswordFromFile(".pwd"));

        try 
        {
            RootDSE rootDSETLS = connectionTLS.getRootDSE();
            RootDSE rootDSESSL = connectionSSL.getRootDSE();
            System.out.println(rootDSETLS.getNamingContextDNs()[0]);
            System.out.println(rootDSESSL.getNamingContextDNs()[0]);
            
            SearchResult searchResultTLS = connectionTLS.search(rootDSETLS.getNamingContextDNs()[0], SearchScope.SUB, "&(uid=*)", "uid", "obuseraccountcontrol", "userpassword");
            System.out.println(searchResultTLS.getEntryCount() + " entries returned.");
            SearchResult searchResultSSL = connectionSSL.search(rootDSESSL.getNamingContextDNs()[0], SearchScope.SUB, "&(uid=*)", "uid", "obuseraccountcontrol", "userpasswprd");
            System.out.println(searchResultSSL.getEntryCount() + " entries returned.");
            
            HashMap<String, SearchResultEntry> oldLDAPServerEntries = listToMap(searchResultTLS.getSearchEntries());
            HashMap<String, SearchResultEntry> newLDAPServerEntries = listToMap(searchResultSSL.getSearchEntries());

            connectionTLS.close();
            connectionSSL.close(); 
            
            PrintWriter writerActive = new PrintWriter("ActivateUsersMigratedToOpenDJ.txt");
            PrintWriter writerDeactivated = new PrintWriter("ActveUsersNotMigratedToOpenDJ.txt");
            PrintWriter writerNoPassword = new PrintWriter("UnmigratedPassword.txt");

            oldLDAPServerEntries.forEach((k,v) -> 
            {
                String toWrite = k;
                
                if(v.getAttributeValue("obuseraccountcontrol") != null && v.getAttributeValue("obuseraccountcontrol").compareToIgnoreCase("ACTIVATED") == 0)
                {
            
                    if(newLDAPServerEntries.containsKey(k))
                    {
                        writerActive.write(toWrite + "\n");
                        toWrite = toWrite.concat(" is migrated to OpenDJ ");
                        migrated++;

                        if(newLDAPServerEntries.get(k).getAttributeValue("userpassword") == null)
                        {
                            writerNoPassword.write(k + "\n");
                            toWrite = toWrite.concat(" has no migrated password in OpenDJ");
                            noPassword++;
                        }
                        
                    }
                    else
                    {
                        writerDeactivated.write(toWrite);
                        toWrite = toWrite.concat(" is not migrated to OpenDJ");
                        unmigrated++;
                    }
                    activated++;
                }
                else
                {
                    deactivated++;
                }

                System.out.println(toWrite);
                entry++;

                if(entry % 10000 == 0)
                {
                    writerActive.flush();
                    writerDeactivated.flush();
                    writerNoPassword.flush();
                }
                
            });

            writerActive.close();
            writerDeactivated.close();
            writerNoPassword.close();

            System.out.println("There were " + Integer.toString(activated) + " active users in Old LDAP Server.");
            System.out.println("There were " + Integer.toString(deactivated) + " deactivated users in OldLDAP Server.");
            System.out.println(Integer.toString(migrated) + " users have been migrated to New LDAP Server.");
            System.out.println(Integer.toString(unmigrated) + " users have not migrated to New LDAP Server.");
            System.out.println(Integer.toString(noPassword) + " users have unmigrated passwords.");
        } 
        catch (Exception e) 
        {
           System.out.println("Could not carry out procedure: " + e.getMessage());
        }
     
        System.out.println("Ending LDAP Diff program");

    }

}