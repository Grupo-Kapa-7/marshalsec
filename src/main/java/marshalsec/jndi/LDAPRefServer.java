/* MIT License

Copyright (c) 2017 Moritz Bechler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package marshalsec.jndi;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.net.HttpURLConnection;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Array;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
import java.util.regex.*;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.listener.LDAPListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import com.unboundid.ldap.listener.AccessLogRequestHandler;
import com.unboundid.ldap.listener.LDAPListenerRequestHandler;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Validator;

import java.util.ArrayList;

/**
 * LDAP server implementation returning JNDI references
 * 
 * @author mbechler
 *
 */
public class LDAPRefServer {

    private static class LDAPConn {
        public String connid;
        public String ipaddress;
        public String token;
    }

    private static final String LDAP_BASE = "dc=example,dc=com";
    public static List<LDAPConn> connections = new ArrayList<LDAPConn>();

    public static void main ( String[] args ) {
        int port = 1389;
        if ( args.length < 1 || args[ 0 ].indexOf('#') < 0 ) {
            System.err.println(LDAPRefServer.class.getSimpleName() + " <codebase_url#classname> [<port>]"); //$NON-NLS-1$
            System.exit(-1);
        }
        else if ( args.length > 1 ) {
            port = Integer.parseInt(args[ 1 ]);
        }

        try {
            customHandler handler = new customHandler();
            handler.setFormatter(new SimpleFormatter());
            handler.setLevel(Level.ALL);
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                "listen", //$NON-NLS-1$
                InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                port,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()));
            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            config.setAccessLogHandler(handler);
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class customHandler extends Handler {

        @Override
        public void close() throws SecurityException {
            
        }

        @Override
        public void flush() {
            
        }

        @Override
        public void publish(LogRecord arg0) {
            try
            {
                //System.out.println(arg0.getMessage());
                Pattern pattern = Pattern.compile("(CONNECT conn=)(\\d+) (from=\")(\\d+.\\d+.\\d+.\\d+)(.*)", Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(arg0.getMessage());
                boolean found = matcher.find();
                if(found)
                {
                    LDAPConn con = new LDAPConn();
                    con.connid = matcher.group(2);
                    con.ipaddress = matcher.group(4);
                    // System.out.println(con.connid);
                    // System.out.println(con.ipaddress);
                    connections.add(con);
                }

                Pattern pattern2 = Pattern.compile("(SEARCH REQUEST conn=)(\\d+) (.*)(base=\")(.*)(\" scope.*)");
                Matcher matcher2 = pattern2.matcher(arg0.getMessage());
                boolean found2 = matcher2.find();
                if(found2)
                {
                    // System.out.println(matcher2.group(2));
                    // System.out.println(matcher2.group(5));
                    connections.forEach((conn) -> {
                        // System.out.println(conn.connid);
                        if(conn.connid.equals(matcher2.group(2)))
                        {
                            conn.token = matcher2.group(5);
                            System.out.println("Matches connection ID: " + conn.connid + " with Token : " + conn.token + " with IP Address: " + conn.ipaddress);
                            //Hacer peticion a API de Threats para notificar que es vulnerable
                            try
                            {
                                URL url = new URL ("https://api.threats.kapa7.com/api/CVEChecks/cve_2021_44228");
                                HttpURLConnection con = (HttpURLConnection)url.openConnection();
                                con.setRequestMethod("POST");
                                con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                                con.setRequestProperty("Accept", "application/json");
                                con.setDoOutput(true);
                                String jsonInputString = "token=" + conn.token + "&ip=" + conn.ipaddress;
                                
                                OutputStreamWriter wr = new OutputStreamWriter(con.getOutputStream());
                                wr.write(jsonInputString);
                                wr.flush();
                                wr.close();

                                try(BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "utf-8"))) 
                                {
                                    StringBuilder response = new StringBuilder();
                                    String responseLine = null;
                                    while ((responseLine = br.readLine()) != null) {
                                        response.append(responseLine.trim());
                                    }
                                    System.out.println(response.toString());
                                }
                                catch(Exception ex)
                                {
                                    System.out.println(ex.getMessage());
                                }
                            }
                            catch(Exception ex)
                            {
                                System.out.println(ex.getMessage());
                            }
                                }
                            });

                }
            }
            catch(Exception ex)
            {
                //System.out.println(ex.getMessage());
            }
        }

    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        /**
         * 
         */
        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }


        /**
         * {@inheritDoc}
         *
         * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
         */
        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }

        }


        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            
            URL turl = new URL("https://threats.kapa7.com/assets/Log4jRCE.class");

            //System.out.println("Send LDAP reference result for token " + base + ", redirecting to " + turl);
            // e.addAttribute("javaClassName", "foo");
            // e.addAttribute("javaCodeBase", "https://threats.kapa7.com/assets/");
            // e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            // e.addAttribute("javaFactory", "Log4jRCE");
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }

    }
}
