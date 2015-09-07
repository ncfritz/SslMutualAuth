package net.ncfritz.example.ssl;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.OptionHandlerFilter;

/**
 * A simple Socket client that authenticates to a server using mutual SSL
 * authentication.
 */
public class Client {

    @Option(name = "--port", aliases = { "-p" }, required = false, usage = "The port to connect to")
    private int port = 1443;

    @Option(name = "--alias", aliases = { "-a" }, required = false, usage = "The KeyStore alias to use for client auth")
    private String alias = "client";

    /**
     * Sends a request to the server and prints the response.
     * 
     * @throws Exception
     *             if there were any problems making the request.
     */
    public void send() throws Exception {

        // Get the KeyManagers and wrap them all in a ForcingKeyManager. The
        // KeyManagers are used when selecting certificates
        // to use for mutual authentication, so we only need to have the
        // client's certificate included. If the client certificate
        // was not self-signed we will also need to have the CA certificate that
        // signed our client present in the keystore we
        // load our certificates from.
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("./src/main/resources/client.keystore"), "changeit".toCharArray());
        keyManagerFactory.init(keyStore, "changeit".toCharArray());

        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        // There should really only be one X509KeyManager present. That should
        // be the KeyManager we created when we loaded our
        // keystore above. By definition there should only ever by one instance
        // of a given KeyManager implementation present.
        // If multiple are specified, only the first will be used.
        for (KeyManager keyManager : keyManagers) {
            System.out.println(String.format("Found KeyManager: %s", keyManager.getClass().getSimpleName()));

            if (keyManager instanceof X509KeyManager) {
                System.out.println("\tKeyManager is a X509KeyManager, wrapping in a ForcingKeyManager");

                keyManager = new ForcingKeyManager((X509KeyManager) keyManager, alias);
            }
        }

        // Create a SSLSocket. To do this we will create and initialize a
        // SSLContext. On init() we provide our wrapped set of
        // KeyManagers. The second argument takes TrustManager, which we do not
        // need as we have specified our TrustManager keystore
        // in our main() method. We could overrride these here though. The third
        // argument is a SecureRandom that we can specifically
        // configure and install. We don't for this example though.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, null, null);
        // Create the socket.
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        SSLSocket socket = (SSLSocket) socketFactory.createSocket();
        // For handshaking purposes, set this socket to client mode
        socket.setUseClientMode(true);
        socket.connect(new InetSocketAddress("localhost", port));

        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        System.out.println(String.format("\nServer >>> %s", reader.readLine()));
    }

    /**
     * Entry point.
     * 
     * @param args
     *            the command line arguments.
     */
    public static void main(String... args) {

        // Install our own keystore to provide trusted certificates. This needs
        // to have both the server
        // certificate and the certificate of the CA that signed our server
        // certificate. If we do not
        // include the CA certificate we will not be able to build a full trust
        // chain back to the CA and
        // the server certificate will ultimately be rejected.
        System.setProperty("javax.net.ssl.trustStore", "./src/main/resources/client.keystore");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        Client client = new Client();
        CmdLineParser parser = new CmdLineParser(client);

        try {
            parser.parseArgument(args);
            client.send();
        } catch (CmdLineException e) {
            System.err.println(e.getMessage());
            System.err.println(String.format("java %s [options...] arguments...", Client.class.getSimpleName()));
            parser.printUsage(System.err);
            System.err.println();
            System.err.println(String.format("  Example: java %s %s", Client.class.getSimpleName(),
                    parser.printExample(OptionHandlerFilter.ALL)));
        } catch (Exception e) {
            System.err.println(String.format("Unexpected error during execution: %s", e.getMessage()));
            e.printStackTrace(System.err);
        }
    }
}
