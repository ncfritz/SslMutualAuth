package net.ncfritz.example.ssl;

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.OutputStreamWriter;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.cert.X509Certificate;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.OptionHandlerFilter;

import com.google.common.base.Strings;

/**
 * A simple Socket server that mutually authenticates client connections.
 */
public class Server {

    @Option(name = "--port", aliases = { "-p" }, required = false, usage = "The port to listen on")
    private int port = 1443;

    /**
     * Listens for connections and responds with the current timestamp.
     * 
     * @throws Exception
     *             if there were any problems accepting client connections.
     */
    public void listen() throws Exception {

        // Load the keystore containing our server certificate and the CA
        // certificate.
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("./src/main/resources/server.keystore"), "changeit".toCharArray());
        keyManagerFactory.init(keyStore, "changeit".toCharArray());

        // Now create a SSLContext, initialize it and grab a SSLServerSocket
        // from it.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket socket = (SSLServerSocket) socketFactory.createServerSocket(port);
        // Force client to authenticate. This is what requests that the client
        // send a client certificate
        // for authentication purposes.
        socket.setNeedClientAuth(true);

        while (true) {
            try {
                // Accept a connection and grab the SSLSession from it. The
                // session will have the client certificate
                // present.
                SSLSocket clientSocket = (SSLSocket) socket.accept();
                SSLSession session = clientSocket.getSession();

                System.out.println(String.format("Client connection from %s", clientSocket.getInetAddress()));

                // Grab the client's certificate chain. This will usually only
                // have a single certificate present.
                X509Certificate[] chain = session.getPeerCertificateChain();

                for (int i = 0; i < chain.length; i++) {
                    System.out.println(String.format("%s%s -> %s", Strings.repeat("  ", i + 1), chain[i].getSubjectDN(),
                            chain[i].getIssuerDN()));
                }

                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
                writer.write(String.format("%s\r\n", System.currentTimeMillis()));
                writer.flush();

                clientSocket.close();
            } catch (Exception e) {
                System.err.println(String.format("Unexpected error handling client connection: %s", e.getMessage()));
                e.printStackTrace(System.err);
            }
        }
    }

    public static void main(String... args) {

        // Install our own keystore to provide trusted certificates. This needs
        // to have both the server
        // certificate and the certificate of the CA/s that have signed client
        // certificates used to connect
        // to us. If we do not include the CA certificate we will not be able to
        // build a full trust chain
        // back to the CA and the client certificate will ultimately be
        // rejected.
        System.setProperty("javax.net.ssl.trustStore", "./src/main/resources/server.keystore");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        Server server = new Server();
        CmdLineParser parser = new CmdLineParser(server);

        try {
            parser.parseArgument(args);
            server.listen();
        } catch (CmdLineException e) {
            System.err.println(e.getMessage());
            System.err.println(String.format("java %s [options...] arguments...", Server.class.getSimpleName()));
            parser.printUsage(System.err);
            System.err.println();
            System.err.println(String.format("  Example: java %s %s", Server.class.getSimpleName(),
                    parser.printExample(OptionHandlerFilter.ALL)));
        } catch (Exception e) {
            System.err.println(String.format("Unexpected error during execution: %s", e.getMessage()));
            e.printStackTrace(System.err);
        }
    }
}
