package net.ncfritz.example.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

/**
 * A client side {@link X509KeyManager} that delegates all function to an
 * existing {@link X509KeyManager} and will ALWAYS choose the configured client
 * alias when one is requested. This will force any request for mutually
 * authenticated SSL to respond with the certificate denoted by {@code alias}.
 */
public class ForcingKeyManager implements X509KeyManager {

    private X509KeyManager delegate;
    private String alias;

    /**
     * Creates a new {@code ForcingKeyManager} that will delegate all requests
     * to the delegate {link X509KeyManager} and respond to all requests for a
     * client alias with the configured {@code alias} value.
     * 
     * @param delegate
     *            the {@link X509KeyManager} to delegate to.
     * @param alias
     *            the name of the certificate to respond with.
     */
    public ForcingKeyManager(X509KeyManager delegate, String alias) {
        this.delegate = delegate;
        this.alias = alias;
    }

    /** {@inheritDoc} */
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    /** {@inheritDoc} */
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return delegate.chooseServerAlias(keyType, issuers, socket);
    }

    /** {@inheritDoc} */
    public X509Certificate[] getCertificateChain(String alias) {
        return delegate.getCertificateChain(alias);
    }

    /** {@inheritDoc} */
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return delegate.getClientAliases(keyType, issuers);
    }

    /** {@inheritDoc} */
    public PrivateKey getPrivateKey(String alias) {
        return delegate.getPrivateKey(alias);
    }

    /** {@inheritDoc} */
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return delegate.getServerAliases(keyType, issuers);
    }
}
