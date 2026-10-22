package org.ifad.portal.httpsclienttest;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

/** Requests HTTPS URLs and reports whether the current JVM accepts their certificate chains. */
public final class HttpsClientTest {
    private HttpsClientTest() {
    }

    public static void main(String[] args) {
        if (args.length == 0 || (args.length == 1 && ("--help".equals(args[0]) || "-h".equals(args[0])))) {
            System.out.println("Usage: java -jar IFADHttpsClientTest.jar https-url [https-url ...]");
            System.out.println("Exit: 0 = all certificates rejected, 1 = one or more trusted, 2 = connection/usage error.");
            if (args.length == 0) {
                System.exit(2);
            }
            return;
        }

        String[] urls = args;
        boolean trusted = false;
        boolean error = false;
        if ("1.7".equals(System.getProperty("java.specification.version"))) {
            // Java 7 supports TLS 1.2 but does not enable it by default for HTTPS.
            System.setProperty("https.protocols", "TLSv1.2");
        }
        System.out.println("Java: " + System.getProperty("java.runtime.version")
                + " (" + System.getProperty("java.vendor") + ")");

        for (String address : urls) {
            HttpsURLConnection connection = null;
            try {
                URL url = new URL(address);
                if (!"https".equalsIgnoreCase(url.getProtocol())) {
                    throw new IllegalArgumentException("HTTPS URL required");
                }
                connection = (HttpsURLConnection) url.openConnection();
                connection.setConnectTimeout(10000);
                connection.setReadTimeout(10000);
                connection.setInstanceFollowRedirects(false);
                int status = connection.getResponseCode();
                System.out.println("TRUSTED  " + address + " (HTTP " + status + ")");
                trusted = true;
            } catch (IOException e) {
                if (isCertificateFailure(e)) {
                    System.out.println("REJECTED " + address + " (" + e.getMessage() + ")");
                } else {
                    System.out.println("ERROR    " + address + " (" + e + ")");
                    error = true;
                }
            } catch (IllegalArgumentException e) {
                System.out.println("ERROR    " + address + " (" + e.getMessage() + ")");
                error = true;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }

        if (trusted) {
            System.err.println("At least one compromised certificate chain was trusted.");
            System.exit(1);
        }
        if (error) {
            System.err.println("At least one check could not be completed.");
            System.exit(2);
        }
        System.out.println("All certificate chains were rejected by this JVM.");
    }

    private static boolean isCertificateFailure(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof CertificateException || cause instanceof SSLPeerUnverifiedException) {
                return true;
            }
        }
        return false;
    }
}
