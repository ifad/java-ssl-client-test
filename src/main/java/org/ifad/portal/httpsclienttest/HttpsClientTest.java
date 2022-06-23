package org.ifad.portal.httpsclienttest;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class HttpsClientTest {

    public static void main(String[] argo) {
        if (argo.length < 1) {
            System.out.println("The first parameter should be the tested URL");
            return;
        }

        String urlParam = argo[0];

        try {
            URL url = new URL(urlParam);

            new HttpsClientTest().testTLS12(url);

        } catch (MalformedURLException e) {
            System.out.println("Malformed URL exception: '" + urlParam + "'");
        } catch (IOException e) {
            System.out.println("Something went wrong when processing the URL '" + urlParam + "'");
            e.printStackTrace();
        }
    }

    void testTLS12(URL url) throws IOException {
        URLConnection con = url.openConnection();

        if (con instanceof HttpsURLConnection) {
            System.out.println("Checking the URL: " + url);

            System.setProperty("jdk.tls.client.protocols", "TLSv1.2");

            disableSslVerification();

            printHttpsCert((HttpsURLConnection) con);
        } else {
            System.out.println("The URL " + url + " is not HTTPS, skipping...");
        }
    }

    private void printHttpsCert(HttpsURLConnection con) throws IOException {
        System.out.println("Response Code : " + con.getResponseCode());
        System.out.println("Cipher Suite : " + con.getCipherSuite());
        System.out.println();

        for (Certificate cert : con.getServerCertificates()) {
            System.out.println("Cert Type : " + cert.getType());
            System.out.println("Cert Hash Code : " + cert.hashCode());
            System.out.println("Cert Public Key Algorithm : "
                    + cert.getPublicKey().getAlgorithm());
            System.out.println("Cert Public Key Format : "
                    + cert.getPublicKey().getFormat());
            System.out.println();
        }
    }

    void disableSslVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
            };

            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
    }
}