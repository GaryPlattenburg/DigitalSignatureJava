
package dod.stig;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.*;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Hashtable;;

/**
 * Hello world!
 *
 */
public class App {

    public static void main(String[] args) {
        try {
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

            System.out.println("Hello World!");

            X509CertSelector selector = new X509CertSelector();
            // selector.setKeyUsage(X509Ke);
            // X509Certificate cert = selector.getCertificate();

            // Read Windows truststore
            KeyStore ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);

            Enumeration<String> aliases = ks.aliases();

            System.out.println("Certs:");

            Hashtable<Integer, String> certDictionary = new Hashtable<Integer, String>();

            int i = 0;
            for (String alias : Collections.list(aliases)) {
                Certificate cert = ks.getCertificate(alias);
                if (cert.getType() == "X.509") {
                    System.out.println(i + " = " + alias);

                    // ks.getKey(alias, null);
                    certDictionary.put(i++, alias);

                }

                // System.out.println(alias);
                // System.out.println(cert.getType());
            }
            // System.out.println("Choose a certificate");
            // String selected = console.readLine();

            // int intSelected = Integer.parseInt(selected);
            int intSelected = 4;

            String selectedCertAlias = certDictionary.get(intSelected);

            System.out.println("Selected cert = " + selectedCertAlias.toString());

            System.out.println("Enter data to hash");
            // String stringPayload = console.readLine();
            String stringPayload = "test data";

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(stringPayload.getBytes());

            Signature signature = Signature.getInstance("SHA256withRSA");
            PrivateKey pk = (PrivateKey) ks.getKey(selectedCertAlias, null);
            signature.initSign(pk);
            signature.update(digest.digest(), i, intSelected);

            byte[] signedData = signature.sign();

            System.out.println("Singed = " + signedData);

            System.out.println("Done!");

            
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
