
package dod.stig;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
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

            // Read Windows truststore
            KeyStore ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);

            Hashtable<Integer, String> certDictionary = listCerts(ks);

            String selectedCertAlias = selectACert(certDictionary);
            System.out.println("Selected cert = " + selectedCertAlias.toString());

            System.out.println("Enter data to hash");
            // String stringPayload = console.readLine();
            String stringPayload = "test data";

            byte[] signedData = signData(stringPayload, ks, selectedCertAlias);
            System.out.println("Singed = " + signedData);

            boolean verifiedPublic = verifyData(stringPayload, signedData, ks, selectedCertAlias);
            System.out.println("Valid = " + verifiedPublic);

            System.out.println("Done!");
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private static boolean verifyData(String stringPayload, byte[] signedData, KeyStore ks, String selectedCertAlias)
            throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(stringPayload.getBytes());
        byte[] data = digest.digest();

        Signature signature = Signature.getInstance("SHA256withRSA");
        PublicKey pk = ks.getCertificate(selectedCertAlias).getPublicKey();
        signature.initVerify(pk);
        signature.update(data);
        signature.verify(signedData);

        boolean valid = signature.verify(signedData);

        return valid;
    }

    private static byte[] signData(String stringPayload, KeyStore ks, String selectedCertAlias) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(stringPayload.getBytes());
        byte[] data = digest.digest();

//         DigestAlgorithmIdentifierFinder hashAlgorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
// AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find("SHA-256");
// DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, messageHash);
// byte[] hashToEncrypt = digestInfo.getEncoded();

        Signature signature = Signature.getInstance("SHA256withRSA");
        PrivateKey pk = (PrivateKey) ks.getKey(selectedCertAlias, null);
        signature.initSign(pk);
        signature.update(data);

        byte[] signedData = signature.sign();

        return signedData;
    }

    private static String selectACert(Hashtable<Integer, String> certDictionary) {
        // System.out.println("Choose a certificate");
        // String selected = console.readLine();

        // int intSelected = Integer.parseInt(selected);
        int intSelected = 4;

        String selectedCertAlias = certDictionary.get(intSelected);

        return selectedCertAlias;
    }

    public static Hashtable<Integer, String> listCerts(KeyStore ks) throws Exception {
        Hashtable<Integer, String> certDictionary = new Hashtable<Integer, String>();

        Enumeration<String> aliases = ks.aliases();
        System.out.println("Certs:");

        int i = 0;
        for (String alias : Collections.list(aliases)) {
            Certificate cert = ks.getCertificate(alias);
            if (cert.getType() == "X.509") {
                System.out.println(i + " = " + alias);

                certDictionary.put(i++, alias);
            }
        }

        return certDictionary;
    }
}
