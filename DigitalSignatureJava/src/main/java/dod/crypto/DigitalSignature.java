package dod.crypto;

import java.io.BufferedReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;

import org.apache.pdfbox.util.Hex;

public class DigitalSignature {

    public void DigitalSignatureTests(BufferedReader console) throws Exception {
        // Read Windows truststore
        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        Hashtable<Integer, String> certDictionary = listCerts(ks);

        String selectedCertAlias = selectACert(certDictionary);
        System.out.println("Selected cert = " + selectedCertAlias.toString());

        System.out.println("Enter data to hash");
        String stringPayload = console.readLine();
        // String stringPayload = "test data";

        byte[] signedData = signData(stringPayload, ks, selectedCertAlias);
        String encodeSignedData = Hex.getString(signedData);
        System.out.println("Signed = " + encodeSignedData);

        byte[] decodedSignedData = Hex.decodeHex(encodeSignedData);
        boolean verifiedPublic = verifyData(stringPayload, decodedSignedData, ks, selectedCertAlias);
        System.out.println("Valid = " + verifiedPublic);
   }

   private boolean verifyData(String stringPayload, byte[] signedData, KeyStore ks, String selectedCertAlias)
            throws Exception {

        byte[] data = stringPayload.getBytes();

        Signature signature = Signature.getInstance("SHA256withRSA");
        PublicKey publicKey = ks.getCertificate(selectedCertAlias).getPublicKey();
        signature.initVerify(publicKey);
        signature.update(data);

        boolean valid = signature.verify(signedData);

        return valid;
    }

    private byte[] signData(String stringPayload, KeyStore ks, String selectedCertAlias) throws Exception {

        byte[] data = stringPayload.getBytes();

        Signature signature = Signature.getInstance("SHA256withRSA");
        PrivateKey privateKey = (PrivateKey) ks.getKey(selectedCertAlias, null);
        signature.initSign(privateKey);
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

    public Hashtable<Integer, String> listCerts(KeyStore ks) throws Exception {
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
