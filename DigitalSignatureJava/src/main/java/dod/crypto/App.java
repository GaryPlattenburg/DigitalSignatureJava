
package dod.crypto;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class App {

    public static void main(String[] args) {
        try {
            BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

            DigitalSignature ds = new DigitalSignature();
           ds.DigitalSignatureTests(console);

           PdfSignature ps = new PdfSignature();
           ps.PdfTests(console);

            System.out.println("Done!");
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    

    

    
}
