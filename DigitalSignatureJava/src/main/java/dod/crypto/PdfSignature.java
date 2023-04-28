package dod.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.security.KeyStore;

import dod.crypto.signature.CreateVisibleSignature2;

import java.awt.geom.Rectangle2D;

public class PdfSignature {

    public void MakePdfDigitalSignature(BufferedReader console) throws Exception {
        //References to the Windows Keystore
        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        //The inputfile and the output filename
        File inputFile = new File("samples\\in\\NascarSample.pdf");
        File signedFile = new File("samples\\out\\NascarSample_signed.pdf");

        //The visibility of the signature can be further customized, but this is a basic one
        Rectangle2D humanRect = new Rectangle2D.Float(100, 100, 300, 100);

        //This is some custom code that reads the cert store and list them to the concole
        //Then the user is prompted to select a specific one
        DigitalSignature ds = new DigitalSignature();
        String alias = ds.SelectACert(ks, console);

        //Reads in the PDF and adds a digital signature and saves it to the output
        CreateVisibleSignature2 cvs = new CreateVisibleSignature2(ks, null, alias);

        File bgImage = new File("samples\\in\\NavsupLogo2.gif");
        cvs.setImageFile(bgImage);

        NotarySignatureOveride nso = new NotarySignatureOveride();
        nso.Name = "Gary's CAC as the Noatary";
        nso.OnBehalfOf = "John F. Doe #123324324";
        nso.Reason = "Gary Notarized This";

        cvs.signPDF(inputFile, signedFile, humanRect, null, "Gary Was Here", nso);
    }
}
