package dod.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.security.KeyStore;

import dod.crypto.signature.CreateVisibleSignature2;

import java.awt.geom.Rectangle2D;

public class PdfSignature {

    public void PdfTests(BufferedReader console) throws Exception {
        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        File inputFile = new File("samples\\in\\NascarSample.pdf");

        File signedFile = new File("samples\\out\\NascarSample_x.pdf");

        Rectangle2D humanRect = new Rectangle2D.Float(100, 100, 200, 100);

        DigitalSignature ds = new DigitalSignature();
        String alias = ds.SelectACert(ks, console);

        CreateVisibleSignature2 cvs = new CreateVisibleSignature2(ks, null, alias);
        cvs.signPDF(inputFile, signedFile, humanRect, null, "Gary Was Here");
    }
}
