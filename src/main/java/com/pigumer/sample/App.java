package com.pigumer.sample;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Iterator;

public class App {

    private PGPPublicKey readPublicKey() throws IOException, PGPException {
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("publickey.asc")) {
           return readPublicKey(is);
        }
    }

    private PGPPublicKey readPublicKey(InputStream var0) throws IOException, PGPException {
        PGPPublicKeyRingCollection var1 = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(var0), new JcaKeyFingerprintCalculator());
        Iterator var2 = var1.getKeyRings();

        while(var2.hasNext()) {
            PGPPublicKeyRing var3 = (PGPPublicKeyRing)var2.next();
            Iterator var4 = var3.getPublicKeys();

            while(var4.hasNext()) {
                PGPPublicKey var5 = (PGPPublicKey)var4.next();
                if (var5.isEncryptionKey()) {
                    return var5;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private void encryptFile(OutputStream outputStream, String inputFileName, PGPPublicKey publicKey, boolean withIntegrityPacket) throws IOException, NoSuchProviderException {
        try (OutputStream os = new ArmoredOutputStream((OutputStream) outputStream)) {
            PGPDataEncryptorBuilder builder = (new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256))
                    .setWithIntegrityPacket(withIntegrityPacket)
                    .setSecureRandom(new SecureRandom());
            PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(builder);
            generator.addMethod((new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)));
            try (OutputStream var6 = generator.open((OutputStream) os, new byte[65536])) {
                PGPCompressedDataGenerator var7 = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                PGPUtil.writeFileToLiteralData(var7.open(var6), 'b', new File(inputFileName), new byte[65536]);
                var7.close();
            }
        } catch (PGPException var8) {
            System.err.println(var8);
            if (var8.getUnderlyingException() != null) {
                var8.getUnderlyingException().printStackTrace();
            }
        }
    }

    public static void main(String[] ages) throws IOException, PGPException, NoSuchProviderException  {
        App app = new App();
        try (BufferedOutputStream output = new BufferedOutputStream(new FileOutputStream("target/demo.encrypted"))) {
            PGPPublicKey publicKey = app.readPublicKey();
            boolean withIntegrityPacket = true;
            app.encryptFile(output, "src/main/resources/demo.txt", publicKey, withIntegrityPacket);
        }
    }
}
