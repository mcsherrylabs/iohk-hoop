package sss.iohk.hoop;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.SigmaDJProductProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.SigmaDJProductVerifierComputation;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.DJKeyGenParameterSpec;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.DamgardJurikEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScDamgardJurikEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertext;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Created by alan on 9/26/16.
 */
public class DamgardJurikEncryption {

    final private int lengthParameter = 9;
    final private SecureRandom secRand = new SecureRandom();
    final private DamgardJurikEnc encryptor = new ScDamgardJurikEnc(secRand);
    private int t;
    private KeyPair pair;

    public SigmaDJProductVerifierComputation createVerifierComputation() {
        return new SigmaDJProductVerifierComputation(t, lengthParameter, secRand);
    }

    public SigmaProverComputation createProverComputation() {
        return new SigmaDJProductProverComputation(t, lengthParameter, secRand);
    }

    public DamgardJurikPublicKey getPublic() {
        return (DamgardJurikPublicKey)pair.getPublic();
    }


    public DamgardJurikEncryption() throws Exception {
        encryptor.setLengthParameter(lengthParameter);
        pair = encryptor.generateKey(new DJKeyGenParameterSpec(128, 40));
        encryptor.setKey(pair.getPublic(), pair.getPrivate());
        t = (getPublic().getModulus().bitLength() / 3) - 1;
    }

    public BigIntegerCiphertext encrypt(BigInteger toBeEncrypted, BigInteger randomNumber) throws Exception {
        return (BigIntegerCiphertext)encryptor.encrypt(new BigIntegerPlainText(toBeEncrypted), randomNumber);
    }

    public BigIntegerCiphertext encrypt(PublicKey pub, BigInteger num) throws Exception {
        encryptor.setKey(pub);
        BigIntegerPlainText plaintext = new BigIntegerPlainText(num);
        return (BigIntegerCiphertext)encryptor.encrypt(plaintext);
    }

    public BigIntegerPlainText decrypt(AsymmetricCiphertext cipher) throws Exception {
        encryptor.setKey(pair.getPublic(), pair.getPrivate());
        BigIntegerPlainText recoveredplaintext = (BigIntegerPlainText)encryptor.decrypt(cipher);
        return recoveredplaintext;
    }

}
