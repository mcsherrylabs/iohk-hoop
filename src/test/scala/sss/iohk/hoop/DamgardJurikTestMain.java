package sss.iohk.hoop;

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.SigmaDJProductCommonInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.SigmaDJProductProverComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.SigmaDJProductProverInput;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.SigmaDJProductVerifierComputation;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg;
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProverInput;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.DJKeyGenParameterSpec;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.DamgardJurikEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScDamgardJurikEnc;
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey;
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext;
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText;
import edu.biu.scapi.midLayer.plaintext.Plaintext;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;

/**
 * This class is where I find out how the DamgardJurik encryptor works
 * It's the quickest way to experiment and so I'll leave it for reference.
 *
 */
public class DamgardJurikTestMain {

    public static void main(String[] args) throws Exception {

        int lengthParameter = 9;
        SecureRandom secRand = new SecureRandom();
        DamgardJurikEnc encryptor = new ScDamgardJurikEnc(secRand);
        DamgardJurikEnc encryptor2 = new ScDamgardJurikEnc(secRand);
        encryptor.setLengthParameter(lengthParameter);

        KeyPair pair = encryptor.generateKey(new DJKeyGenParameterSpec(128, 40));
        KeyPair pair2 = encryptor2.generateKey(new DJKeyGenParameterSpec(128, 40));
        DamgardJurikPublicKey pKey = (DamgardJurikPublicKey) pair.getPublic();
        DamgardJurikPublicKey pKey2 = (DamgardJurikPublicKey) pair2.getPublic();
        encryptor.setKey(pair.getPublic(), pair.getPrivate());
        encryptor2.setKey(pair2.getPublic(), pair2.getPrivate());


        String num_a = "2";
        String num_b = "44";
        String num_c = "88";

        BigIntegerPlainText x1 = new BigIntegerPlainText(new BigInteger(num_a));
        BigIntegerPlainText x2 = new BigIntegerPlainText(new BigInteger(num_b));
        BigIntegerPlainText x3 = new BigIntegerPlainText(new BigInteger(num_c));

        BigInteger r1 = new BigInteger("108");
        BigInteger r2 = new BigInteger("208");
        BigInteger r3 = new BigInteger("2008");

        encryptor.setKey(pair2.getPublic());
        BigIntegerCiphertext num_a_enc = (BigIntegerCiphertext) encryptor.encrypt(x1, r1);
        BigIntegerCiphertext num_b_enc = (BigIntegerCiphertext) encryptor.encrypt(x2, r2);
        BigIntegerCiphertext num_c_enc = (BigIntegerCiphertext) encryptor.encrypt(x3, r3);

        //Plaintext decrypted_2 = encryptor.decrypt(num_a_enc);
        //Plaintext decrypted_44 = encryptor.decrypt(num_b_enc);
        //Plaintext decrypted_88 = encryptor.decrypt(num_b_enc);

        int t = (pKey.getModulus().bitLength() / 3) - 1;

        //Creates sigma prover computation.

        SigmaProverComputation proverComputation = new SigmaDJProductProverComputation(t, lengthParameter, secRand);
        //Creates input for the prover.
        //SigmaProverInput input = new SigmaDJProductProverInput(pKey, num_a_enc, num_b_enc, num_c_enc, (DamgardJurikPrivateKey) pair.getPrivate(), x1, x2);
        SigmaProverInput input = new SigmaDJProductProverInput(pKey2,
                num_a_enc, num_b_enc, num_c_enc,
                r1, r2,r3, x1, x2
        );


        //Creates sigma verifier computation.
        SigmaDJProductVerifierComputation verifierComputation = new SigmaDJProductVerifierComputation(t, lengthParameter, secRand);

        SigmaDJProductCommonInput commonInput = new SigmaDJProductCommonInput(pKey2, num_a_enc, num_b_enc, num_c_enc);

        for(int i = 0; i< 10; i++) {

            // send a to verifier
            verifierComputation.sampleChallenge();
            // get challenge from verifier
            byte[] e = verifierComputation.getChallenge();

            SigmaProtocolMsg a = proverComputation.computeFirstMsg(input);
            //Compute the second message by the underlying proverComputation.
            SigmaProtocolMsg z = proverComputation.computeSecondMsg(e);

            boolean verified = verifierComputation.verify(commonInput, a, z);

            System.out.println("Verified? " + verified);
        }

    }

}