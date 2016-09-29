package sss.iohk.hoop


import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.{SigmaDJProductCommonInput, SigmaDJProductProverInput}
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText
import org.scalacheck.Gen
import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}

import scala.util.Random

/**
  * Created by alan on 9/27/16.
  */
class DamgardJurikEncryptionSpec extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers {

  val oneThousandInts = for (n <- Gen.choose(1, 10000)) yield n

  property("DamgardJurikEncryption verifies encrypted products") {

    val sut = new DamgardJurikEncryption

    forAll (oneThousandInts, oneThousandInts, minSuccessful(10)){ (A: Int, B: Int) => {
      whenever(A > 0 && B > 0) {
        val r1: BigInt = Random.nextInt(1000)
        val r2: BigInt = Random.nextInt(1000)
        val r3: BigInt = Random.nextInt(1000)
        val goodProduct = BigInt(A * B)

        val x1: BigIntegerPlainText = new BigIntegerPlainText(BigInt(A).bigInteger)
        val x2: BigIntegerPlainText = new BigIntegerPlainText(BigInt(B).bigInteger)

        val c_A = sut.encrypt(BigInt(A).bigInteger, r1.bigInteger)
        val c_B = sut.encrypt(BigInt(B).bigInteger, r2.bigInteger)
        val c_C = sut.encrypt(goodProduct.bigInteger, r3.bigInteger)

        val proverComputation = sut.createProverComputation()
        val input = new SigmaDJProductProverInput(sut.getPublic,
          c_A, c_B, c_C, r1.bigInteger, r2.bigInteger, r3.bigInteger, x1, x2)

        val verifier = sut.createVerifierComputation()
        val commonInput = new SigmaDJProductCommonInput(sut.getPublic, c_A, c_B, c_C)

        verifier.sampleChallenge()
        val e = verifier.getChallenge
        val a = proverComputation.computeFirstMsg(input)
        val z = proverComputation.computeSecondMsg(e)

        assert(verifier.verify(commonInput, a, z), "Verify is false for good inputs!")
      }
      }
    }
  }

  property("DamgardJurikEncryption fails to verify badly encrypted products") {

    val sut = new DamgardJurikEncryption

    forAll (oneThousandInts, oneThousandInts, minSuccessful(10)){ (A: Int, B: Int) => {
      whenever(A > 0 && B > 0) {
        val r1: BigInt = Random.nextInt(1000)
        val r2: BigInt = Random.nextInt(1000)
        val r3: BigInt = Random.nextInt(1000)
        val goodProduct = BigInt(A * B)
        val badProduct = goodProduct + 1

        val x1: BigIntegerPlainText = new BigIntegerPlainText(BigInt(A).bigInteger)
        val x2: BigIntegerPlainText = new BigIntegerPlainText(BigInt(B).bigInteger)

        val c_A = sut.encrypt(BigInt(A).bigInteger, r1.bigInteger)
        val c_B = sut.encrypt(BigInt(B).bigInteger, r2.bigInteger)
        val c_C = sut.encrypt(badProduct.bigInteger, r3.bigInteger)


        val proverComputation = sut.createProverComputation()

        val badInput = new SigmaDJProductProverInput(sut.getPublic,
          c_A, c_B, c_C,
          r1.bigInteger, r2.bigInteger, r3.bigInteger, x1, x2)

        val verifier = sut.createVerifierComputation()

        val badCommonInput = new SigmaDJProductCommonInput(sut.getPublic, c_A, c_B, c_C)

        verifier.sampleChallenge()
        val e = verifier.getChallenge
        val a = proverComputation.computeFirstMsg(badInput)
        val z = proverComputation.computeSecondMsg(e)

        assert(!verifier.verify(badCommonInput, a, z), "Verify is true for bad inputs!")
      }
    }
    }
  }
}
