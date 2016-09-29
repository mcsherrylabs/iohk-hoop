package sss.iohk.hoop

import akka.actor._
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.{SigmaDJProductCommonInput, SigmaDJProductVerifierComputation}
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext
import sss.iohk.hoop.environment.EnvironmentActor._

import scala.language.postfixOps
import scala.util.Random


/**
  * Created by alan on 9/27/16.
  */
class UserActor(userIdentifier: Identifier,
                publicRepository: Map[Identifier, DamgardJurikPublicKey],
                encryptor: DamgardJurikEncryption,
                environment: ActorRef) extends Actor {

  private var c_Bob: BigIntegerCiphertext = _
  private var c_Alice: BigIntegerCiphertext = _
  private var c_Product: BigIntegerCiphertext = _

  private def verifying(brokerRef: ActorRef, verifierComputation: SigmaDJProductVerifierComputation,
                        commonInput: SigmaDJProductCommonInput): Receive = {

    case BeginVerification =>
          verifierComputation.sampleChallenge()
          // get challenge from verifier
          val e = verifierComputation.getChallenge
          brokerRef ! VerifierChallenge(e)

    case ProverResponse(a: SigmaProtocolMsg, z: SigmaProtocolMsg) =>
      val verified = verifierComputation.verify(commonInput, a, z)
      environment ! VerificationResult(userIdentifier, verified)

  }

  private def encrypting(brokerRef: ActorRef): Receive = {
    case BigIntForEncryption(aBigInt) =>
      val cipherForBrokerDecrypt = encryptor.encrypt(publicRepository(BrokerCarol), aBigInt.bigInteger)
      val rnd = Random.nextInt(1000)
      val cipher = encryptor.encrypt(publicRepository(BrokerCarol), aBigInt.bigInteger, BigInt(rnd).bigInteger)
      if(userIdentifier == Bob) c_Bob = cipher else c_Alice = cipher
      brokerRef ! DamgardJurikEncryptedNumWithRnd(userIdentifier, cipherForBrokerDecrypt, cipher, BigInt(rnd))


    case DamgardJurikEncryptedNum(BrokerCarol, encryptedProduct) =>
      environment ! WriteMsg(s"$userIdentifier has received ${encryptedProduct.toString.substring(0,35)}... from Carol")
      c_Product = encryptedProduct
      val verifierComputation = encryptor.createVerifierComputation()
      val commonInput: SigmaDJProductCommonInput =
        new SigmaDJProductCommonInput(publicRepository(BrokerCarol), c_Bob, c_Alice, c_Product)
      context.become(init orElse verifying(brokerRef, verifierComputation, commonInput))
      environment ! ReadyToVerify(userIdentifier)

    case DamgardJurikEncryptedNum(Bob, bobsEncNumber) if(userIdentifier == Bob) =>
        assert(bobsEncNumber.equals(c_Bob), "Encrypted distribtion from broker not same as originally calculated locally")

    case DamgardJurikEncryptedNum(Bob, bobsEncNumber) => c_Bob = bobsEncNumber

    case DamgardJurikEncryptedNum(Alice, aliceEncNumber) if(userIdentifier == Alice) =>
      assert(aliceEncNumber.equals(c_Alice), "Encrypted distribtion from broker not same as originally calculated locally")

    case DamgardJurikEncryptedNum(Alice, aliceEncNumber) => c_Alice = aliceEncNumber
  }

  private def init: Receive = {
    case GetDamgardJurikEncryptedNum =>
      environment ! GetBigIntForEncryption(s"Enter number for $userIdentifier")
      context.become(init orElse encrypting(sender()))
  }

  override def receive: Receive = init
}
