package sss.iohk.hoop

import akka.actor.{Actor, ActorLogging, ActorRef}
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.SigmaProverComputation
import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct.SigmaDJProductProverInput
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText
import sss.iohk.hoop.environment.EnvironmentActor._

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration
import scala.language.postfixOps
import scala.util.Random

/**
  * Created by alan on 9/27/16.
  */
class BrokerCarolActor(publicKeyRepository: Map[Identifier, DamgardJurikPublicKey],
                       encryptor: DamgardJurikEncryption,
                       environment: ActorRef,
                       bobRef: ActorRef,
                       aliceRef: ActorRef,
                       timeout: FiniteDuration) extends Actor with ActorLogging {


  private def waiting(bufferedEncNumberOpt: Option[DamgardJurikEncryptedNumWithRnd]): Receive = {
    case TooSlow =>
      environment ! ProtocolAborted
      context.become(receive)

    case anotherEncryptedNumber @ DamgardJurikEncryptedNumWithRnd(userIdentifier, _,  cipher, _) =>

      bufferedEncNumberOpt match {
        case None => context.become(waiting(Some(anotherEncryptedNumber)))
        case Some(bufferedEncNumber) =>
          assert(bufferedEncNumber.userIdentifier != userIdentifier,
            s"Received 2 encrypted numbers from same id $userIdentifier")

          aliceRef ! DamgardJurikEncryptedNum(userIdentifier, cipher)
          aliceRef ! DamgardJurikEncryptedNum(bufferedEncNumber.userIdentifier, bufferedEncNumber.randNumCipher)
          bobRef ! DamgardJurikEncryptedNum(userIdentifier, cipher)
          bobRef ! DamgardJurikEncryptedNum(bufferedEncNumber.userIdentifier, bufferedEncNumber.randNumCipher)

          if(bufferedEncNumber.userIdentifier == Bob) {
            context.become(calculateProduct(bufferedEncNumber, anotherEncryptedNumber))
          } else {
            context.become(calculateProduct(anotherEncryptedNumber, bufferedEncNumber))
          }

          self ! CalculateProduct
      }

  }

  private def calculateProduct(bobsEncryptedMessage :DamgardJurikEncryptedNumWithRnd,
                               alicesEncryptedMessage :DamgardJurikEncryptedNumWithRnd): Receive = {
    case CalculateProduct =>

      val numA = encryptor.decrypt(bobsEncryptedMessage.publicKeyCipher)
      val numB = encryptor.decrypt(alicesEncryptedMessage.publicKeyCipher)
      val product = numA.getX.multiply(numB.getX)
      log.info(s"Product => $numA * $numB = $product")

      val r1 = bobsEncryptedMessage.rnd.bigInteger
      val r2 = alicesEncryptedMessage.rnd.bigInteger
      val r3 = BigInt(Random.nextInt(1000)).bigInteger

      val x1= new BigIntegerPlainText(numA.getX)
      val x2= new BigIntegerPlainText(numB.getX)

      val num_a_enc: BigIntegerCiphertext = bobsEncryptedMessage.randNumCipher
      val num_b_enc: BigIntegerCiphertext = alicesEncryptedMessage.randNumCipher
      val num_c_enc: BigIntegerCiphertext = encryptor.encrypt(product, r3)

      bobRef ! DamgardJurikEncryptedNum(BrokerCarol, num_c_enc)
      aliceRef ! DamgardJurikEncryptedNum(BrokerCarol, num_c_enc)

      val proverComputation = encryptor.createProverComputation

      //Creates input for the prover.
      val input = new SigmaDJProductProverInput(publicKeyRepository(BrokerCarol),
        num_a_enc, num_b_enc, num_c_enc, r1, r2, r3, x1, x2)

      context.become(proving(proverComputation, input))

  }

  private def proving(prover: SigmaProverComputation, input: SigmaDJProductProverInput): Receive = {
    case VerifierChallenge(e) =>
      val a = prover.computeFirstMsg(input)
      val z = prover.computeSecondMsg(e)
      sender() ! ProverResponse(a,z)
  }

  override def receive: Receive = {
    case Begin =>
      context.become(waiting(None))
      environment ! WriteMsg("Broker Carol asking for encrypted numbers ...")
      bobRef ! GetDamgardJurikEncryptedNum
      aliceRef ! GetDamgardJurikEncryptedNum
      context.system.scheduler.scheduleOnce(timeout, self, TooSlow)

  }
}
