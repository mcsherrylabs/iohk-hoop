package sss.iohk.hoop

/**
  * Created by alan on 9/27/16.
  */

import java.math.BigInteger

import akka.actor.{Actor, ActorLogging, ActorRef, ActorSystem, Props}
import akka.pattern.ask
import akka.testkit.{DefaultTimeout, ImplicitSender, TestKit}
import com.typesafe.config.ConfigFactory
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext
import org.scalatest.{BeforeAndAfterAll, Matchers, WordSpecLike}
import sss.iohk.hoop.environment.EnvironmentActor._

import scala.concurrent.duration._
import scala.language.postfixOps


case object ForwardToTest
case object SupplyBigInt

class EnvironmentForwardActor(actorRef: ActorRef) extends Actor with ActorLogging {

  private def control: Receive = {
    case ForwardToTest =>
      context.become(control orElse forwardToTestActor)
      sender() ! "Ok"

    case SupplyBigInt =>
      context.become(control orElse supplyBigInt)
      sender() ! "Ok"
  }

  private def forwardToTestActor: Receive = {
    case x => actorRef forward x
  }

  private def supplyBigInt: Receive = {
    case GetBigIntForEncryption(_) => sender ! BigIntForEncryption(34)
  }
  override def receive: Receive = control
}

/**
  * Tests show some TestKit usage ability
  */
class IOHKDamgardJurikActorSpec
  extends TestKit(ActorSystem(
    "UsageSpec",
    ConfigFactory.parseString(IOHKDamgardJurikActorSpec.config)))
    with DefaultTimeout with ImplicitSender
    with WordSpecLike with Matchers with BeforeAndAfterAll {

  val bobEncryptor = new DamgardJurikEncryption()
  val aliceEncryptor = new DamgardJurikEncryption()
  val brokerCarolEncryptor = new DamgardJurikEncryption()

  val dummyCipherText = new BigIntegerCiphertext(new BigInteger("34343434343434343434343434343434343434343434343434343434343434343434343434"))
  val publicKeyRepository = Map(Bob -> bobEncryptor.getPublic,
    Alice -> aliceEncryptor.getPublic,
    BrokerCarol -> brokerCarolEncryptor.getPublic
  )

  val environmentRef = system.actorOf(Props(classOf[EnvironmentForwardActor], this.testActor))
  val bobRef = system.actorOf(Props(classOf[UserActor], Bob, publicKeyRepository, bobEncryptor, environmentRef))
  val aliceRef = system.actorOf(Props(classOf[UserActor], Alice, publicKeyRepository, aliceEncryptor, environmentRef))
  val brokerCarolRef = system.actorOf(Props(classOf[BrokerCarolActor], publicKeyRepository, brokerCarolEncryptor, environmentRef, bobRef, aliceRef, 5 seconds))

  override def afterAll {
    shutdown()
  }


  "The Environment actor " should {
    " abort the protocol if no numbers to encrypt are received " in {
      within(6 seconds) {
        environmentRef ? ForwardToTest
        brokerCarolRef ! Begin
        receiveN(3)
        expectMsg(ProtocolAborted)
      }
    }
  }

  "A UserActor" should {
    " respond with a correctly identified encrypted message when asked " in {
      within(500 millis) {
        // Use the ask pattern to prevent race conditions
        // (even though the test dispatcher might only be a single thread.)
        environmentRef ? SupplyBigInt
        bobRef ! GetDamgardJurikEncryptedNum
        val d = expectMsgType[DamgardJurikEncryptedNumWithRnd]
        d.userIdentifier should be (Bob)
      }
    }
  }

  "A Bob UserActor" should {
    " respond with ReadyToVerify(Bob) when provided with all cipher texts " in {
      within(500 millis) {
        // Use the ask pattern to prevent race conditions
        // (even though the test dispatcher might only be a single thread.)
        environmentRef ? SupplyBigInt
        bobRef ! GetDamgardJurikEncryptedNum
        val d = expectMsgType[DamgardJurikEncryptedNumWithRnd]
        d.userIdentifier should be (Bob)
        environmentRef ? ForwardToTest
        bobRef ! DamgardJurikEncryptedNum(BrokerCarol, dummyCipherText)
        receiveN(1)
        expectMsg(ReadyToVerify(Bob))
      }
    }
  }


}

object IOHKDamgardJurikActorSpec {
  // Define your test specific configuration here
  val config = """
    akka {
      loglevel = "WARNING"
    }
               """

}