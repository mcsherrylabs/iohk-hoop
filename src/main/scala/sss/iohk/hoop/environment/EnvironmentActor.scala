package sss.iohk.hoop.environment

import akka.actor.{Actor, ActorLogging, ActorRef}
import sss.iohk.hoop._

import scala.util.{Failure, Success, Try}

/**
  * Created by alan on 9/27/16.
  */

object EnvironmentActor {

  case class GetBigIntForEncryption(prompt: String)
  case class BigIntForEncryption(n: BigInt)
  case class WriteMsg(message: String)
  case object ProtocolAborted
  case class ReadyToVerify(who: Identifier)
  case class VerificationResult(who: Identifier, verified: Boolean)

}

class EnvironmentActor(ui: UserInterface) extends Actor with ActorLogging {

  import EnvironmentActor._
  import ui._

  override def receive: Receive = provideNumbersForEncryption

  private case object RunVerification

  private def runVerifications(ids: Map[Identifier, ActorRef]): Receive = {

    case ReadyToVerify(id) =>
      log.info(s"Second id $id is ready to verify...")
      context.become(runVerifications(ids + (id -> sender())))

    case RunVerification =>
      log.info(s"Prompt to run verification")
      write(s"Identities ready to try verification are ${ids.keys.mkString(",")}")
      read("type 'b' for Bob or 'a' for Alice?") match {
        case "b" => ids(Bob) ! BeginVerification
        case "a" => ids(Alice) ! BeginVerification
        case _ => self ! RunVerification
      }

    case VerificationResult(who, verified) =>
      log.info(s"Verification Result from $who, result is $verified")
      write(s"$who says verified == $verified")
      self ! RunVerification

  }

  private def provideNumbersForEncryption: Receive = {
    case m @ GetBigIntForEncryption(prompt) =>
      log.info(s"Request for Big Int for encryption...")
      Try(BigInt(read(prompt))) match {
        case Success(bigInt) => sender() ! BigIntForEncryption(bigInt)
        case Failure(e) =>
          write("Invalid int, try again")
          self forward m
      }

    case WriteMsg(message) => write(message)

    case ProtocolAborted =>
      log.warning(s"ProtocolAborted")
      write("Protocol aborted! Took too long to input numbers?")
      sender() ! Begin

    case ReadyToVerify(id) =>
      log.info(s"First id $id is ready to verify...")
      context.become(runVerifications(Map(id -> sender())))
      self ! RunVerification

  }
}
