package sss.iohk.hoop

import akka.actor.{ActorSystem, Props}
import sss.iohk.hoop.environment.{EnvironmentActor, UserInterface}

import scala.concurrent.duration._
import scala.language.postfixOps

/**
  * Created by alan on 9/27/16.
  */

object Main {

  def main(args: Array[String]): Unit = {

    val system = ActorSystem()

    val bobEncryptor = new DamgardJurikEncryption()
    val aliceEncryptor = new DamgardJurikEncryption()
    val brokerCarolEncryptor = new DamgardJurikEncryption()

    val publicKeyRepository = Map(Bob -> bobEncryptor.getPublic,
      Alice -> aliceEncryptor.getPublic,
      BrokerCarol -> brokerCarolEncryptor.getPublic
    )

    val environmentRef = system.actorOf(Props(classOf[EnvironmentActor], UserInterface))
    val bobRef = system.actorOf(Props(classOf[UserActor], Bob, publicKeyRepository, bobEncryptor, environmentRef))
    val aliceRef = system.actorOf(Props(classOf[UserActor], Alice, publicKeyRepository, aliceEncryptor, environmentRef))

    val brokerCarolRef = system.actorOf(Props(classOf[BrokerCarolActor], publicKeyRepository, brokerCarolEncryptor, environmentRef, bobRef, aliceRef, 15 seconds))

    brokerCarolRef ! Begin

  }

}
