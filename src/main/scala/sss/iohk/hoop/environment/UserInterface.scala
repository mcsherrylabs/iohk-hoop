package sss.iohk.hoop.environment

import scala.io.StdIn
/**
  * Created by alan on 9/27/16.
  *
  */
trait UserInterface {

  def read(prompt: String): String = synchronized {

    print(s"$prompt: ")

    Option(System.console()) match {
      case Some(console) => console.readLine()
      case None => StdIn.readLine()
    }
  }

  def write(message: String): Unit = println(message)

}

object UserInterface extends UserInterface