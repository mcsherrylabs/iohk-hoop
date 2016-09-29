package sss.iohk

import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility.SigmaProtocolMsg
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext

/**
  * Created by alan on 9/28/16.
  *
  * This is the package wide interface.
  * These classes may be used anywhere in the solution.
  */
package object hoop {

  sealed trait Identifier
  case object Bob extends Identifier
  case object Alice extends Identifier
  case object BrokerCarol extends Identifier

  case object Begin
  case object TooSlow
  case object CalculateProduct
  case class VerifierChallenge(e: Array[Byte])

  case object BeginVerification
  case object GetDamgardJurikEncryptedNum
  case class DamgardJurikEncryptedNum(userIdentifier: Identifier, cipher: BigIntegerCiphertext)

  case class DamgardJurikEncryptedNumWithRnd(userIdentifier: Identifier,
                                             publicKeyCipher: BigIntegerCiphertext,
                                             randNumCipher: BigIntegerCiphertext,
                                             rnd: BigInt)

  case class ProverResponse(a: SigmaProtocolMsg, z: SigmaProtocolMsg)

}
