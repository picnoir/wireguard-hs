module Network.WireGuard.Internal.Data.Handshake (
 HandshakeInitSeed (..),
 HandshakeError(..),
 HandshakeRespSeed
) where
  
import Control.Exception          (SomeException)
import Crypto.Noise.DH            (KeyPair)
import Crypto.Noise.DH.Curve25519 (Curve25519)
import Data.Word                  (Word32)
import System.Posix.Types         (EpochTime)

data HandshakeInitSeed = 
  InitHandshakeSeed {
   handshakeEphemeralKey :: KeyPair Curve25519,
   handshakeNowTS        :: EpochTime,
   handshakeSeed         :: Word32}

type HandshakeRespSeed = EpochTime

data HandshakeError = OngoingHandshake
                    | MissingPacketTimestamp
                    | UnexpectedIncomingPacketType String
                    | NoiseProtocolError SomeException
                    | PeerNotAuthorized
                    | IsReplayAttack
                    | PacketOutdated
                    | CannotFindPeerIndex
                    | ResponsePayloadShouldBeEmpty
  
