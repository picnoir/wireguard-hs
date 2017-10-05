module Network.WireGuard.Internal.Data.Handshake (
 HandshakeSeed (..)
) where
  
import Crypto.Noise.DH            (KeyPair)
import Crypto.Noise.DH.Curve25519 (Curve25519)
import Data.Word                  (Word32)
import System.Posix.Types         (EpochTime)

data HandshakeSeed = HandshakeSeed {
 handshakeEphemeralKey :: KeyPair Curve25519,
 handshakeTimeStamp    :: EpochTime,
 handshakeIndex        :: Word32
}
