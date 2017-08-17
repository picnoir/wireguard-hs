module Network.WireGuard.Internal.Data.Types
  ( Index
  , Counter
  , PeerId
  , PublicKey
  , PrivateKey
  , KeyPair
  , PresharedKey
  , Time
  , UdpPacket
  , TunPacket
  , EncryptedPayload
  , AuthTag
  , TAI64n
  , SessionKey(..)
  , WireGuardError(..)
  , getPeerId
  , farFuture
  ) where

import           Control.Exception          (Exception, SomeException)
import qualified Crypto.Noise.DH            as DH
import           Crypto.Noise.DH.Curve25519 (Curve25519)
import           Data.ByteArray             (ScrubbedBytes)
import qualified Data.ByteArray             as BA
import qualified Data.ByteString            as BS
import           Foreign.C.Types            (CTime (..))
import           Network.Socket             (SockAddr)
import           System.Posix.Types         (EpochTime)

import           Data.Word

type Index        = Word32
type Counter      = Word64
type PeerId       = BS.ByteString

type PublicKey    = DH.PublicKey Curve25519
type PrivateKey   = DH.SecretKey Curve25519
type KeyPair      = DH.KeyPair Curve25519
type PresharedKey = ScrubbedBytes

type Time         = EpochTime

type UdpPacket    = (BS.ByteString, SockAddr)
type TunPacket    = ScrubbedBytes

type EncryptedPayload = BS.ByteString
type AuthTag          = BS.ByteString
type TAI64n           = BS.ByteString

data SessionKey = SessionKey
                { sendKey :: !ScrubbedBytes
                , recvKey :: !ScrubbedBytes
                }

data WireGuardError
    = DecryptFailureError
    | DestinationNotReachableError
    | DeviceNotReadyError
    | EndPointUnknownError
    | HandshakeInitiationReplayError
    | InvalidIPPacketError
    | InvalidWGPacketError String
    | NoiseError SomeException
    | NonceReuseError
    | OutdatedPacketError
    | RemotePeerNotFoundError
    | SourceAddrBlockedError
    | UnknownIndexError
  deriving (Show)

instance Exception WireGuardError

getPeerId :: PublicKey -> PeerId
getPeerId = BA.convert . DH.dhPubToBytes

farFuture :: Time
farFuture = CTime maxBound
