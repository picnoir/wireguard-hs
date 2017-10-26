{-|
Module      : Network.WireGuard.Internal.Data.Handshake
Description : Handshake related data types.
License     : GPL-3
Maintainer  : felix@alternativebit.fr
Stability   : experimental
Portability : POSIX

This module contains the data types used during a
wireguard handshake.
-}

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

-- | Seed needed to initiate a handshake.
data HandshakeInitSeed = 
   HandshakeInitSeed {
   -- | Ephemeral keypair generated for a handshake.
   handshakeEphemeralKey :: KeyPair Curve25519,
   -- | Timestmap of the handshake initiation.
   handshakeNowTS        :: EpochTime,
   -- | Random 8-byte index locally generated in order
   --   to identify the remote peer.
   handshakeSeed         :: Word32}

-- | Timestamp of the handshake response.
type HandshakeRespSeed = EpochTime

-- | Errors that could occur during a wireguard handshake.
data HandshakeError = OngoingHandshake
                    | MissingPacketTimestamp
                    | UnexpectedIncomingPacketType String
                    | NoiseProtocolError SomeException
                    | PeerNotAuthorized
                    | IsReplayAttack
                    | PacketOutdated
                    | CannotFindPeerIndex
                    | ResponsePayloadShouldBeEmpty
                    deriving (Show)
  
