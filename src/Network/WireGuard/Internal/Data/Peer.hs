{-|
Module      : Network.WireGuard.Internal.Data.Peer
Description : Peer streaming related data types.
License     : GPL-3
Maintainer  : felix@alternativebit.fr
Stability   : experimental
Portability : POSIX

Peer streaming related data types. Contains Asyncs process
taking care of the various encrypting, decrypting, handshake-related
and cookie-related operations.
-}

module Network.WireGuard.Internal.Data.Peer (
  PeerStreamAsyncs(..),
  DecryptPacketError(..),
  ValidatePacketError(..)
) where

import Control.Concurrent.Async (Async)

-- | Data type aggregating all peer's attached asyncs.
data PeerStreamAsyncs = PeerStreamAsyncs {
  decryptPeerAsync   :: Async (),
  encryptPeerAsync   :: Async (),
  handshakePeerAsync :: Async (),
  cookiePeerAsync    :: Async ()
}

data DecryptPacketError = UnknownPeerIndex
                        | MissingSession
                        | UnexpectedIncomingPacket
                        | DecryptError
                        deriving (Show, Eq)

data ValidatePacketError = SourceAddrBlocked
                         | InvalidDecryptedIPPacket
                         deriving (Show, Eq)
