{-|
Module      : Network.WireGuard.Internal.Data.QueueSystem
Description : Device and Peer queue system types.
License     : GPL-3
Maintainer  : felix@alternativebit.fr
Stability   : experimental
Portability : POSIX

Device and Peer queue system types.
-}

module Network.WireGuard.Internal.Data.QueueSystem (
  DeviceQueues(..),
  PeerQueues(..),
  createPeerQueues
) where


import Network.WireGuard.Internal.Data.Types  (UdpPacket, TunPacket, Time)
import Network.WireGuard.Internal.PacketQueue (PacketQueue, newPacketQueue)
import Network.WireGuard.Internal.Packet      (Packet)

-- | Queues attached to the wireguard device.
data DeviceQueues = DeviceQueues {
  readUdpQueue  :: PacketQueue UdpPacket,
  writeUdpQueue :: PacketQueue UdpPacket,
  readTunQueue  :: PacketQueue (Time, TunPacket),
  writeTunQueue :: PacketQueue TunPacket
} deriving (Eq)

-- | Queues attached to a wireguard peer.
data PeerQueues = PeerQueues {
  readHandshakeQueue  :: PacketQueue Packet,
  decryptQueue        :: PacketQueue UdpPacket,
  encryptQueue        :: PacketQueue TunPacket
} deriving (Eq)

-- | Helper function instantiating a peer's queues.
createPeerQueues :: IO PeerQueues
createPeerQueues = do
  readHs  <- newPacketQueue 
  decrypt <- newPacketQueue
  encrypt <- newPacketQueue
  return $ PeerQueues readHs decrypt encrypt
