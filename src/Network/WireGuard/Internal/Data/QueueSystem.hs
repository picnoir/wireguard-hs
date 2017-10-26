module Network.WireGuard.Internal.Data.QueueSystem (
  DeviceQueues(..),
  PeerQueues(..)
) where


import Network.WireGuard.Internal.Data.Types  (UdpPacket, TunPacket,Time)
import Network.WireGuard.Internal.PacketQueue (PacketQueue)

-- | Queues attached to the wireguard device.
data DeviceQueues = DeviceQueues {
  readUdpQueue  :: PacketQueue UdpPacket,
  writeUdpQueue :: PacketQueue UdpPacket,
  readTunQueue  :: PacketQueue (Time, TunPacket),
  writeTunQueue :: PacketQueue TunPacket
} deriving (Eq)

-- | Queues attached to a wireguard peer.
data PeerQueues = PeerQueues {
  readHandshakeQueue  :: PacketQueue UdpPacket,
  writeHandshakeQueue :: PacketQueue UdpPacket,
  decryptQueue        :: PacketQueue UdpPacket,
  encryptQueue        :: PacketQueue UdpPacket
} deriving (Eq)
