module Network.WireGuard.Internal.PacketQueue
  ( PacketQueue
  , newPacketQueue
  , popPacketQueue
  , pushPacketQueue
  , module Control.Concurrent.Chan
  ) where

import           Control.Concurrent.Chan

type PacketQueue packet = Chan packet

newPacketQueue :: IO (PacketQueue packet)
newPacketQueue = newChan

popPacketQueue :: PacketQueue packet -> IO packet
popPacketQueue = readChan

pushPacketQueue :: PacketQueue packet -> packet -> IO ()
pushPacketQueue = writeChan
