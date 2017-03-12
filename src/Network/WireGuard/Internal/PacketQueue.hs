{-# LANGUAGE RecordWildCards #-}

module Network.WireGuard.Internal.PacketQueue
  ( PacketQueue
  , newPacketQueue
  , popPacketQueue
  , pushPacketQueue
  , tryPushPacketQueue
  ) where

import           Control.Concurrent.STM

data PacketQueue packet = PacketQueue
                        { tqueue    :: TQueue packet
                        , allowance :: TVar Int
                        }

-- | Create a new PacketQueue with size limit of |maxQueuedPackets|.
newPacketQueue :: Int -> STM (PacketQueue packet)
newPacketQueue maxQueuedPackets = PacketQueue <$> newTQueue <*> newTVar maxQueuedPackets

-- | Pop a packet out from the queue, blocks if no packet is available.
popPacketQueue :: PacketQueue packet -> STM packet
popPacketQueue PacketQueue{..} = do
    packet <- readTQueue tqueue
    modifyTVar' allowance (+1)
    return packet

-- | Push a packet into the queue. Blocks if it's full.
pushPacketQueue :: PacketQueue packet -> packet -> STM ()
pushPacketQueue PacketQueue{..} packet = do
    allowance' <- readTVar allowance
    if allowance' <= 0
      then retry
      else do
          writeTQueue tqueue packet
          writeTVar allowance (allowance' - 1)

-- | Try to push a packet into the queue. Returns True if it's pushed.
tryPushPacketQueue :: PacketQueue packet -> packet -> STM Bool
tryPushPacketQueue PacketQueue{..} packet = do
    allowance' <- readTVar allowance
    if allowance' <= 0
      then return False
      else do
          writeTQueue tqueue packet
          writeTVar allowance (allowance' - 1)
          return True

