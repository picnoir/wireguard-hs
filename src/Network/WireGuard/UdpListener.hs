{-# LANGUAGE OverloadedStrings #-}

module Network.WireGuard.UdpListener
  ( runUdpListener
  ) where

import           Control.Concurrent.Async               (cancel, wait,
                                                         withAsync)
import           Control.Concurrent.STM.TVar            (TVar, readTVar)
import           Control.Exception                      (bracket)
import           Control.Monad                          (forever, void)
import           Control.Monad.STM                      (STM, atomically, retry)
import           Data.Streaming.Network                 (bindPortUDP,
                                                         bindRandomPortUDP)
import           Network.Socket                         (Socket, close)
import           Network.Socket.ByteString              (recvFrom, sendTo)

import           Network.WireGuard.Internal.State       (Device, port)

import           Network.WireGuard.Internal.Constant    (udpReadBufferLength)
import           Network.WireGuard.Internal.PacketQueue (PacketQueue, pushPacketQueue,
                                                         popPacketQueue)
import           Network.WireGuard.Internal.Data.Types  (UdpPacket)
import           Network.WireGuard.Internal.Util        (retryWithBackoff)

runUdpListener :: Device -> PacketQueue UdpPacket -> PacketQueue UdpPacket -> IO ()
runUdpListener device readUdpChan writeUdpChan = loop 0
  where
    loop oport =
        withAsync (handlePort oport readUdpChan writeUdpChan) $ \t -> do
            nport <- atomically $ waitNewVar oport (port device)
            cancel t
            loop nport

handlePort :: Int -> PacketQueue UdpPacket -> PacketQueue UdpPacket -> IO ()
handlePort bindPort readUdpChan writeUdpChan = retryWithBackoff $
    bracket (bind bindPort) close $ \sock ->
        withAsync (handleRead sock readUdpChan) $ \rt ->
        withAsync (handleWrite sock writeUdpChan) $ \wt -> do
            wait rt
            wait wt
  where
    -- TODO: prefer ipv6 binding here
    bind 0 = snd <$> bindRandomPortUDP "!4"
    bind p = bindPortUDP p "!4"

handleRead :: Socket -> PacketQueue UdpPacket -> IO ()
handleRead sock readUdpChan = forever $ do
    packet <- recvFrom sock udpReadBufferLength
    pushPacketQueue readUdpChan packet

handleWrite :: Socket -> PacketQueue UdpPacket -> IO ()
handleWrite sock writeUdpChan = forever $ do
    (packet, dest) <- popPacketQueue writeUdpChan
    void $ sendTo sock packet dest

waitNewVar :: Eq a => a -> TVar a -> STM a
waitNewVar old tvar = do
    now <- readTVar tvar
    if now == old
      then retry
      else return now
