{-|
Module      : Network.WireGuard.Internal.State.
Description : Collection of peer-related streaming features.
License     : GPL-3
Maintainer  : felix@alternativebit.fr
Stability   : experimental
Portability : POSIX

Collection of peer-related streaming asyncs process.
-}

module Network.WireGuard.Internal.Stream.Peer (
  spawnPeerProcesses,
  spawnDevicePeerProcesses
) where

import Data.Maybe                                  (fromJust)
import Control.Concurrent.Async                    (async)
import Control.Concurrent.STM                      (atomically, readTVar, writeTVar)
import Control.Monad.Trans.Except                  (runExceptT)
import Crypto.Noise.DH                             (dhGenKey)
import System.IO                                   (hPrint, stderr)
import System.Posix.Time                           (epochTime)
import System.Random                               (randomIO)

import Network.WireGuard.Internal.PacketQueue      (PacketQueue, popPacketQueue,
                                                    pushPacketQueue)
import Network.WireGuard.Internal.Packet           (Packet)
import Network.WireGuard.Internal.State            (Device(..), Peer(..), acquireEmptyIndex)
import Network.WireGuard.Internal.Data.QueueSystem (PeerQueues(..), createPeerQueues)
import Network.WireGuard.Internal.Data.Peer        (PeerStreamAsyncs(..))
import Network.WireGuard.Internal.Data.Types       (UdpPacket)
import Network.WireGuard.Internal.Data.Handshake   (HandshakeInitSeed(..))
import Network.WireGuard.Internal.Stream.Handshake (processHandshakeInitiation)

-- | Creates the peer's related queues and spawn asynchronous processes
--   used to listen to those queues.
spawnPeerProcesses :: Device -> Peer -> PacketQueue UdpPacket -> IO (PeerQueues, PeerStreamAsyncs)
spawnPeerProcesses d p outUdp = do
  q   <- createPeerQueues
  dim <- async $ decryptIncomingMessages p q
  hs  <- async $ processIncomingHandshakeMessages d p (readHandshakeQueue q) outUdp
  c   <- async $ processIncomingCookieMessages p q
  return (q, PeerStreamAsyncs dim hs c)

-- | Creates the peers queues and spawns the peers asyncs processes
-- of all the peers associated with a device.
spawnDevicePeerProcesses :: Device -> PacketQueue UdpPacket -> IO ()
spawnDevicePeerProcesses d outUdp = do
  prs <- atomically $ readTVar $ peers d 
  mapM_ updatePeerTvar prs
  return ()
  where
    updatePeerTvar :: Peer -> IO ()
    updatePeerTvar p = do
      (pq, psa) <- spawnPeerProcesses d p outUdp
      atomically $ writeTVar (asyncs p) $ Just psa
      atomically $ writeTVar (queues p) $ Just pq
      

decryptIncomingMessages :: Peer -> PeerQueues -> IO ()
decryptIncomingMessages _ _ = undefined

processIncomingHandshakeMessages :: Device -> Peer -> PacketQueue Packet -> PacketQueue UdpPacket -> IO ()
processIncomingHandshakeMessages dev peer handshakeQ udpQ = do
  seed  <- generateHandshakeSeed dev peer
  kp    <- atomically . readTVar $ localKey dev
  psh   <- atomically . readTVar $ presharedKey dev
  saddr <- atomically . readTVar $ endPoint peer
  p     <- popPacketQueue handshakeQ
  udpP  <- atomically . runExceptT $ processHandshakeInitiation seed dev (fromJust kp) psh (fromJust saddr) p
  either (hPrint stderr) (pushPacketQueue udpQ) udpP

generateHandshakeSeed :: Device -> Peer -> IO HandshakeInitSeed
generateHandshakeSeed dev peer = do
  eKp <- dhGenKey
  iSeed <- randomIO
  index <- atomically $ acquireEmptyIndex dev peer iSeed
  ts <- epochTime
  return $ HandshakeInitSeed eKp ts index

processIncomingCookieMessages :: Peer -> PeerQueues -> IO ()
processIncomingCookieMessages _ _ = undefined
