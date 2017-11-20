{-# LANGUAGE RecordWildCards #-}
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

import Data.Either                                 (isRight)
import Data.Maybe                                  (isJust, listToMaybe)
import Data.Serialize                              (runGet)
import qualified Data.IP.RouteTable          as RT (lookup)
import Data.ByteArray                              (ScrubbedBytes)
import Data.IP                                     (makeAddrRange)
import Control.Concurrent.Async                    (async)
import Control.Concurrent.STM                      (readTVarIO, STM,
                                                    atomically, readTMVar,
                                                    putTMVar, modifyTVar',
                                                    writeTVar, readTVar, tryReadTMVar)
import Control.Monad                               (when, unless)
import Control.Monad.Trans.Class                   (lift)
import Control.Monad.Trans.Except                  (ExceptT, throwE, runExceptT)
import Crypto.Noise.DH                             (dhGenKey, dhPubEq)
import qualified Data.ByteArray              as BA (length)
import Data.Serialize                              (runPut)
import Network.Socket                              (SockAddr)
import System.IO                                   (hPrint, stderr)
import System.Posix.Time                           (epochTime)
import System.Random                               (randomIO)

import Network.WireGuard.Internal.PacketQueue      (PacketQueue, popPacketQueue,
                                                    pushPacketQueue)
import Network.WireGuard.Internal.Packet           (Packet(..), buildPacket, parsePacket,
                                                    getMac1)
import Network.WireGuard.Internal.State            (Device(..), Peer(..), acquireEmptyIndex,
                                                    getSession, nextNonce, sessionKey, theirIndex,
                                                    renewTime, appendNewSessionToState, updateEndPoint)
import Network.WireGuard.Internal.Data.QueueSystem (PeerQueues(..), createPeerQueues)
import Network.WireGuard.Internal.Data.Peer        (PeerStreamAsyncs(..), DecryptPacketError(..),
                                                    ValidatePacketError(..))
import Network.WireGuard.Internal.Data.Types       (UdpPacket, TunPacket, Time)
import Network.WireGuard.Internal.Data.Handshake   (HandshakeInitSeed(..))
import Network.WireGuard.Internal.Noise            (encryptMessage, decryptMessage)
import Network.WireGuard.Internal.IPPacket         (IPPacket(InvalidIPPacket), 
                                                    IPPacket(IPv4Packet, IPv6Packet),
                                                    parseIPPacket)
import Network.WireGuard.Internal.Stream.Handshake (processHandshakeInitiation, handshakeInit)
import Network.WireGuard.Internal.Util             (assertJust)

-- | Creates the peer's related queues and spawn asynchronous processes
--   used to listen to those queues.
spawnPeerProcesses :: Device -> Peer -> PacketQueue UdpPacket -> PacketQueue TunPacket -> IO (PeerQueues, PeerStreamAsyncs)
spawnPeerProcesses d p outUdp outTun = do
  q   <- createPeerQueues
  dim <- async $ decryptIncomingMessages d p q outTun
  eom <- async $ encryptOutgoingMessages p d (encryptQueue q) outUdp
  hs  <- async $ processIncomingHandshakeMessages d p (readHandshakeQueue q) outUdp
  c   <- async $ processIncomingCookieMessages p q
  return (q, PeerStreamAsyncs dim eom hs c)

-- | Creates the peers queues and spawns the peers asyncs processes
-- of all the peers associated with a device.
spawnDevicePeerProcesses :: Device -> PacketQueue UdpPacket -> PacketQueue TunPacket -> IO ()
spawnDevicePeerProcesses d outUdp outTun = do
  prs <- readTVarIO $ peers d 
  mapM_ updatePeerTvar prs
  return ()
  where
    updatePeerTvar :: Peer -> IO ()
    updatePeerTvar p = do
      (pq, psa) <- spawnPeerProcesses d p outUdp outTun
      atomically $ putTMVar (asyncs p) psa
      atomically $ putTMVar (queues p) pq

-- TODO: See if we can clean this function's error handling.
decryptIncomingMessages :: Device -> Peer -> PeerQueues -> PacketQueue TunPacket -> IO ()
decryptIncomingMessages dev peer pq tunOutQ = do
    udpEncryptedPacket <- popPacketQueue $ decryptQueue pq
    key <- atomically . readTMVar $ localKey dev
    psk <- readTVarIO $ presharedKey dev
    let eEncryptedPacket = runGet (parsePacket (getMac1 (snd key) psk)) (fst udpEncryptedPacket)
    case eEncryptedPacket of
        Left err -> error err
        Right encryptedPacket -> do
            now <- epochTime
            eDecryptedPacket <- atomically $ runExceptT $ decryptPacket peer encryptedPacket now
            case eDecryptedPacket of 
                Right decryptedPacket -> do
                    parsedPacket <- parseIPPacket decryptedPacket
                    ok <- atomically $ runExceptT $ validateDecryptedPacket peer dev parsedPacket
                    when (isRight ok) $ do
                        atomically $
                          updateStateAfterDecrypt peer decryptedPacket (snd udpEncryptedPacket) now
                        pushPacketQueue tunOutQ decryptedPacket
                Left err -> error $ show err
    return ()

encryptOutgoingMessages :: Peer -> Device -> PacketQueue TunPacket -> PacketQueue UdpPacket -> IO ()
encryptOutgoingMessages peer dev encryptQ writeUdpChan = do
  packet   <- popPacketQueue encryptQ
  isSession <- isJust <$> atomically (tryReadTMVar $ activeSession peer)
  when isSession $ initiateHandshake peer dev writeUdpChan
  -- Wait for an established session
  atomically $ readTMVar $ activeSession peer
  msession <- getSession peer
  session  <- case msession of
      Just session -> return session
      _ -> error "Missing active session." 

  now <- epochTime
  when (now >= renewTime session) $
      initiateHandshake peer dev writeUdpChan
  nonce <- atomically $ nextNonce session
  let (msg, authtag) = encryptMessage (sessionKey session) nonce packet
      encrypted = runPut $ buildPacket (error "internal error") $
          PacketData (theirIndex session) nonce msg authtag
  endp <- atomically $ readTMVar $ endPoint peer
  pushPacketQueue writeUdpChan (encrypted, endp)
  atomically $ modifyTVar' (transferredBytes peer) (+fromIntegral (BA.length packet))
  atomically $ writeTVar (lastTransferTime peer) now
  return ()

initiateHandshake :: Peer -> Device -> PacketQueue UdpPacket -> IO ()
initiateHandshake peer dev writeUdpChan = do
  seed     <- generateHandshakeSeed dev peer
  stopTime <- undefined
  sock     <- atomically . readTMVar $ endPoint peer
  r        <- atomically . runExceptT $ handshakeInit seed dev peer stopTime sock
  case r of
      Left err -> error $ show err  
      Right packet -> do
          pushPacketQueue writeUdpChan packet
          return ()

processIncomingHandshakeMessages :: Device -> Peer -> PacketQueue Packet -> PacketQueue UdpPacket -> IO ()
processIncomingHandshakeMessages dev peer handshakeQ udpQ = do
  p     <- popPacketQueue handshakeQ
  seed  <- generateHandshakeSeed dev peer
  kp    <- atomically . readTMVar $ localKey dev
  psh   <- readTVarIO $ presharedKey dev
  saddr <- atomically . readTMVar $ endPoint peer
  udpP  <- atomically $ runExceptT $ processHandshakeInitiation seed dev kp psh saddr p
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

decryptPacket :: Peer -> Packet -> Time -> ExceptT DecryptPacketError STM ScrubbedBytes
decryptPacket peer PacketData{..} now = do
    fstPckSinceHandshake <- isJust <$> lift (readTVar (handshakeRespSt peer))
    when fstPckSinceHandshake $ lift $ appendNewSessionToState peer now
    session <- assertJust MissingSession $ lift (listToMaybe <$> readTVar (sessions peer))
    case decryptMessage (sessionKey session) counter (encryptedPayload, authTag) of
        Nothing               -> throwE DecryptError
        Just decryptedPayload -> return decryptedPayload
decryptPacket _ _ _ = throwE UnexpectedIncomingPacket

validateDecryptedPacket :: Peer -> Device -> IPPacket -> ExceptT ValidatePacketError STM ()
validateDecryptedPacket peer dev packet = do
    case packet of
      InvalidIPPacket   -> throwE InvalidDecryptedIPPacket
      IPv4Packet src4 _ -> do
          peer' <- assertJust SourceAddrBlocked $ 
              RT.lookup (makeAddrRange src4 32) <$> lift (readTVar (routeTable4 dev))
          unless (remotePub peer `dhPubEq` remotePub peer') $ throwE SourceAddrBlocked
      IPv6Packet src6 _ -> do
          peer' <- assertJust SourceAddrBlocked $
              RT.lookup (makeAddrRange src6 128) <$> lift (readTVar (routeTable6 dev))
          unless (remotePub peer `dhPubEq` remotePub peer') $ throwE SourceAddrBlocked
    return ()

updateStateAfterDecrypt :: Peer -> ScrubbedBytes -> SockAddr -> Time -> STM ()
updateStateAfterDecrypt peer decryptedPayload sock now = do
    updateEndPoint peer sock
    if BA.length decryptedPayload /= 0
      then
        writeTVar (lastKeepaliveTime peer) now
      else do
        writeTVar (lastReceiveTime peer) now
        modifyTVar' (receivedBytes peer) (+fromIntegral (BA.length decryptedPayload))
    return ()
