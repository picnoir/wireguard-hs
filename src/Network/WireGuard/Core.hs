{-# LANGUAGE RecordWildCards #-}

module Network.WireGuard.Core
 ( runCore
 ) where

import           Control.Concurrent                          (getNumCapabilities,
                                                              threadDelay)
import           Control.Concurrent.Async                    (wait, withAsync)
import           Control.Monad                               (forM_, forever, unless,
                                                              void, when)
import           Control.Monad.IO.Class                      (liftIO)
import           Control.Monad.STM                           (atomically)
import           Control.Monad.Trans.Except                  (ExceptT, runExceptT,
                                                              throwE)
import           Crypto.Noise                                (HandshakeRole(ResponderRole, InitiatorRole))
import           Crypto.Noise.DH                             (dhGenKey, dhPubEq)
import qualified Data.ByteArray                              as BA (length, convert)
import qualified Data.HashMap.Strict                         as HM (lookup)
import           Data.IP                                     (makeAddrRange)
import qualified Data.IP.RouteTable                          as RT (lookup)
import           Data.Maybe                                  (fromMaybe, isJust,
                                                              isNothing)
import           Data.Serialize                              (putWord32be,
                                                              putWord64be, runGet,
                                                              runPut)
import           Foreign.C.Types                             (CTime(CTime))
import           Network.Socket                              (SockAddr)
import           System.IO                                   (hPrint, stderr)
import           System.Posix.Time                           (epochTime)
import           System.Random                               (randomIO)

import           Control.Concurrent.STM                      (readTVarIO, modifyTVar',
                                                              writeTVar, newTVar, readTVar,
                                                              tryReadTMVar)

import           Network.WireGuard.Internal.Constant         (heartbeatWaitTime, handshakeRetryTime,
                                                              timestampLength, handshakeStopTime,
                                                              sessionRenewTime, sessionExpireTime,
                                                              sessionKeepaliveTime)
import           Network.WireGuard.Internal.IPPacket         (IPPacket(InvalidIPPacket), 
                                                              IPPacket(IPv4Packet, IPv6Packet),
                                                              parseIPPacket)
import           Network.WireGuard.Internal.Noise            (encryptMessage, newNoiseState,
                                                              recvFirstMessageAndReply, recvSecondMessage,
                                                              decryptMessage, sendFirstMessage)
import           Network.WireGuard.Internal.Packet           (Packet(HandshakeInitiation, HandshakeResponse),
                                                              Packet(PacketData), buildPacket, parsePacket,
                                                              encryptedPayload, senderIndex, receiverIndex,
                                                              counter, authTag, getMac1)
import           Network.WireGuard.Internal.PacketQueue      (PacketQueue, popPacketQueue,
                                                              pushPacketQueue)
import           Network.WireGuard.Internal.State            (Device(Device), HandshakeResp(HandshakeResp),
                                                              Peer(Peer), localKey, presharedKey,
                                                              routeTable4, routeTable6, getSession,
                                                              endPoint, waitForSession, nextNonce,
                                                              sessionKey, theirIndex, renewTime, transferredBytes,
                                                              lastTransferTime, peers, updateTai64n, 
                                                              acquireEmptyIndex, eraseHandshakeInit,
                                                              handshakeInitSt, indexMap, handshakeRespSt,
                                                              initOurIndex, initNoise, Session(Session),
                                                              eraseHandshakeInit, addSession,
                                                              lastHandshakeTime, updateEndPoint,
                                                              findSession, respOurIndex, respTheirIndex,
                                                              respSessionKey, remotePub, remotePub,
                                                              lastReceiveTime, receivedBytes, lastKeepaliveTime,
                                                              initRekeyAttemptTime, initRekeyTimeout, respStopTime,
                                                              filterSessions, expireTime, eraseHandshakeResp,
                                                              HandshakeInit(HandshakeInit))
import           Network.WireGuard.Internal.Data.Types       (Time, TunPacket, UdpPacket,
                                                              WireGuardError(..), KeyPair, PresharedKey,
                                                              TAI64n, getPeerId)
import           Network.WireGuard.Internal.Data.QueueSystem (DeviceQueues(..))
import           Network.WireGuard.Internal.Util             (ignoreSyncExceptions, withJust,
                                                              retryWithBackoff, dropUntilM,
                                                              assertJust)
import           Network.WireGuard.Internal.Stream.Peer      (spawnDevicePeerProcesses)

runCore :: Device -> DeviceQueues -> IO ()
runCore device devQueues = do
    threads <- getNumCapabilities
    spawnDevicePeerProcesses device (writeUdpQueue devQueues) (writeTunQueue devQueues)
    loop threads []
  where
    heartbeatLoop = forever $ ignoreSyncExceptions $ do
        withJust (atomically $ tryReadTMVar (localKey device)) $ \key ->
            runHeartbeat device key (writeUdpQueue devQueues)
        -- TODO: use accurate timer
        threadDelay heartbeatWaitTime
    loop 0 asyncs =
        withAsync heartbeatLoop $ \ht ->
            mapM_ wait asyncs >> wait ht
    loop x asyncs =
        withAsync (retryWithBackoff $ handleReadTun device (readTunQueue devQueues) (writeUdpQueue devQueues)) $ \rt ->
        withAsync (retryWithBackoff $ handleReadUdp device (readUdpQueue devQueues) (writeTunQueue devQueues) (writeUdpQueue devQueues)) $ \ru ->
        -- TODO: specify right Chan
        withAsync (retryWithBackoff $ handleHandshakeInit device (readUdpQueue devQueues)) $ \rhs ->
            loop (x-1) (rhs:rt:ru:asyncs)

handleHandshakeInit :: Device -> PacketQueue UdpPacket -> IO ()
handleHandshakeInit _ _ = undefined

handleReadTun :: Device -> PacketQueue (Time, TunPacket) -> PacketQueue UdpPacket -> IO ()
handleReadTun device readTunChan writeUdpChan = forever $ do
    earliestToProcess <- (`addTime` (-handshakeRetryTime)) <$> epochTime
    (_, tunPacket) <- dropUntilM ((>=earliestToProcess).fst) $ popPacketQueue readTunChan
    res <- runExceptT $ processTunPacket device writeUdpChan tunPacket
    case res of
        Right udpPacket -> pushPacketQueue writeUdpChan udpPacket
        Left err        -> hPrint stderr err -- TODO: proper logging

handleReadUdp :: Device -> PacketQueue UdpPacket -> PacketQueue TunPacket
              -> PacketQueue UdpPacket
              -> IO ()
handleReadUdp device readUdpChan writeTunChan writeUdpChan = forever $ do
    udpPacket <- popPacketQueue readUdpChan
    res <- runExceptT $ processUdpPacket device udpPacket
    case res of
        Left err      -> hPrint stderr err -- TODO: proper logging
        Right mpacket -> case mpacket of
            Just (Right tunp) -> pushPacketQueue writeTunChan tunp
            Just (Left  udpp) -> pushPacketQueue writeUdpChan udpp
            Nothing           -> return ()

processTunPacket :: Device -> PacketQueue UdpPacket -> TunPacket
                 -> ExceptT WireGuardError IO UdpPacket
processTunPacket device@Device{..} writeUdpChan packet = do
    key <- assertJust DeviceNotReadyError $ liftIO (atomically $ tryReadTMVar localKey)
    psk <- liftIO (readTVarIO presharedKey)
    parsedPacket <- liftIO $ parseIPPacket packet
    peer <- assertJust DestinationNotReachableError $ case parsedPacket of
        InvalidIPPacket    -> throwE InvalidIPPacketError
        IPv4Packet _ dest4 -> RT.lookup (makeAddrRange dest4 32)
            <$> liftIO (readTVarIO routeTable4)
        IPv6Packet _ dest6 -> RT.lookup (makeAddrRange dest6 128)
            <$> liftIO (readTVarIO routeTable6)
    msession <- liftIO (getSession peer)
    session <- case msession of
        Just session -> return session
        Nothing      -> do
            now0 <- liftIO epochTime
            endp0 <- assertJust EndPointUnknownError $ liftIO $ atomically $ tryReadTMVar (endPoint peer)
            liftIO $ void $ checkAndTryInitiateHandshake device key psk writeUdpChan peer endp0 now0
            assertJust OutdatedPacketError $ liftIO $ waitForSession (handshakeRetryTime * 1000000) peer
    nonce <- liftIO $ atomically $ nextNonce session
    let (msg, authtag) = encryptMessage (sessionKey session) nonce packet
        encrypted = runPut $ buildPacket (error "internal error") $
            PacketData (theirIndex session) nonce msg authtag
    now <- liftIO epochTime
    endp <- assertJust EndPointUnknownError $ liftIO $ atomically $ tryReadTMVar (endPoint peer)
    when (now >= renewTime session) $ liftIO $
        void $ checkAndTryInitiateHandshake device key psk writeUdpChan peer endp now
    liftIO $ atomically $ modifyTVar' (transferredBytes peer) (+fromIntegral (BA.length packet))
    liftIO $ atomically $ writeTVar (lastTransferTime peer) now
    return (encrypted, endp)

processUdpPacket :: Device -> UdpPacket
                 -> ExceptT WireGuardError IO (Maybe (Either UdpPacket TunPacket))
processUdpPacket device@Device{..} (packet, sock) = do
    key <- assertJust DeviceNotReadyError $ liftIO (atomically $ tryReadTMVar localKey)
    psk <- liftIO (readTVarIO presharedKey)
    let mp = runGet (parsePacket (getMac1 (snd key) psk)) packet
    case mp of
        Left errMsg        -> throwE (InvalidWGPacketError errMsg)
        Right parsedPacket -> processPacket device key psk sock parsedPacket

processPacket :: Device -> KeyPair -> Maybe PresharedKey -> SockAddr -> Packet
              -> ExceptT WireGuardError IO (Maybe (Either UdpPacket TunPacket))
processPacket device@Device{..} key psk sock HandshakeInitiation{..} = do
    ekey <- liftIO dhGenKey
    let state0 = newNoiseState key psk ekey Nothing ResponderRole
        outcome = recvFirstMessageAndReply state0 encryptedPayload mempty
    case outcome of
        Left err                                   -> throwE (NoiseError err)
        Right (reply, decryptedPayload, rpub, sks) -> do
            when (BA.length decryptedPayload /= timestampLength) $
                throwE $ InvalidWGPacketError "timestamp expected"
            peer <- assertJust RemotePeerNotFoundError $
                HM.lookup (getPeerId rpub) <$> liftIO (readTVarIO peers)
            notReplayAttack <- liftIO $ atomically $ updateTai64n peer (BA.convert decryptedPayload)
            unless notReplayAttack $ throwE HandshakeInitiationReplayError
            now <- liftIO epochTime
            seed <- liftIO randomIO
            ourindex <- liftIO $ atomically $ do
                ourindex <- acquireEmptyIndex device peer seed
                void $ eraseHandshakeResp device peer Nothing
                let rwait = HandshakeResp ourindex senderIndex
                        (addTime now handshakeStopTime) sks
                writeTVar (handshakeRespSt peer) (Just rwait)
                return ourindex
            let responsePacket = runPut $ buildPacket (getMac1 rpub psk) $
                    HandshakeResponse ourindex senderIndex reply
            return (Just (Left (responsePacket, sock)))

processPacket device@Device{..} _key _psk sock HandshakeResponse{..} = do
    peer <- assertJust UnknownIndexError $
        HM.lookup receiverIndex <$> liftIO (readTVarIO indexMap)
    iwait <- assertJust OutdatedPacketError $ liftIO (readTVarIO (handshakeInitSt peer))
    when (initOurIndex iwait /= receiverIndex) $ throwE OutdatedPacketError
    let state1 = initNoise iwait
        outcome = recvSecondMessage state1 encryptedPayload
    case outcome of
        Left err                      -> throwE (NoiseError err)
        Right (decryptedPayload, sks) -> do
            now <- liftIO epochTime
            newCounter <- liftIO $ atomically $ newTVar 0
            let newsession = Session receiverIndex senderIndex sks
                    (addTime now sessionRenewTime)
                    (addTime now sessionExpireTime)
                    newCounter
            when (BA.length decryptedPayload /= 0) $
                throwE $ InvalidWGPacketError "empty payload expected"
            succeeded <- liftIO $ atomically $ do
                erased <- eraseHandshakeInit device peer (Just receiverIndex)
                when erased $ do
                    addSession device peer newsession
                    writeTVar (lastHandshakeTime peer) (Just now)
                return erased
            unless succeeded $ throwE OutdatedPacketError
            liftIO $ atomically $ updateEndPoint peer sock
            return Nothing

processPacket device@Device{..} _key _psk sock PacketData{..} = do
    peer <- assertJust UnknownIndexError $
        HM.lookup receiverIndex <$> liftIO (readTVarIO indexMap)
    outcome <- liftIO $ atomically $ findSession peer receiverIndex
    now <- liftIO epochTime
    (isFromResponderWait, session) <- case outcome of
        Nothing                       -> throwE OutdatedPacketError
        Just (Right session)          -> return (False, session)
        Just (Left HandshakeResp{..}) -> do
            newCounter <- liftIO $ atomically $ newTVar 0
            let newsession = Session respOurIndex respTheirIndex respSessionKey
                    (addTime now (sessionRenewTime + 2 * handshakeRetryTime))
                    (addTime now sessionExpireTime)
                    newCounter
            return (True, newsession)
    case decryptMessage (sessionKey session) counter (encryptedPayload, authTag) of
        Nothing               -> throwE DecryptFailureError
        Just decryptedPayload -> do
            when isFromResponderWait $ liftIO $ atomically $ do
                erased <- eraseHandshakeResp device peer (Just receiverIndex)
                when erased $ do
                    addSession device peer session
                    writeTVar (lastHandshakeTime peer) (Just now)
            liftIO $ atomically $ updateEndPoint peer sock
            if BA.length decryptedPayload /= 0
              then do
                parsedPacket <- liftIO $ parseIPPacket decryptedPayload
                case parsedPacket of
                    InvalidIPPacket   -> throwE InvalidIPPacketError
                    IPv4Packet src4 _ -> do
                        peer' <- assertJust SourceAddrBlockedError $
                            RT.lookup (makeAddrRange src4 32) <$> liftIO (readTVarIO routeTable4)
                        unless (remotePub peer `dhPubEq` remotePub peer') $ throwE SourceAddrBlockedError
                    IPv6Packet src6 _ -> do
                        peer' <- assertJust SourceAddrBlockedError $
                            RT.lookup (makeAddrRange src6 128) <$> liftIO (readTVarIO routeTable6)
                        unless (remotePub peer `dhPubEq` remotePub peer') $ throwE SourceAddrBlockedError
                liftIO $ atomically $ writeTVar (lastReceiveTime peer) now
                liftIO $ atomically $ modifyTVar' (receivedBytes peer) (+fromIntegral (BA.length decryptedPayload))
              else 
                liftIO $ atomically $ writeTVar (lastKeepaliveTime peer) now
            return (Just (Right decryptedPayload))

runHeartbeat :: Device -> KeyPair -> PacketQueue UdpPacket -> IO ()
runHeartbeat device key chan = do
    psk <- readTVarIO (presharedKey device)
    now <- epochTime
    peers' <- readTVarIO (peers device)
    forM_ peers' $ \peer -> do
        reinitiate <- atomically $ do
            miwait <- readTVar (handshakeInitSt peer)
            case miwait of
                Just iwait | now >= initRekeyAttemptTime iwait -> do
                    void $ eraseHandshakeInit device peer Nothing
                    return Nothing
                Just iwait | now >= initRekeyTimeout iwait -> do
                    void $ eraseHandshakeInit device peer Nothing
                    return (Just (initRekeyAttemptTime iwait))
                _ -> return Nothing
        when (isJust reinitiate) $ withJust (atomically $ tryReadTMVar (endPoint peer)) $ \endp ->
            void $ tryInitiateHandshakeIfEmpty device key psk chan peer endp reinitiate
        atomically $ withJust (readTVar (handshakeRespSt peer)) $ \rwait ->
            when (now >= respStopTime rwait) $ void $ eraseHandshakeResp device peer Nothing
        atomically $ filterSessions device peer ((now<).expireTime)
        lastrecv <- readTVarIO (lastReceiveTime peer)
        lastsent <- readTVarIO (lastTransferTime peer)
        lastkeep <- readTVarIO (lastKeepaliveTime peer)
        when (lastsent < lastrecv && lastrecv <= addTime now (-sessionKeepaliveTime)) $ do
            atomically $ writeTVar (lastTransferTime peer) now
            atomically $ writeTVar (lastReceiveTime peer) now
            withJust (atomically $ tryReadTMVar (endPoint peer)) $ \endp ->
                withJust (getSession peer) $ \session -> do
                    nonce <- atomically $ nextNonce session
                    let (msg, authtag) = encryptMessage (sessionKey session) nonce mempty
                        keepalivePacket = runPut $ buildPacket (error "internal error") $
                            PacketData (theirIndex session) nonce msg authtag
                    pushPacketQueue chan (keepalivePacket, endp)
        when (lastrecv < lastsent && lastkeep < lastsent && lastsent <= addTime now (-(sessionKeepaliveTime + handshakeRetryTime))) $ do
            atomically $ writeTVar (lastTransferTime peer) now
            atomically $ writeTVar (lastReceiveTime peer) now
            withJust (atomically $ tryReadTMVar (endPoint peer)) $ \endp ->
                void $ checkAndTryInitiateHandshake device key psk chan peer endp now

checkAndTryInitiateHandshake :: Device -> KeyPair -> Maybe PresharedKey
                             -> PacketQueue UdpPacket -> Peer -> SockAddr -> Time
                             -> IO Bool
checkAndTryInitiateHandshake device key psk chan peer@Peer{..} endp now = do
    initiated <- readAndVerifyStopTime initRekeyAttemptTime handshakeInitSt (eraseHandshakeInit device peer Nothing)
    responded <- readAndVerifyStopTime respStopTime handshakeRespSt (eraseHandshakeResp device peer Nothing)
    if initiated || responded
      then return False
      else tryInitiateHandshakeIfEmpty device key psk chan peer endp Nothing
  where
    readAndVerifyStopTime getStopTime tvar erase = atomically $ do
        ma <- readTVar tvar
        case ma of
            Just a  | now > getStopTime a -> erase >> return False
            Just _  -> return True
            Nothing -> return False


tryInitiateHandshakeIfEmpty :: Device -> KeyPair -> Maybe PresharedKey
                            -> PacketQueue UdpPacket -> Peer -> SockAddr -> Maybe Time
                            -> IO Bool
tryInitiateHandshakeIfEmpty device key psk chan peer@Peer{..} endp stopTime = do
    ekey <- dhGenKey
    now <- epochTime
    seed <- randomIO
    let state0 = newNoiseState key psk ekey (Just remotePub) InitiatorRole
        Right (payload, state1) = sendFirstMessage state0 timestamp
        timestamp = BA.convert (genTai64n now)
    mpacket <- atomically $ do
        isEmpty <- isNothing <$> readTVar handshakeInitSt
        if isEmpty
          then do
            index <- acquireEmptyIndex device peer seed
            let iwait = HandshakeInit index
                    (addTime now handshakeRetryTime)
                    (fromMaybe (addTime now handshakeStopTime) stopTime)
                    state1
            writeTVar handshakeInitSt (Just iwait)
            let packet = runPut $ buildPacket (getMac1 remotePub psk) $
                    HandshakeInitiation index payload
            return (Just packet)
          else return Nothing
    case mpacket of
        Just packet -> pushPacketQueue chan (packet, endp) >> return True
        Nothing     -> return False



addTime :: Time -> Int -> Time
addTime (CTime now) secs = CTime (now + fromIntegral secs)

genTai64n :: Time -> TAI64n
genTai64n (CTime now) = runPut $ do
    putWord64be (fromIntegral now + 4611686018427387914)
    putWord32be 0
