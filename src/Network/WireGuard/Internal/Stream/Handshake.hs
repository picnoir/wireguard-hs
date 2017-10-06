{-# LANGUAGE RecordWildCards #-}
module Network.WireGuard.Internal.Stream.Handshake
(
  handshakeInit,
  processHandshakeInitiation,
  processHandshakeResponse
) where

import qualified Data.ByteArray                  as BA  (convert, length)
import qualified Data.HashMap.Strict             as HM  (lookup)
import qualified Data.ByteString                 as BS  (ByteString)
import           Data.Serialize                         (putWord32be,
                                                         putWord64be, runPut)
import           Data.Maybe                             (isNothing, fromMaybe)
import           Control.Monad                          (when, unless, void)
import           Control.Monad.Trans.Except             (ExceptT, throwE)
import           Control.Monad.STM                      (STM)
import           Control.Monad.Trans.Maybe              (MaybeT)
import           Control.Monad.Trans.Class              (lift)
import           Control.Concurrent.STM.TVar            (readTVar, writeTVar, newTVar)
import           Crypto.Noise                           (HandshakeRole(..))
import           Crypto.Noise.DH                        (dhPubToBytes)
import           Crypto.Hash.BLAKE2.BLAKE2s             (finalize, update, initialize,
                                                         initialize')
import           Network.Socket                         (SockAddr)
import           Foreign.C.Types                        (CTime(..))

import Network.WireGuard.Internal.Constant
import Network.WireGuard.Internal.Data.Types
import Network.WireGuard.Internal.Data.Handshake
import Network.WireGuard.Internal.State
import Network.WireGuard.Internal.Packet
import Network.WireGuard.Internal.Noise

handshakeInit :: HandshakeInitSeed -> Device -> KeyPair -> Maybe PresharedKey
                            -> Peer -> Maybe Time
                            -> MaybeT STM BS.ByteString
handshakeInit seed device key psk peer@Peer{..} stopTime = do
    let ekey   = handshakeEphemeralKey seed
    let now    = handshakeNowTS seed
    let hsSeed = handshakeSeed seed
    let state0 = newNoiseState key psk ekey (Just remotePub) InitiatorRole
        Right (payload, state1) = sendFirstMessage state0 timestamp
        timestamp = BA.convert (genTai64n now)
    mpacket <- do
        isEmpty <- lift $ isNothing <$> readTVar initiatorWait
        if isEmpty
          then do
            index <- lift $ acquireEmptyIndex device peer hsSeed
            let iwait = InitiatorWait index
                    (addTime now handshakeRetryTime)
                    (fromMaybe (addTime now handshakeStopTime) stopTime)
                    state1
            lift $ writeTVar initiatorWait (Just iwait)
            let packet = runPut $ buildPacket (getMac1 remotePub psk) $
                    HandshakeInitiation index payload
            return (Just packet)
          else return Nothing
    case mpacket of
        Just packet -> return packet
        Nothing     -> fail "Packet not generated"

processHandshakeInitiation :: HandshakeInitSeed -> Device -> KeyPair -> Maybe PresharedKey -> SockAddr -> Packet
              -> ExceptT WireGuardError STM (Maybe (Either UdpPacket TunPacket))
processHandshakeInitiation InitHandshakeSeed{..} device@Device{..} key psk sock HandshakeInitiation{..} = do
    let ekey   = handshakeEphemeralKey 
    let now    = handshakeNowTS 
    let hsSeed = handshakeSeed 
    let state0 = newNoiseState key psk ekey Nothing ResponderRole
        outcome = recvFirstMessageAndReply state0 encryptedPayload mempty
    case outcome of
        Left err                                   -> throwE (NoiseError err)
        Right (reply, decryptedPayload, rpub, sks) -> do
            when (BA.length decryptedPayload /= timestampLength) $
                throwE $ InvalidWGPacketError "timestamp expected"
            peer <- assertJust RemotePeerNotFoundError $
                HM.lookup (getPeerId rpub) <$> lift (readTVar peers)
            notReplayAttack <- lift $ updateTai64n peer (BA.convert decryptedPayload)
            unless notReplayAttack $ throwE HandshakeInitiationReplayError
            ourindex <- do
                ourindex <- lift $ acquireEmptyIndex device peer hsSeed
                void $ lift $ eraseResponderWait device peer Nothing
                let rwait = ResponderWait ourindex senderIndex
                        (addTime now handshakeStopTime) sks
                lift $ writeTVar (responderWait peer) (Just rwait)
                return ourindex
            let responsePacket = runPut $ buildPacket (getMac1 rpub psk) $
                    HandshakeResponse ourindex senderIndex reply
            return $ Just (Left (responsePacket, sock))

processHandshakeResponse :: HandshakeRespSeed -> Device -> KeyPair -> Maybe PresharedKey -> SockAddr -> Packet
              -> ExceptT WireGuardError STM (Maybe (Either UdpPacket TunPacket))
processHandshakeResponse now device@Device{..} _key _psk sock HandshakeResponse{..} = do
    peer <- assertJust UnknownIndexError $
        HM.lookup receiverIndex <$> lift (readTVar indexMap)
    iwait <- assertJust OutdatedPacketError $ lift (readTVar (initiatorWait peer))
    when (initOurIndex iwait /= receiverIndex) $ throwE OutdatedPacketError
    let state1 = initNoise iwait
        outcome = recvSecondMessage state1 encryptedPayload
    case outcome of
        Left err                      -> throwE (NoiseError err)
        Right (decryptedPayload, sks) -> do
            newCounter <- lift $ newTVar 0
            let newsession = Session receiverIndex senderIndex sks
                    (addTime now sessionRenewTime)
                    (addTime now sessionExpireTime)
                    newCounter
            when (BA.length decryptedPayload /= 0) $
                throwE $ InvalidWGPacketError "empty payload expected"
            succeeded <- lift $ do
                erased <- eraseInitiatorWait device peer (Just receiverIndex)
                when erased $ do
                    addSession device peer newsession
                    writeTVar (lastHandshakeTime peer) (Just now)
                return erased
            unless succeeded $ throwE OutdatedPacketError
            lift $ updateEndPoint peer sock
            return Nothing

genTai64n :: Time -> TAI64n
genTai64n (CTime now) = runPut $ do
    putWord64be (fromIntegral now + 4611686018427387914)
    putWord32be 0

addTime :: Time -> Int -> Time
addTime (CTime now) secs = CTime (now + fromIntegral secs)

getMac1 :: PublicKey -> Maybe PresharedKey -> BS.ByteString -> BS.ByteString
getMac1 pub mpsk payload =
    finalize mac1Length $ update payload $ update (BA.convert (dhPubToBytes pub)) $
        case mpsk of
            Nothing  -> initialize mac1Length
            Just psk -> initialize' mac1Length (BA.convert psk)

assertJust :: Monad m => e -> ExceptT e m (Maybe a) -> ExceptT e m a
assertJust err ma = do
    res <- ma
    case res of
        Just a  -> return a
        Nothing -> throwE err
