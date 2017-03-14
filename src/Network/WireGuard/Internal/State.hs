{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections   #-}

module Network.WireGuard.Internal.State
  ( PeerId
  , Device(..)
  , Peer(..)
  , InitiatorWait(..)
  , ResponderWait(..)
  , Session(..)
  , createDevice
  , createPeer
  , invalidateSessions
  , buildRouteTables
  , acquireEmptyIndex
  , removeIndex
  , nextNonce
  , eraseInitiatorWait
  , eraseResponderWait
  , getSession
  , waitForSession
  , findSession
  , addSession
  , filterSessions
  , updateTai64n
  , updateEndPoint
  ) where

import           Control.Monad                       (forM, when)
import           Crypto.Noise                        (NoiseState)
import           Crypto.Noise.Cipher.ChaChaPoly1305  (ChaChaPoly1305)
import           Crypto.Noise.DH.Curve25519          (Curve25519)
import           Crypto.Noise.Hash.BLAKE2s           (BLAKE2s)
import qualified Data.HashMap.Strict                 as HM
import           Data.IP                             (IPRange (..), IPv4, IPv6)
import qualified Data.IP.RouteTable                  as RT
import           Data.Maybe                          (catMaybes, fromJust,
                                                      isNothing, mapMaybe)
import           Data.Word
import           Network.Socket.Internal             (SockAddr)

import           Control.Concurrent.STM

import           Network.WireGuard.Internal.Constant
import           Network.WireGuard.Internal.Types

data Device = Device
            { intfName     :: String
            , localKey     :: TVar (Maybe KeyPair)
            , presharedKey :: TVar (Maybe PresharedKey)
            , fwmark       :: TVar Word
            , port         :: TVar Int
            , peers        :: TVar (HM.HashMap PeerId Peer)
            , routeTable4  :: TVar (RT.IPRTable IPv4 Peer)
            , routeTable6  :: TVar (RT.IPRTable IPv6 Peer)
            , indexMap     :: TVar (HM.HashMap Index Peer)
            }

data Peer = Peer
          { remotePub         :: !PublicKey
          , ipmasks           :: TVar [IPRange]
          , endPoint          :: TVar (Maybe SockAddr)
          , lastHandshakeTime :: TVar (Maybe Time)
          , receivedBytes     :: TVar Word64
          , transferredBytes  :: TVar Word64
          , keepaliveInterval :: TVar Int
          , initiatorWait     :: TVar (Maybe InitiatorWait)
          , responderWait     :: TVar (Maybe ResponderWait)
          , sessions          :: TVar [Session]  -- last two active sessions
          , lastTai64n        :: TVar TAI64n
          , lastReceiveTime   :: TVar Time
          , lastTransferTime  :: TVar Time
          , lastKeepaliveTime :: TVar Time
          }

data InitiatorWait = InitiatorWait
                   { initOurIndex  :: !Index
                   , initRetryTime :: !Time
                   , initStopTime  :: !Time
                   , initNoise     :: !(NoiseState ChaChaPoly1305 Curve25519 BLAKE2s)
                   }

data ResponderWait = ResponderWait
                   { respOurIndex   :: !Index
                   , respTheirIndex :: !Index
                   , respStopTime   :: !Time
                   , respSessionKey :: !SessionKey
                   }

data Session = Session
             { ourIndex       :: !Index
             , theirIndex     :: !Index
             , sessionKey     :: !SessionKey
             , renewTime      :: !Time
             , expireTime     :: !Time
             , sessionCounter :: TVar Counter
             -- TODO: avoid nonce reuse from remote peer
             }

createDevice :: String -> STM Device
createDevice intf = Device intf <$> newTVar Nothing
                                <*> newTVar Nothing
                                <*> newTVar 0
                                <*> newTVar 0
                                <*> newTVar HM.empty
                                <*> newTVar RT.empty
                                <*> newTVar RT.empty
                                <*> newTVar HM.empty

createPeer :: PublicKey -> STM Peer
createPeer rpub = Peer rpub <$> newTVar []
                            <*> newTVar Nothing
                            <*> newTVar Nothing
                            <*> newTVar 0
                            <*> newTVar 0
                            <*> newTVar 0
                            <*> newTVar Nothing
                            <*> newTVar Nothing
                            <*> newTVar []
                            <*> newTVar mempty
                            <*> newTVar farFuture
                            <*> newTVar farFuture
                            <*> newTVar 0

invalidateSessions :: Device -> STM ()
invalidateSessions Device{..} = do
    writeTVar indexMap HM.empty
    readTVar peers >>= mapM_ invalidatePeerSessions
  where
    invalidatePeerSessions Peer{..} = do
        writeTVar lastHandshakeTime Nothing
        writeTVar initiatorWait Nothing
        writeTVar responderWait Nothing
        writeTVar sessions []

buildRouteTables :: Device -> STM ()
buildRouteTables Device{..} = do
    gather pickIPv4 >>= writeTVar routeTable4 . RT.fromList . concat
    gather pickIPv6 >>= writeTVar routeTable6 . RT.fromList . concat
  where
    gather pick = do
        peers' <- readTVar peers
        forM peers' $ \peer ->
            map (,peer) . mapMaybe pick <$> readTVar (ipmasks peer)
    pickIPv4 (IPv4Range ipv4) = Just ipv4
    pickIPv4 _                = Nothing
    pickIPv6 (IPv6Range ipv6) = Just ipv6
    pickIPv6 _                = Nothing

acquireEmptyIndex :: Device -> Peer -> Index -> STM Index
acquireEmptyIndex device peer seed = do
    imap <- readTVar (indexMap device)
    let findEmpty idx
            | HM.member idx imap = findEmpty (idx * 3 + 1)
            | otherwise          = idx
        emptyIndex = findEmpty seed
    writeTVar (indexMap device) $ HM.insert emptyIndex peer imap
    return emptyIndex

removeIndex :: Device -> Index -> STM ()
removeIndex device index = modifyTVar' (indexMap device) (HM.delete index)

nextNonce :: Session -> STM Counter
nextNonce Session{..} = do
    nonce <- readTVar sessionCounter
    writeTVar sessionCounter (nonce + 1)
    return nonce

eraseInitiatorWait :: Device -> Peer -> Maybe Index -> STM Bool
eraseInitiatorWait device Peer{..} index = do
    miwait <- readTVar initiatorWait
    case miwait of
        Just iwait | isNothing index || initOurIndex iwait == fromJust index -> do
            writeTVar initiatorWait Nothing
            when (isNothing index) $ removeIndex device (initOurIndex iwait)
            return True
        _ -> return False

eraseResponderWait :: Device -> Peer -> Maybe Index -> STM Bool
eraseResponderWait device Peer{..} index = do
    mrwait <- readTVar responderWait
    case mrwait of
        Just rwait | isNothing index || respOurIndex rwait == fromJust index -> do
            writeTVar responderWait Nothing
            when (isNothing index) $ removeIndex device (respOurIndex rwait)
            return True
        _ -> return False

getSession :: Peer -> IO (Maybe Session)
getSession peer = do
    sessions' <- readTVarIO (sessions peer)
    case sessions' of
        []    -> return Nothing
        (s:_) -> return (Just s)

waitForSession :: Int -> Peer -> IO (Maybe Session)
waitForSession timelimit peer = do
    getTimeout <- registerDelay timelimit
    atomically $ do
        sessions' <- readTVar (sessions peer)
        case sessions' of
            []    -> do
                timeout <- readTVar getTimeout
                if timeout
                  then return Nothing
                  else retry
            (s:_) -> return (Just s)

findSession :: Peer -> Index -> STM (Maybe (Either ResponderWait Session))
findSession peer index = do
    sessions' <- filter ((==index).ourIndex) <$> readTVar (sessions peer)
    case sessions' of
        (s:_) -> return (Just (Right s))
        []    -> do
            mrwait <- readTVar (responderWait peer)
            case mrwait of
                Just rwait | respOurIndex rwait == index -> return (Just (Left rwait))
                _                                        -> return Nothing


addSession :: Device -> Peer -> Session -> STM ()
addSession device peer session = do
    (toKeep, toDrop) <- splitAt maxActiveSessions . (session:) <$> readTVar (sessions peer)
    mapM_ (removeIndex device . ourIndex) toDrop
    writeTVar (sessions peer) toKeep

filterSessions :: Device -> Peer -> (Session -> Bool) -> STM ()
filterSessions device peer cond = do
    sessions' <- readTVar (sessions peer)
    filtered <- fmap catMaybes $ forM sessions' $ \session ->
        if cond session
          then return (Just session)
          else do
            removeIndex device (ourIndex session)
            return Nothing
    writeTVar (sessions peer) filtered

updateTai64n :: Peer -> TAI64n -> STM Bool
updateTai64n peer tai64n = do
    lastTai64n' <- readTVar (lastTai64n peer)
    if tai64n <= lastTai64n'
      then return False
      else do
        writeTVar (lastTai64n peer) tai64n
        return True

updateEndPoint :: Peer -> SockAddr -> STM ()
updateEndPoint peer sock = writeTVar (endPoint peer) (Just sock)
