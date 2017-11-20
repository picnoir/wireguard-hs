{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections   #-}

{-|
Module      : Network.WireGuard.Internal.State.
Description : STM state shared across the different threads.
License     : GPL-3
Maintainer  : felix@alternativebit.fr
Stability   : experimental
Portability : POSIX

STM state shared across the different threads.
-}

module Network.WireGuard.Internal.State
  ( PeerId
  , Device(..)
  , Peer(..)
  , HandshakeInit(..)
  , HandshakeResp(..)
  , Session(..)
  , createDevice
  , createPeer
  , invalidateSessions
  , buildRouteTables
  , acquireEmptyIndex
  , removeIndex
  , nextNonce
  , eraseHandshakeInit 
  , eraseHandshakeResp
  , getSession
  , waitForSession
  , findSession
  , addSession
  , filterSessions
  , updateTai64n
  , updateEndPoint
  , appendNewSessionToState
  ) where

import           Control.Monad                       (forM, when)
import           Crypto.Noise                        (NoiseState)
import           Crypto.Noise.Cipher.ChaChaPoly1305  (ChaChaPoly1305)
import           Crypto.Noise.DH.Curve25519          (Curve25519)
import           Crypto.Noise.Hash.BLAKE2s           (BLAKE2s)
import qualified Data.HashMap.Strict                 as HM (HashMap, empty, member,
                                                            insert, delete)
import           Data.IP                             (IPRange (..), IPv4, IPv6)
import qualified Data.IP.RouteTable                  as RT (IPRTable, empty, fromList)
import           Data.Maybe                          (catMaybes, fromJust,
                                                      isNothing, mapMaybe,
                                                      fromMaybe)
import           Data.Word                           (Word64)
import           Network.Socket.Internal             (SockAddr)
import           Control.Concurrent.STM              (TMVar, TVar, STM, newTVar,
                                                      writeTVar, readTVar,
                                                      modifyTVar', readTVarIO,
                                                      registerDelay, atomically,
                                                      retry, newEmptyTMVar)

import           Network.WireGuard.Internal.Constant   (maxActiveSessions, sessionRenewTime,
                                                        handshakeRetryTime, sessionExpireTime)
import           Network.WireGuard.Internal.Util       (writeMaybeTMVar, addTime)
import           Network.WireGuard.Internal.Data.Types (KeyPair, PresharedKey, PeerId,
                                                        Index, PublicKey, Time,
                                                        TAI64n, SessionKey, Counter,
                                                        farFuture)
import           Network.WireGuard.Internal.Data.Peer  (PeerStreamAsyncs)
import           Network.WireGuard.Internal.Data.QueueSystem (PeerQueues)

-- | STM data structure storing device-related informations.
data Device = Device
            { -- | Interface name (EG. wg0)
              intfName     :: String,
              -- | Local static key. 32 bits Curve25519 key couple.
              localKey     :: TMVar KeyPair,
              -- | TODO: refactor this key to the peer datastructure.
              presharedKey :: TVar (Maybe PresharedKey),
              -- | Firewall mark.
              fwmark       :: TVar Word,
              -- | Listening UDP port.
              port         :: TVar Int,
              -- | Remote known hosts 32 bits Curve25519 public keys.
              peers        :: TVar (HM.HashMap PeerId Peer),
              -- | IPV4 routing table.
              routeTable4  :: TVar (RT.IPRTable IPv4 Peer),
              -- | IPV6 routing table.
              routeTable6  :: TVar (RT.IPRTable IPv6 Peer),
              -- | Local index/peer associative table.
              indexMap     :: TVar (HM.HashMap Index Peer)
            }
             
-- | Remote peer STM data structure.
data Peer = Peer
          { -- | Peer's  32 bits Curve 25519 public key. 
            remotePub         :: !PublicKey,
            -- | Peer's asynchronous processes listening to various
            -- internal queues.
            asyncs            :: TMVar PeerStreamAsyncs,
            -- | Queues associated with this peer.
            queues            :: TMVar PeerQueues,
            -- | Authorized origin IP ranges for this peer.
            ipmasks           :: TVar [IPRange],
            -- | Last known remote address.
            endPoint          :: TMVar SockAddr,
            lastHandshakeTime :: TVar (Maybe Time),
            receivedBytes     :: TVar Word64,
            transferredBytes  :: TVar Word64,
            keepaliveInterval :: TVar Int,
            -- | Handshake initiation state.
            handshakeInitSt   :: TVar (Maybe HandshakeInit),
            -- | Handshake response state.
            handshakeRespSt   :: TVar (Maybe HandshakeResp),
            -- | Last two active sessions
            sessions          :: TVar [Session],
            -- | Variable used for internal synchronisation. Empty if there is no
            --   active session, empty otherwise.
            activeSession     :: TMVar (),
            -- | Last init handshake time. Used to prevent replay attacks.
            lastTai64n        :: TVar TAI64n,
            lastReceiveTime   :: TVar Time,
            lastTransferTime  :: TVar Time,
            lastKeepaliveTime :: TVar Time
          }

-- | Handshake initiation state.
data HandshakeInit = HandshakeInit
                   { -- | Our index. 32 bits locally randomly generated integer. This integer 
                     --   will be used to identify the remote peer. Analogous to IPsec's "SPI".
                     initOurIndex         :: !Index,
                     -- | Time after which the initial handshake message should be replayed.
                     initRekeyTimeout     :: !Time,
                     -- | Time after which the handshake should be aborded.
                     initRekeyAttemptTime :: !Time,
                     -- | Noise state.
                     initNoise            :: !(NoiseState ChaChaPoly1305 Curve25519 BLAKE2s)
                   }

-- | Handshake response local state.
data HandshakeResp = HandshakeResp
                   { -- | Our index. 32 bits locally randomly generated integer. This integer 
                     --   will be used to identify the remote peer. Analogous to IPsec's "SPI".
                     respOurIndex   :: !Index,
                     -- | Remote peer index, we use this index to indentify ourselves when sending a message to the remote peer.
                     respTheirIndex :: !Index,
                     -- | Time after wich the session should be renewed.
                     respStopTime   :: !Time,
                     -- | Generated ephemeral session key.
                     respSessionKey :: !SessionKey
                   }

-- | Wireguard session related data
data Session = Session
             { -- | 32 bits integer by which the remote peer indexes us.
               --   This index has been generated by the remote peer.
               ourIndex       :: !Index,
               -- | 32 bit integer locally generated indexing the remote peer.
               theirIndex     :: !Index,
               -- | 32 bit integer locally generated indexing the remote peer.
               sessionKey     :: !SessionKey,
               -- | Passed that time, we need to generate a new session with the remote peer.
               renewTime      :: !Time,
               -- | Passed that time, we will reject any incoming packet from that host.
               expireTime     :: !Time,
               -- | Nonce counter.
               sessionCounter :: TVar Counter
             -- TODO: avoid nonce reuse from remote peer
             }

-- | Creates a new device with its associated empty STM
-- shared variables.
createDevice :: String -> STM Device
createDevice intf = Device intf <$> newEmptyTMVar
                                <*> newTVar Nothing
                                <*> newTVar 0
                                <*> newTVar 0
                                <*> newTVar HM.empty
                                <*> newTVar RT.empty
                                <*> newTVar RT.empty
                                <*> newTVar HM.empty

-- | Creates a new Peer with its associated empty STM
-- shared variables.
createPeer :: PublicKey -> STM Peer
createPeer rpub = Peer rpub <$> newEmptyTMVar
                            <*> newEmptyTMVar
                            <*> newTVar []
                            <*> newEmptyTMVar
                            <*> newTVar Nothing
                            <*> newTVar 0
                            <*> newTVar 0
                            <*> newTVar 0
                            <*> newTVar Nothing
                            <*> newTVar Nothing
                            <*> newTVar []
                            <*> newEmptyTMVar
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
        writeTVar handshakeInitSt Nothing
        writeTVar handshakeRespSt Nothing
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

eraseHandshakeInit :: Device -> Peer -> Maybe Index -> STM Bool
eraseHandshakeInit device Peer{..} index = do
    miwait <- readTVar handshakeInitSt
    case miwait of
        Just iwait | isNothing index || initOurIndex iwait == fromJust index -> do
            writeTVar handshakeInitSt Nothing
            when (isNothing index) $ removeIndex device (initOurIndex iwait)
            return True
        _ -> return False

eraseHandshakeResp :: Device -> Peer -> Maybe Index -> STM Bool
eraseHandshakeResp device Peer{..} index = do
    mrwait <- readTVar handshakeRespSt
    case mrwait of
        Just rwait | isNothing index || respOurIndex rwait == fromJust index -> do
            writeTVar handshakeRespSt Nothing
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

findSession :: Peer -> Index -> STM (Maybe (Either HandshakeResp Session))
findSession peer index = do
    sessions' <- filter ((==index).ourIndex) <$> readTVar (sessions peer)
    case sessions' of
        (s:_) -> return (Just (Right s))
        []    -> do
            mrwait <- readTVar (handshakeRespSt peer)
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
updateEndPoint peer sock = writeMaybeTMVar (endPoint peer) (Just sock)

appendNewSessionToState :: Peer -> Time -> STM ()
appendNewSessionToState peer now = do
   prevS         <- readTVar $ sessions peer
   handshakeRespM <-  readTVar $ handshakeRespSt peer
   let handshakeResp = fromMaybe (error "No session") handshakeRespM
   newCounter    <- newTVar 0
   let newSession = Session (respOurIndex handshakeResp) (respTheirIndex handshakeResp) 
                     (respSessionKey handshakeResp)
                     (addTime now (sessionRenewTime + 2 * handshakeRetryTime))
                     (addTime now sessionExpireTime)
                     newCounter
   let newS = case prevS of
                 []     -> [newSession] 
                 (ps:_) -> [newSession, ps]
   writeTVar (sessions peer) newS
   return ()
