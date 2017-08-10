{-# LANGUAGE RecordWildCards #-}

module Network.WireGuard.RPC
  ( runRPC,
    serveConduit
  ) where

import           Control.Concurrent.STM              (STM, atomically,
                                                      modifyTVar', readTVar,
                                                      writeTVar)
import           Control.Monad                       (replicateM, sequence,
                                                      when)
import           Control.Monad.IO.Class              (liftIO)
import qualified Crypto.Noise.DH                     as DH
import qualified Data.ByteArray                      as BA
import qualified Data.ByteString                     as BS
import qualified Data.Conduit.Binary                 as CB
import           Data.Conduit.Network.Unix           (appSink, appSource,
                                                      runUnixServer,
                                                      serverSettings)
import qualified Data.HashMap.Strict                 as HM
import           Data.Int                            (Int32)
import           Data.List                           (genericLength)
import           Foreign.C.Types                     (CTime (..))

import           Data.Bits
import           Data.Conduit
import           Data.IP
import           Data.Maybe

import           Network.WireGuard.Foreign.UAPI
import           Network.WireGuard.Internal.Constant
import           Network.WireGuard.Internal.State
import           Network.WireGuard.Internal.Types
import           Network.WireGuard.Internal.Util     (catchIOExceptionAnd,
                                                      catchSomeExceptionAnd)

import Debug.Trace
-- | Run RPC service over a unix socket
runRPC :: FilePath -> Device -> IO ()
runRPC sockPath device = runUnixServer (serverSettings sockPath) $ \app ->
    catchIOExceptionAnd (return ()) $ runConduit (appSource app .| serveConduit device .| appSink app)
    
-- TODO: ensure that all bytestring over sockets will be erased
serveConduit :: Device -> ConduitM BS.ByteString BS.ByteString IO ()
serveConduit device = do
        h <- CB.head
        traceM $  "Received " ++ show h
        case h of
            Just 0 -> showDevice device
            Just byte -> do
                leftover (BS.singleton byte)
                mWgdev <- CB.sinkStorable
                case mWgdev of
                    Just wgdev -> catchSomeExceptionAnd returnError (updateDevice wgdev)
                    Nothing    -> mempty
            Nothing   -> mempty
  where
    returnError = yield $ writeConfig (-invalidValueError)

    showDevice Device{..} = do
        (wgdevice, peers') <- liftIO buildWgDevice
        yield (writeConfig wgdevice)
        mapM_ showPeer peers'
      where
        buildWgDevice = atomically $ do
            localKey' <- readTVar localKey
            let (pub, priv) = case localKey' of
                    Nothing          -> (emptyKey, emptyKey)
                    Just (sec, pub') -> (pubToBytes pub', privToBytes sec)
            psk' <- fmap pskToBytes <$> readTVar presharedKey
            fwmark' <- fromIntegral <$> readTVar fwmark
            port' <- fromIntegral <$> readTVar port
            peers' <- readTVar peers
            return (WgDevice intfName 0 pub priv (fromMaybe emptyKey psk')
                fwmark' port' (fromIntegral $ HM.size peers'), peers')

    showPeer Peer{..} = do
        (wgpeer, ipmasks') <- liftIO buildWgPeer
        yield (writeConfig wgpeer)
        yield $ BS.concat (map (writeConfig . ipRangeToWgIpmask) ipmasks')
      where
        extractTime Nothing          = 0
        extractTime (Just (CTime t)) = fromIntegral t

        buildWgPeer = atomically $ do
            ipmasks' <- readTVar ipmasks
            wgpeer <- WgPeer (pubToBytes remotePub)
                          <$> return 0
                          <*> readTVar endPoint
                          <*> (extractTime <$> readTVar lastHandshakeTime)
                          <*> (fromIntegral <$> readTVar receivedBytes)
                          <*> (fromIntegral <$> readTVar transferredBytes)
                          <*> (fromIntegral <$> readTVar keepaliveInterval)
                          <*> return (genericLength ipmasks')
            return (wgpeer, ipmasks')

    updateDevice wgdevice = do
        setPeerMs <- replicateM (fromIntegral $ deviceNumPeers wgdevice) $ do
            Just wgpeer <- CB.sinkStorable
            -- TODO: replace fromJust
            ipranges <- replicateM (fromIntegral $ peerNumIpmasks wgpeer)
                (wgIpmaskToIpRange . fromJust <$> CB.sinkStorable)
            return $ setPeer device wgpeer ipranges
        liftIO $ atomically $ do
            setDevice device wgdevice
            anyIpMaskChanged <- or <$> sequence setPeerMs
            -- TODO: modify routetable incrementally
            when anyIpMaskChanged $ buildRouteTables device
        yield $ writeConfig (0 :: Int32)

-- | implementation of config.c::set_peer()
setPeer :: Device -> WgPeer -> [IPRange] -> STM Bool
setPeer Device{..} WgPeer{..} ipranges
    | peerPubKey == emptyKey              = return False
    | testFlag peerFlags peerFlagRemoveMe = modifyTVar' peers (HM.delete peerPubKey) >> return False
    | otherwise                           = do
        peers' <- readTVar peers
        Peer{..} <- case HM.lookup peerPubKey peers' of
            Nothing -> do
                newPeer <- createPeer (fromJust $ bytesToPub peerPubKey) -- TODO: replace fromJust
                modifyTVar' peers (HM.insert peerPubKey newPeer)
                return newPeer
            Just p  -> return p
        when (isJust peerAddr) $ writeTVar endPoint peerAddr
        let replaceIpmasks = testFlag peerFlags peerFlagReplaceIpmasks
            changeIpmasks = replaceIpmasks || not (null ipranges)
        when changeIpmasks $
            if replaceIpmasks
              then writeTVar ipmasks ipranges
              else modifyTVar' ipmasks (++ipranges)
        when (peerKeepaliveInterval /= complement 0) $
            writeTVar keepaliveInterval (fromIntegral peerKeepaliveInterval)
        return changeIpmasks

-- | implementation of config.c::config_set_device()
setDevice :: Device -> WgDevice -> STM ()
setDevice device@Device{..} WgDevice{..} = do
    when (deviceFwmark /= 0 || deviceFwmark == 0 && testFlag deviceFlags deviceFlagRemoveFwmark) $
        writeTVar fwmark (fromIntegral deviceFwmark)
    when (devicePort /= 0) $ writeTVar port (fromIntegral devicePort)
    when (testFlag deviceFlags deviceFlagReplacePeers) $ writeTVar peers HM.empty

    let removeLocalKey = testFlag deviceFlags deviceFlagRemovePrivateKey
        changeLocalKey = removeLocalKey || devicePrivkey /= emptyKey
        changeLocalKeyTo = if removeLocalKey then Nothing else bytesToPair devicePrivkey
    when changeLocalKey $ writeTVar localKey changeLocalKeyTo

    let removePSK = testFlag deviceFlags deviceFlagRemovePresharedKey
        changePSK = removePSK || devicePSK /= emptyKey
        changePSKTo = if removePSK then Nothing else Just (bytesToPSK devicePSK)
    when changePSK $ writeTVar presharedKey changePSKTo

    when (changeLocalKey || changePSK) $ invalidateSessions device

ipRangeToWgIpmask :: IPRange -> WgIpmask
ipRangeToWgIpmask (IPv4Range ipv4range) = case addrRangePair ipv4range of
    (ipv4, prefix) -> WgIpmask (Left (toHostAddress ipv4)) (fromIntegral prefix)
ipRangeToWgIpmask (IPv6Range ipv6range) = case addrRangePair ipv6range of
    (ipv6, prefix) -> WgIpmask (Right (toHostAddress6 ipv6)) (fromIntegral prefix)

wgIpmaskToIpRange :: WgIpmask -> IPRange
wgIpmaskToIpRange (WgIpmask ip cidr) = case ip of
    Left ipv4  -> IPv4Range $ makeAddrRange (fromHostAddress ipv4) (fromIntegral cidr)
    Right ipv6 -> IPv6Range $ makeAddrRange (fromHostAddress6 ipv6) (fromIntegral cidr)

invalidValueError :: Int32
invalidValueError = 22  -- TODO: report back actual error

emptyKey :: BS.ByteString
emptyKey = BS.replicate keyLength 0

testFlag :: Bits a => a -> a -> Bool
testFlag a flag = (a .&. flag) /= zeroBits

pubToBytes :: PublicKey -> BS.ByteString
pubToBytes = BA.convert . DH.dhPubToBytes

privToBytes :: PrivateKey -> BS.ByteString
privToBytes = BA.convert . DH.dhSecToBytes

pskToBytes :: PresharedKey -> BS.ByteString
pskToBytes = BA.convert

bytesToPair :: BS.ByteString -> Maybe KeyPair
bytesToPair = DH.dhBytesToPair . BA.convert

bytesToPub :: BS.ByteString -> Maybe PublicKey
bytesToPub = DH.dhBytesToPub . BA.convert

bytesToPSK :: BS.ByteString -> PresharedKey
bytesToPSK = BA.convert
