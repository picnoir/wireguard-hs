{-# LANGUAGE RecordWildCards #-}

module Network.WireGuard.RPC
  ( OpType(..),
    RpcRequest(..),
    runRPC,
    serveConduit,
    bytesToPair,
    showDevice,
    showPeer
  ) where

import           Control.Concurrent.STM                    (STM, atomically,
                                                            modifyTVar', readTVar,
                                                            writeTVar)
import           Control.Monad                             (when)
import           Control.Monad.IO.Class                    (liftIO)
import qualified Crypto.Noise.DH                     as DH (dhPubToBytes, dhSecToBytes,
                                                            dhBytesToPair, dhBytesToPair,
                                                            dhBytesToPub)
import qualified Data.ByteArray                      as BA (convert)
import qualified Data.ByteString                     as BS (ByteString, concat,
                                                            replicate, empty)
import qualified Data.ByteString.Char8               as BC (pack, singleton, map)
import           Data.Char                                 (toLower)
import           Data.Conduit.Attoparsec                   (sinkParserEither) 
import           Data.Conduit.Network.Unix                 (appSink, appSource,
                                                            runUnixServer,
                                                            serverSettings)
import qualified Data.HashMap.Strict                 as HM ( delete, lookup, insert,
                                                            empty, elems)
import           Data.Hex                                  (hex)
import           Data.Int                                  (Int32)
import           Data.List                                 (foldl')
import           Data.Bits                                 (Bits(..))
import           Data.Conduit                              (ConduitM, (.|),
                                                            yield, runConduit)
import           Data.IP                                   (IPRange(..), addrRangePair,
                                                            toHostAddress, toHostAddress6,
                                                            fromHostAddress, makeAddrRange,
                                                            fromHostAddress6)
import           Data.Maybe                                (fromJust, isJust)

import           Network.WireGuard.Foreign.UAPI            (WgPeer(..), WgDevice(..),
                                                            WgIpmask(..),
                                                            peerFlagRemoveMe, peerFlagReplaceIpmasks,
                                                            deviceFlagRemoveFwmark, deviceFlagReplacePeers,
                                                            deviceFlagRemovePrivateKey, deviceFlagRemovePresharedKey)
import           Network.WireGuard.Internal.Constant       (keyLength)
import           Network.WireGuard.Internal.RpcParsers     (RpcRequest(..), RpcSetPayload(..), 
                                                            OpType(..), requestParser)
import           Network.WireGuard.Internal.State          (Device(..), Peer(..),
                                                            createPeer,
                                                            invalidateSessions)
import           Network.WireGuard.Internal.Data.Types     (PrivateKey, PublicKey,
                                                            PresharedKey, KeyPair)
import           Network.WireGuard.Internal.Util           (catchIOExceptionAnd)

-- | Run RPC service over a unix socket
runRPC :: FilePath -> Device -> IO ()
runRPC sockPath device = runUnixServer (serverSettings sockPath) $ \app ->
    catchIOExceptionAnd (return ()) $ 
      runConduit (appSource app .| serveConduit device .| appSink app)
    
-- TODO: ensure that all bytestring over sockets will be erased
serveConduit :: Device -> ConduitM BS.ByteString BS.ByteString IO ()
serveConduit device = do
  request <- sinkParserEither requestParser
  routeRequest request
  where
    --returnError = yield $ writeConfig (-invalidValueError)
    routeRequest (Left _) = yield mempty
    routeRequest (Right req) = 
      case opType req of
        Set -> undefined
        Get -> do
          deviceBstr <- liftIO . atomically $ showDevice device
          yield $ BS.concat [deviceBstr, BC.pack "errno=0\n\n"]

showDevice :: Device -> STM BS.ByteString
showDevice device@Device{..} = do
  listen_port   <- BC.pack . show <$> readTVar port
  fwm           <- BC.pack . show <$> readTVar fwmark
  private_key   <- fmap (toLowerBs . hex . privToBytes . fst) <$> readTVar localKey
  let devHm     = [("private_key", private_key),
                   ("listen_port", Just listen_port),
                   ("fwmark", Just fwm)]
  let devBs     = serializeRpcKeyValue devHm
  prs           <- readTVar peers 
  peersBstrList <-  mapM showPeer $ HM.elems prs
  return . BS.concat $ (devBs : peersBstrList)

showPeer :: Peer -> STM BS.ByteString
showPeer Peer{..} = do
  let hm                        =  HM.empty
  let public_key                =  toLowerBs . hex $ pubToBytes remotePub
  endpoint                      <- readTVar endPoint
  persistant_keepalive_interval <- readTVar keepaliveInterval
  allowed_ip                    <- readTVar ipmasks
  rx_bytes                      <- readTVar receivedBytes
  tx_bytes                      <- readTVar transferredBytes
  last_handshake_time           <- readTVar lastHandshakeTime
  let peer = [("public_key", Just public_key),
              ("endpoint", BC.pack . show <$> endpoint),
              ("persistent_keepalive_interval", Just . BC.pack . show $ persistant_keepalive_interval),
              ("tx_bytes", Just . BC.pack . show $ tx_bytes),
              ("rx_bytes", Just . BC.pack . show $ rx_bytes),
              ("last_handshake_time", BC.pack . show <$> last_handshake_time)
              ] ++ expandAllowedIps (Just . BC.pack . show <$> allowed_ip)
  return $ serializeRpcKeyValue peer
  where
    expandAllowedIps = foldr (\val acc -> ("allowed_ip", val):acc) []

serializeRpcKeyValue :: [(String, Maybe BS.ByteString)] -> BS.ByteString
serializeRpcKeyValue = foldl' showKeyValueLine BS.empty
  where
    showKeyValueLine acc (key, Just val) 
      | val == BC.pack "0" = acc
      | otherwise          = BS.concat [acc, BC.pack key, BC.singleton '=', val, BC.singleton '\n']
    showKeyValueLine acc (_, Nothing) = acc


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

toLowerBs :: BS.ByteString -> BS.ByteString
toLowerBs = BC.map toLower 

testFlag :: Bits a => a -> a -> Bool
testFlag a flag = (a .&. flag) /= zeroBits
