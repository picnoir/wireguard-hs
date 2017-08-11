module Network.WireGuard.RPCSpec (spec) where

import Control.Monad.STM                           (atomically, STM)
import Control.Concurrent.STM.TVar                 (writeTVar)
import qualified Data.ByteArray             as BA (convert)
import qualified Data.ByteString            as BS  (ByteString)
import qualified Data.ByteString.Lazy       as BSL (ByteString, isSuffixOf)
import qualified Data.ByteString.Char8      as BC  (pack)
import qualified Data.ByteString.Lazy.Char8 as BCL (pack)
import           Data.Maybe                        (fromJust)
import           Data.Hex                          (unhex)
import           Data.IP                           (AddrRange, IPv4, IPRange(..))
import qualified Crypto.Noise.DH            as DH  (dhBytesToPair, dhBytesToPub)
import Data.Conduit                                (runConduit, yield, ( .|))
import Data.Conduit.Binary                         (sinkLbs)
import Network.Socket                              (SockAddr(..), tupleToHostAddress)
import Test.Hspec                                  (Spec, describe,
                                                    it, shouldBe,
                                                    shouldSatisfy)
import Network.WireGuard.RPC            (serveConduit, showPeer)
import Network.WireGuard.Internal.State (Device(..), Peer(..),
                                         createDevice, createPeer)
import Network.WireGuard.Internal.Types (PresharedKey)

spec :: Spec
spec = do
      describe "serveConduit" $ do
        it "must correctly respond to a malformed request" $ do
          devStm <- testDevice
          device <- atomically devStm
          res <- runConduit (yield (BC.pack "") .| serveConduit device .| sinkLbs)
          res `shouldBe` BCL.pack ""
        it "must correctly respond to an empty request" $ do
          devStm <- testDevice
          device <- atomically devStm
          res <- runConduit (yield (BC.pack "\n\n") .| serveConduit device .| sinkLbs)
          res `shouldBe` BCL.pack ""
        it "must respond to a correctly formed get v1 request" $ do
          devStm <- testDevice
          device <- atomically devStm
          res <- runConduit (yield (BC.pack "get=1\n\n") .| serveConduit device .| sinkLbs)
          res `shouldBe` bsTestDevice
          chkCorrectEnd res
      describe "showPeer" $ do
        it "must correctly generate a complete peer bytestring containing one ip range" $ do
          peerPub <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          peer    <- atomically $ getTestPeerOneRange peerPub
          res <- atomically $ showPeer peer
          res `shouldBe` BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\npersistant_keepalive_interval=0\nrx_bytes=777\ntx_bytes=778\nlast_handshake_time=1502895867\nallowed_ip=192.168.1.0/24\n"
        it "must correctly generate a complete peer bytestring containing several ip ranges" $ do
          peerPub <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          peer    <- atomically $ getTestPeerTwoRanges peerPub
          res <- atomically $ showPeer peer
          res `shouldBe` BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\npersistant_keepalive_interval=0\nrx_bytes=777\ntx_bytes=778\nlast_handshake_time=1502895867\nallowed_ip=192.168.1.0/24\nallowed_ip=192.168.2.0/24\n"
        where
          testDevice = do
            pkH <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a" 
            pshH <- unhex $ BC.pack "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52" 
            return $ getTestDevice pkH pshH 
          chkCorrectEnd bs = shouldSatisfy bs (BSL.isSuffixOf (BCL.pack "\n\n") )

getGenericPeer :: BS.ByteString -> STM Peer
getGenericPeer pub = do
  peer <- createPeer pubKey
  writeTVar (endPoint peer) $ Just $ SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)
  writeTVar (receivedBytes peer) 777 
  writeTVar (transferredBytes peer) 778
  writeTVar (lastHandshakeTime peer) (Just 1502895867)
  return peer
  where
    pubKey = fromJust . DH.dhBytesToPub $ BA.convert pub

getTestPeerOneRange :: BS.ByteString -> STM Peer
getTestPeerOneRange publicKeyHexBytes = do
  p <- getGenericPeer publicKeyHexBytes
  writeTVar (ipmasks p) ipmask
  return p
  where
    ipmask = [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]

getTestPeerTwoRanges :: BS.ByteString -> STM Peer
getTestPeerTwoRanges publicKeyHexBytes = do
  peer <- getGenericPeer publicKeyHexBytes
  writeTVar (ipmasks peer) ipmask
  return peer
  where
    ipmask = [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4), IPv4Range (read "192.168.2.0/24" :: AddrRange IPv4)]

getTestDevice :: BS.ByteString -> BS.ByteString -> STM Device
getTestDevice pkHex pshHex = do
  dev <- createDevice "wg0"
  let keyPair = DH.dhBytesToPair $ BA.convert pkHex
  let psh = Just $ BA.convert pshHex :: Maybe PresharedKey
  writeTVar (localKey dev) keyPair
  writeTVar (presharedKey dev) psh
  writeTVar (port dev) 12912
  return dev

bsTestDevice :: BSL.ByteString
bsTestDevice = BCL.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=12912\nfwmark=0\n\n"


--bsTestDeviceWithPairs :: BSL.ByteString
--bsTestDeviceWithPairs = BCL.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=12912\npublic_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33\npreshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52\nallowed_ip=192.168.4.4/32\nendpoint=[abcd:23::33%2]:51820\npublic_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376\ntx_bytes=38333\nrx_bytes=2224\nallowed_ip=192.168.4.6/32\npersistent_keepalive_interval=111\nendpoint=182.122.22.19:3233\npublic_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=5.152.198.39:51820\nallowed_ip=192.168.4.10/32\nallowed_ip=192.168.4.11/32\ntx_bytes=1212111\nrx_bytes=1929999999\nerrno=0\n\n"

