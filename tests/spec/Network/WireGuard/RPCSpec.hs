module Network.WireGuard.RPCSpec (spec) where

import Control.Monad.STM                           (atomically, STM)
import Control.Concurrent.STM.TVar                 (writeTVar)
import           Data.Attoparsec.ByteString.Char8  (parse, eitherResult, feed)
import qualified Data.ByteArray             as BA  (convert)
import qualified Data.ByteString            as BS  (ByteString)
import qualified Data.ByteString.Lazy       as BSL (ByteString, isSuffixOf)
import qualified Data.ByteString.Char8      as BC  (pack, empty)
import qualified Data.ByteString.Lazy.Char8 as BCL (pack)
import           Data.Either                       (isLeft)
import           Data.Maybe                        (fromJust)
import           Data.HashMap.Strict        as HM  (fromList)
import           Data.Hex                          (unhex)
import           Data.IP                           (AddrRange, IPv4, 
                                                    IPv6, IPRange(..),
                                                    toHostAddress6)
import qualified Crypto.Noise.DH            as DH  (dhBytesToPair, dhBytesToPub)
import Data.Conduit                                (runConduit, yield, ( .|))
import Data.Conduit.Binary                         (sinkLbs)
import Network.Socket                              (SockAddr(..), tupleToHostAddress)
import Test.Hspec                                  (Spec, describe,
                                                    it, shouldBe,
                                                    shouldSatisfy)

import Network.WireGuard.RPC                                     (serveConduit, showPeer)
import Network.WireGuard.Internal.RpcParsers                     (deviceParser, peerParser,
                                                                  setPayloadParser, requestParser)
import Network.WireGuard.Internal.State                          (Device(..), Peer(..),
                                                                  createDevice, createPeer)
import Network.WireGuard.Internal.Data.Types                     (PresharedKey, PeerId)
import qualified Network.WireGuard.Internal.Data.RpcTypes as RPC (RpcDevicePayload(..), RpcPeerPayload(..),
                                                                  RpcSetPayload(..), RpcRequest(..),
                                                                  OpType(..))

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
        it "must respond to a correctly formed get v1 request not connected to any peer" $ do
          devStm <- testDevice
          device <- atomically devStm
          res <- runConduit (yield (BC.pack "get=1\n\n") .| serveConduit device .| sinkLbs)
          res `shouldBe` bsTestDevice
          chkCorrectEnd res
        it "must respond to a correctly formed get v1 request connected to several peers" $ do
          pubKey1 <- unhex $ BC.pack "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"
          pubKey2 <- unhex $ BC.pack "58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"
          pubKey3 <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"
          peer1 <- atomically $ getPeer1 pubKey1
          peer2 <- atomically $ getPeer2 pubKey2
          peer3 <- atomically $ getPeer3 pubKey3
          devStm <- testDeviceWithPeers [(BC.pack "peer1", peer1), (BC.pack "peer2", peer2), (BC.pack "peer3", peer3)]
          device <- atomically $ devStm
          res <- runConduit (yield (BC.pack "get=1\n\n") .| serveConduit device .| sinkLbs)
          res `shouldBe` bsTestDeviceWithPairs
          chkCorrectEnd res
      describe "showPeer" $ do
        it "must correctly generate a complete peer bytestring containing one ip range" $ do
          peerPub <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          peer    <- atomically $ getTestPeerOneRange peerPub
          res <- atomically $ showPeer peer
          res `shouldBe` BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\ntx_bytes=778\nrx_bytes=777\nlast_handshake_time=1502895867\nallowed_ip=192.168.1.0/24\n"
        it "must correctly generate a complete peer bytestring containing several ip ranges" $ do
          peerPub <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          peer    <- atomically $ getTestPeerTwoRanges peerPub
          res <- atomically $ showPeer peer
          res `shouldBe` BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\ntx_bytes=778\nrx_bytes=777\nlast_handshake_time=1502895867\nallowed_ip=192.168.1.0/24\nallowed_ip=192.168.2.0/24\n"
      describe "deviceParser" $ do
        it "must parse a add device entry" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          let expectedDevice = RPC.RpcDevicePayload pk 777 (Just 0) False
          let result = feed (parse deviceParser $ BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=777\nfwmark=0\n") BC.empty
          eitherResult result `shouldBe` Right expectedDevice
        it "must parse a remove pk device entry" $ do
          let expectedDevice = RPC.RpcDevicePayload Nothing 777 (Just 0) False
          let result = feed (parse deviceParser $ BC.pack "private_key=\nlisten_port=777\nfwmark=0\n") BC.empty
          eitherResult result `shouldBe` Right expectedDevice
        it "must parse a remove fwmark device entry" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          let expectedDevice = RPC.RpcDevicePayload pk 777 Nothing False
          let result = feed (parse deviceParser $ BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=777\nfwmark=\n") BC.empty
          eitherResult result `shouldBe` Right expectedDevice
        it "must handle remove device flag" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          let expectedDevice = RPC.RpcDevicePayload pk 777 Nothing True
          let result = feed (parse deviceParser $ BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=777\nfwmark=\nreplace_peers=true\n") BC.empty
          eitherResult result `shouldBe` Right expectedDevice
        it "must not be position sensitive" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          let expectedDevice = RPC.RpcDevicePayload pk 777 Nothing True
          let result = feed (parse deviceParser $ BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nfwmark=\nreplace_peers=true\nlisten_port=777\n") BC.empty
          eitherResult result `shouldBe` Right expectedDevice
      describe "peerParser" $ do
        it "must parse a standart add peer entry" $ do
          pubHex           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          let pubK          = fromJust . DH.dhBytesToPub $ BA.convert pubHex
          let expectedPeer  = RPC.RpcPeerPayload pubK False Nothing (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let result = feed (parse peerParser $ BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\n") BC.empty
          eitherResult result `shouldBe` Right expectedPeer
        it "must parse a remove peer entry" $ do
          pubHex           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          let pubK          = fromJust . DH.dhBytesToPub $ BA.convert pubHex
          let expectedPeer  = RPC.RpcPeerPayload pubK True Nothing (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let result = feed (parse peerParser $ BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nremove=true\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\n") BC.empty
          eitherResult result `shouldBe` Right expectedPeer
        it "must parse a peer entry containing a preshared key" $ do
          pubHex           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          pshHex           <- unhex $ BC.pack "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52"
          let pubK          = fromJust . DH.dhBytesToPub $ BA.convert pubHex
          let pshK          = Just $ BA.convert pshHex :: Maybe PresharedKey
          let expectedPeer  = RPC.RpcPeerPayload pubK False pshK (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let result = feed (parse peerParser $ BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\npreshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\n") BC.empty
          eitherResult result `shouldBe` Right expectedPeer
        it "must parse a peer having an ipv6 endpoint" $ do
          pubHex           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          let pubK          = fromJust . DH.dhBytesToPub $ BA.convert pubHex
          let ipv6          = SockAddrInet6 51820 0 (toHostAddress6 $ read "abcd:23::33") 2
          let expectedPeer  = RPC.RpcPeerPayload pubK False Nothing ipv6 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let result = feed (parse peerParser $ BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=[abcd:23::33%2]:51820\nallowed_ip=192.168.1.0/24\n") BC.empty
          eitherResult result `shouldBe` Right expectedPeer
        it "must parse a peer having several allowed ips " $ do
          pubHex           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          let pubK          = fromJust . DH.dhBytesToPub $ BA.convert pubHex
          let expectedPeer  = RPC.RpcPeerPayload pubK False Nothing (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4),IPv6Range (read "2001:7f8::/29" :: AddrRange IPv6)]
          let result = feed (parse peerParser $ BC.pack "public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\nallowed_ip=[2001:7f8::/29]\n") BC.empty
          eitherResult result `shouldBe` Right expectedPeer
        it "must not parse a peer having an incorrect public key" $ do
          let result = feed (parse peerParser $ BC.pack "public_key=2e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\n") BC.empty
          eitherResult result `shouldSatisfy` isLeft 
        it "must not parse a peer having an incorrect allowed ip" $ do
          let result = feed (parse peerParser $ BC.pack "public_key=2e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0.2/24\n") BC.empty
          eitherResult result `shouldSatisfy` isLeft 
      describe "setPayloadParser" $ do
        it "must parse a standard set payload" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          pubHex           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          let pubK          = fromJust . DH.dhBytesToPub $ BA.convert pubHex
          let expectedDevice = RPC.RpcDevicePayload pk 777 (Just 0) False
          let expectedPeer  = RPC.RpcPeerPayload pubK False Nothing (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let expectedPayload = RPC.RpcSetPayload expectedDevice [expectedPeer]
          let result = feed (parse setPayloadParser $ BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=777\nfwmark=0\npublic_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\n") BC.empty
          eitherResult result `shouldBe` Right expectedPayload
        it "must parse a set payload containing several peers" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          pubHex1           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          let pubK1          = fromJust . DH.dhBytesToPub $ BA.convert pubHex1
          pubHex2           <- unhex $ BC.pack "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"
          let pubK2          = fromJust . DH.dhBytesToPub $ BA.convert pubHex2
          let expectedDevice = RPC.RpcDevicePayload pk 777 (Just 0) False
          let expectedPeer1  = RPC.RpcPeerPayload pubK1 False Nothing (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let expectedPeer2  = RPC.RpcPeerPayload pubK2 False Nothing (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let expectedPayload = RPC.RpcSetPayload expectedDevice [expectedPeer1, expectedPeer2]
          let result = feed (parse setPayloadParser $ BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=777\nfwmark=0\npublic_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\npublic_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\n") BC.empty
          eitherResult result `shouldBe` Right expectedPayload
        it "must parse a set payload containing no peers" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          let expectedDevice = RPC.RpcDevicePayload pk 777 (Just 0) False
          let expectedPayload = RPC.RpcSetPayload expectedDevice []
          let result = feed (parse setPayloadParser $ BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=777\nfwmark=0\n") BC.empty
          eitherResult result `shouldBe` Right expectedPayload
      describe "requestParser" $ do
        it "must correctly parse a set operation" $ do
          pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
          let pk = DH.dhBytesToPair $ BA.convert pkHex
          pubHex           <- unhex $ BC.pack "662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58" 
          let pubK          = fromJust . DH.dhBytesToPub $ BA.convert pubHex
          let expectedDevice = RPC.RpcDevicePayload pk 777 (Just 0) False
          let expectedPeer  = RPC.RpcPeerPayload pubK False Nothing (SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)) 0 False [IPv4Range (read "192.168.1.0/24" :: AddrRange IPv4)]
          let expectedResult = RPC.RpcRequest RPC.Set . Just $ RPC.RpcSetPayload expectedDevice [expectedPeer]
          let result = feed (parse requestParser $ BC.pack "set=1\nprivate_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=777\nfwmark=0\npublic_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=192.168.1.1:1337\nallowed_ip=192.168.1.0/24\n\n") BC.empty
          eitherResult result `shouldBe` Right expectedResult
        it "must correctly parse a get operation" $ do
          let expectedResult = RPC.RpcRequest RPC.Get Nothing
          let result = feed (parse requestParser $ BC.pack "get=1\n\n") BC.empty
          eitherResult result `shouldBe` Right expectedResult
        where
          testDevice = do
            pkH <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a" 
            pshH <- unhex $ BC.pack "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52" 
            return $ getTestDevice pkH pshH 
          chkCorrectEnd bs = shouldSatisfy bs (BSL.isSuffixOf (BCL.pack "\n\n") )
          testDeviceWithPeers prs = do
            pkH <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a" 
            pshH <- unhex $ BC.pack "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52" 
            return $ getTestDeviceWithPeers pkH pshH prs
            

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

getTestDeviceWithPeers :: BS.ByteString -> BS.ByteString -> [(PeerId, Peer)] -> STM Device
getTestDeviceWithPeers pkHex pshHex prs = do
  dev <- createDevice "wg0"
  let keyPair = DH.dhBytesToPair $ BA.convert pkHex
  let psh = Just $ BA.convert pshHex :: Maybe PresharedKey
  writeTVar (localKey dev) keyPair
  writeTVar (presharedKey dev) psh
  writeTVar (port dev) 12912
  writeTVar (peers dev) $ HM.fromList prs
  return dev
  
getPeer1 :: BS.ByteString -> STM Peer
getPeer1 pubHex = do
  peer <- createPeer pubKey
  writeTVar (endPoint peer) . Just $ SockAddrInet6 51820 0 (toHostAddress6 $ read "abcd:23::33") 2
  writeTVar (ipmasks peer) ipRange 
  return peer
  where
    pubKey = fromJust . DH.dhBytesToPub $ BA.convert pubHex
    ipRange = [IPv4Range (read "192.168.4.4/32" :: AddrRange IPv4)]
getPeer2 :: BS.ByteString -> STM Peer
getPeer2 pubHex = do
  peer <- createPeer pubKey
  writeTVar (endPoint peer) $ Just $ SockAddrInet 3233 $ tupleToHostAddress (182,122,22,19)
  writeTVar (receivedBytes peer) 2224
  writeTVar (transferredBytes peer) 38333
  writeTVar (keepaliveInterval peer) 111
  writeTVar (ipmasks peer) ipRange 
  return peer
  where
    pubKey = fromJust . DH.dhBytesToPub $ BA.convert pubHex
    ipRange = [IPv4Range (read "192.168.4.6/32" :: AddrRange IPv4)]

getPeer3 :: BS.ByteString -> STM Peer
getPeer3 pubHex = do
  peer <- createPeer pubKey
  writeTVar (endPoint peer) $ Just $ SockAddrInet 51820 $ tupleToHostAddress (5, 152, 198, 39)
  writeTVar (receivedBytes peer) 1929999999 
  writeTVar (transferredBytes peer) 1212111
  writeTVar (ipmasks peer) ipRange 
  return peer
  where
    pubKey = fromJust . DH.dhBytesToPub $ BA.convert pubHex
    ipRange = [IPv4Range (read "192.168.4.10/32" :: AddrRange IPv4),
               IPv4Range (read "192.168.4.11/32" :: AddrRange IPv4)]
bsTestDevice :: BSL.ByteString
bsTestDevice = BCL.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=12912\nerrno=0\n\n"


bsTestDeviceWithPairs :: BSL.ByteString
bsTestDeviceWithPairs = BCL.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=12912\npublic_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33\nendpoint=[abcd:23::33%2]:51820\nallowed_ip=192.168.4.4/32\npublic_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376\nendpoint=182.122.22.19:3233\npersistent_keepalive_interval=111\ntx_bytes=38333\nrx_bytes=2224\nallowed_ip=192.168.4.6/32\npublic_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=5.152.198.39:51820\ntx_bytes=1212111\nrx_bytes=1929999999\nallowed_ip=192.168.4.10/32\nallowed_ip=192.168.4.11/32\nerrno=0\n\n"
