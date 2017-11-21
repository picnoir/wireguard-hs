module Network.WireGuard.HandshakeSpec (spec) where

import Test.Hspec                                  (Spec, describe,
                                                    it, around, shouldSatisfy,
                                                    shouldNotBe, shouldBe)
import Control.Monad.STM                           (atomically)
import Control.Monad.Trans.Except                  (runExceptT)
import Control.Exception                           (bracket)
import Control.Concurrent.STM                      (putTMVar, writeTVar, readTVarIO)
import qualified Data.ByteArray             as BA  (convert)
import qualified Data.ByteString.Char8      as BC  (pack)
import qualified Data.ByteString            as BS  (empty)
import           Data.Either                       (isRight)
import           Data.Maybe                        (fromJust, isJust)
import           Data.Hex                          (unhex)
import           Data.IP                           (AddrRange, IPv4, 
                                                    IPRange(..))
import qualified Crypto.Noise.DH            as DH  (dhBytesToPub, dhBytesToPair)
import Foreign.C.Types                             (CTime(..))
import Network.Socket                              (SockAddr(..), tupleToHostAddress)
import System.Posix.Time                           (epochTime)

import Network.WireGuard.Internal.Constant         (handshakeRetryTime, handshakeStopTime)
import Network.WireGuard.Internal.State            (Peer(..), Device(..), createPeer,
                                                    createDevice, initRekeyTimeout, initRekeyAttemptTime)
import Network.WireGuard.Internal.Data.Types       (PresharedKey, Time)
import Network.WireGuard.Internal.Data.Handshake   (HandshakeInitSeed(..))
import Network.WireGuard.Internal.Stream.Handshake (handshakeInit)

spec :: Spec
spec = around withTestInitPeer $ describe "handshakeinit" $ do
    it "should generate a correct udp packet" $ \(dev,peer,seed) -> do
        eInitPacket <- atomically . runExceptT $ handshakeInit seed dev peer Nothing remote
        eInitPacket `shouldSatisfy` isRight
        let initPacket = fromRight eInitPacket
        initPacket `shouldNotBe` (BS.empty, undefined)
        snd initPacket `shouldBe` remote
    it "should accordingly update the STM state" $ \(dev,peer,seed)  -> do
        _ <- atomically . runExceptT $ handshakeInit seed dev peer Nothing remote
        initState <- readTVarIO $ handshakeInitSt peer
        let timeout = initRekeyTimeout <$> initState
        timeout`shouldSatisfy` isJust
    it "should correctly update the rekey timeout timer" $ \(dev,peer,seed) -> do
        _ <- atomically . runExceptT $ handshakeInit seed dev peer Nothing remote
        initState <- readTVarIO $ handshakeInitSt peer
        let timeout = initRekeyTimeout <$> initState
        fromJust timeout `shouldSatisfy` (> handshakeNowTS seed)
        fromJust timeout `shouldBe` addTime (handshakeNowTS seed) handshakeRetryTime
    it "should correctly update the rekey attempt time timer" $ \(dev,peer,seed) -> do
        _ <- atomically . runExceptT $ handshakeInit seed dev peer Nothing remote
        initState <- readTVarIO $ handshakeInitSt peer
        let attempt = initRekeyAttemptTime <$> initState
        fromJust attempt `shouldBe` addTime (handshakeNowTS seed) handshakeStopTime
    where remote = SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)

fromRight :: Either a b -> b
fromRight (Right b) = b
fromRight _ = error "Not right"

withTestInitPeer :: ((Device,Peer,HandshakeInitSeed) -> IO ()) -> IO ()
withTestInitPeer = bracket withRessources (\ _ -> return ())
    where withRessources = do
            dev  <- initDev
            peer <- initPeer 
            seed <- initSeed
            return (dev,peer,seed)
                                

initDev :: IO Device
initDev = do
    dev <- atomically $ createDevice "wg0"
    pkHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a" 
    pshHex <- unhex $ BC.pack "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52" 
    let keyPair = fromJust $ DH.dhBytesToPair $ BA.convert pkHex
    let psh = Just $ BA.convert pshHex :: Maybe PresharedKey
    atomically $ do 
        putTMVar  (localKey dev) keyPair
        writeTVar (presharedKey dev) psh
        writeTVar (port dev) 12912
    return dev

initPeer :: IO Peer
initPeer = do
    pubHex <- unhex $ BC.pack "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"
    peer <- atomically $ createPeer (pubKey pubHex)
    atomically $ putTMVar (endPoint peer) $ SockAddrInet 3233 $ tupleToHostAddress (182,122,22,19)
    atomically $ writeTVar (ipmasks peer) ipRange
    return peer
    where
        pubKey hex = fromJust . DH.dhBytesToPub $ BA.convert hex 
        ipRange = [IPv4Range (read "192.168.4.6/32" :: AddrRange IPv4)]

initSeed :: IO HandshakeInitSeed
initSeed = do
    now <- epochTime
    eKpHex <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
    let eKp = fromJust $ DH.dhBytesToPair $ BA.convert eKpHex
    return $ HandshakeInitSeed eKp now 0

addTime :: Time -> Int -> Time
addTime (CTime now) secs = CTime (now + fromIntegral secs)
