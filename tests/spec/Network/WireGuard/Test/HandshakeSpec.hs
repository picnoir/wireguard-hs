module Network.WireGuard.Test.HandshakeSpec (spec) where

import Test.Hspec                                  (Spec, describe,
                                                    it, around, shouldSatisfy,
                                                    shouldNotBe, shouldBe, pending)
import Control.Monad.STM                           (atomically)
import Control.Monad.Trans.Except                  (runExceptT)
import Control.Exception                           (bracket)
import Control.Concurrent.STM                      (putTMVar, writeTVar, readTVarIO,
                                                    readTMVar)
import qualified Data.ByteArray             as BA  (convert)
import qualified Data.ByteString.Char8      as BC  (pack)
import qualified Data.ByteString            as BS  (empty)
import           Data.Either                       (isRight)
import           Data.Maybe                        (fromJust, isJust)
import           Data.Hex                          (unhex)
import           Data.IP                           (AddrRange, IPv4, 
                                                    IPRange(..))
import Data.Serialize                              (runPut)
import qualified Crypto.Noise.DH            as DH  (dhBytesToPub, dhBytesToPair)
import Foreign.C.Types                             (CTime(..))
import Network.Socket                              (SockAddr(..), tupleToHostAddress)
import System.Posix.Time                           (epochTime)

import Network.WireGuard.Internal.Constant         (handshakeRetryTime, handshakeStopTime)
import Network.WireGuard.Internal.State            (Peer(..), Device(..), createPeer,
                                                    createDevice, initRekeyTimeout, initRekeyAttemptTime)
import Network.WireGuard.Internal.Data.Types       (Time)
import Network.WireGuard.Internal.Data.Handshake   (HandshakeInitSeed(..))
import Network.WireGuard.Internal.Packet           (Packet(..), buildPacket, getMac1)
import Network.WireGuard.Internal.Stream.Handshake (handshakeInit, processHandshakeInitiation)

import Network.WireGuard.Test.Utils                (pk1,psh)

spec :: Spec
spec = do
  around withTestInitHandshake $ describe "handshakeinit" $ do
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
  around withTestRespHandshake $ describe "processHandshakeInitiation"  $ do
    it "should respond something" $ \(dev,packet,seed) -> do
        key <- atomically $ readTMVar $ localKey dev
        pshk <- readTVarIO $ presharedKey dev
        resp <- atomically . runExceptT $ processHandshakeInitiation seed dev key pshk remote packet 
        resp `shouldSatisfy` isRight
        fst (fromRight resp) `shouldNotBe` BS.empty
        snd (fromRight resp) `shouldBe` remote
        pending
    where remote = SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)

fromRight :: Either a b -> b
fromRight (Right b) = b
fromRight _ = error "Not right"

withTestRespHandshake :: ((Device,Packet,HandshakeInitSeed) -> IO ()) -> IO ()
withTestRespHandshake = bracket withRessources (\_ -> return ())
    where withRessources = do
            dev    <- initDev
            peer   <- initPeer
            packet <- initMessage dev peer
            seed   <- initSeed
            return (dev,packet,seed)

withTestInitHandshake :: ((Device,Peer,HandshakeInitSeed) -> IO ()) -> IO ()
withTestInitHandshake = bracket withRessources (\ _ -> return ())
    where withRessources = do
            dev  <- initDev
            peer <- initPeer 
            seed <- initSeed
            return (dev,peer,seed)

initDev :: IO Device
initDev = do
    dev <- atomically $ createDevice "wg0"
    keyPair <- pk1
    pshk <- psh
    atomically $ do 
        putTMVar  (localKey dev) keyPair
        writeTVar (presharedKey dev) pshk
        writeTVar (port dev) 12912
    return dev

initPeer :: IO Peer
initPeer = do
    pubHex <- unhex $ BC.pack "0069356ea6121cd27c5553ed3598a99ffe490462b39badccb6edc6224cb0892f"
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

initMessage :: Device -> Peer -> IO Packet
initMessage device peer = do
    seed <- initSeed
    pshk <- psh
    payload <- atomically . runExceptT $ handshakeInit seed device peer Nothing remote
    let pubK = remotePub peer
    let packetPayload = runPut $ buildPacket (getMac1 pubK pshk) $ HandshakeInitiation 0 (fst $ fromRight payload)
    return $ HandshakeInitiation 0 packetPayload
    where remote = SockAddrInet 1337 $ tupleToHostAddress (192,168,1,1)

addTime :: Time -> Int -> Time
addTime (CTime now) secs = CTime (now + fromIntegral secs)
