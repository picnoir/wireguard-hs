module Network.WireGuard.RPCSpec (spec) where

import Control.Monad.STM                     (atomically, STM)
import qualified Data.ByteString      as BS  (ByteString)
import qualified Data.ByteString.Lazy as BSL (ByteString)
import qualified Data.ByteString.Char8          as BC  (pack)
import qualified Data.ByteString.Lazy.Char8     as BCL (pack)
import Data.Conduit                          (runConduit, yield, ( .|))
import Data.Conduit.Binary                   (sinkLbs)
import Test.Hspec                            (Spec, describe,
                                              it, shouldBe)

import Network.WireGuard.RPC            (serveConduit)
import Network.WireGuard.Internal.State (Device, createDevice)


getCommand :: BS.ByteString
getCommand = BC.pack "\n\nget=1\n\n"

deviceS :: STM Device
deviceS = createDevice "wg0"

bsDeviceStrict :: BS.ByteString
bsDeviceStrict = BC.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=12912\npublic_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33\npreshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52\nallowed_ip=192.168.4.4/32\nendpoint=[abcd:23::33%2]:51820\n\n"

bsDevice :: BSL.ByteString
bsDevice = BCL.pack "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a\nlisten_port=12912\npublic_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33\npreshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52\nallowed_ip=192.168.4.4/32\nendpoint=[abcd:23::33%2]:51820\npublic_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376\ntx_bytes=38333\nrx_bytes=2224\nallowed_ip=192.168.4.6/32\npersistent_keepalive_interval=111\nendpoint=182.122.22.19:3233\npublic_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58\nendpoint=5.152.198.39:51820\nallowed_ip=192.168.4.10/32\nallowed_ip=192.168.4.11/32\ntx_bytes=1212111\nrx_bytes=1929999999\nerrno=0"

spec :: Spec
spec = describe "serveConduit" $ 
        it "must respond to a get v1 request" $ do
          device <- atomically deviceS
          res <- runConduit (yield getCommand .| serveConduit device .| sinkLbs)
          res `shouldBe` bsDevice
