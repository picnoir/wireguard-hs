module Network.WireGuard.RPCSpec (spec) where

import Test.Hspec (Spec, describe, it, shouldBe)

import Network.WireGuard.RPC (runRPC)


spec :: Spec
spec = describe "test" $ 
        it "should fail" $ 
          True `shouldBe` False
