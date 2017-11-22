module Network.WireGuard.Test.Utils(
  pk1,
  pk2,
  psh
) where

import qualified Data.ByteArray             as BA  (convert)
import qualified Data.ByteString.Char8      as BC  (pack)
import           Data.Hex                          (unhex)
import           Data.Maybe                        (fromJust)
import qualified Crypto.Noise.DH            as DH  (dhBytesToPair)
import Network.WireGuard.Internal.Data.Types       (PresharedKey, KeyPair)

pk1 :: IO KeyPair
pk1 = do
    pk <- unhex $ BC.pack "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"
    return $ fromJust $ DH.dhBytesToPair $ BA.convert pk


pk2 :: IO KeyPair
pk2 = do
    pk <- unhex $ BC.pack "8037f28b226a651cb3a4ce90de2747f63bd759ac5ae7c2a348fd139e94ea1052"
    return $ fromJust $ DH.dhBytesToPair $ BA.convert pk

psh :: IO (Maybe PresharedKey)
psh = do
    pshH <- unhex $ BC.pack "188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52" 
    let pshk = Just $ BA.convert pshH :: Maybe PresharedKey
    return pshk
