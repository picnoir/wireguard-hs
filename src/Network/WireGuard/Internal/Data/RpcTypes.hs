module Network.WireGuard.Internal.Data.RpcTypes(
 OpType(..),
 RpcRequest(..),
 RpcSetPayload(..),
 RpcDevicePayload(..),
 RpcPeerPayload(..)
) where

import Data.Word                                (Word64)
import Data.IP                                  (IPRange(..))
import           Crypto.Noise.DH                (dhSecToBytes)
import Network.Socket.Internal                  (SockAddr)

import Network.WireGuard.Internal.Data.Types    (PublicKey, KeyPair,
                                                 Time)
-- | Kind of client operation. 
--
--  See <https://www.wireguard.com/xplatform/#configuration-protocol> for more informations.
data OpType = Get | Set

-- | Request wrapper. The payload is set only for Set operations. 
--
--  See <https://www.wireguard.com/xplatform/#configuration-protocol> for more informations.
data RpcRequest = RpcRequest {
  opType  ::  OpType,
  payload ::  Maybe RpcSetPayload
}

-- | Payload sent together with a set RPC operation.
data RpcSetPayload = RpcSetPayload {
  devicePayload :: RpcDevicePayload,
  peersPayload  :: [RpcPeerPayload]
}

-- | Device related payload sent together with a set RPC operation.
data RpcDevicePayload = RpcDevicePayload {
  pk           :: Maybe KeyPair,
  listenPort   :: Int,
  fwMark       :: Maybe Word,
  replacePeers :: Bool
} 

instance Show RpcDevicePayload where
  show (RpcDevicePayload kp lp fwM rpp) = show (showKeyPair <$> kp) ++ show lp ++ show fwM ++ show rpp
   where
     showKeyPair (pk, _) = show $ dhSecToBytes pk

instance Eq RpcDevicePayload where
    (==) (RpcDevicePayload pk1 prt1 fw1 rp1) (RpcDevicePayload pk2 prt2 fw2 rp2) =
      ((dhSecToBytes . fst) <$> pk1) == ((dhSecToBytes . fst) <$> pk2) && (prt1 == prt2) &&
      (rp1 == rp2) && (fw1 == fw2)

-- | Peer related payload sent together with a set RPC operation.
data RpcPeerPayload  = RpcPeerPayload {
  pubK                        :: PublicKey,
  remove                      :: Bool,
  endpoint                    :: SockAddr,
  persistantKeepaliveInterval :: Int,
  allowedIp                   :: [IPRange],
  rxBytes                     :: Word64,
  txBytes                     :: Word64,
  lastHandshake               :: Time 
}
