module Network.WireGuard.Internal.Data.RpcTypes(
 OpType(..),
 RpcRequest(..),
 RpcSetPayload(..),
 RpcDevicePayload(..),
 RpcPeerPayload(..),
 RpcDeviceField(..),
 RpcPeerField(..)
) where

import Data.IP                                  (IPRange(..))
import Crypto.Noise.DH                          (dhSecToBytes, dhPubToBytes)
import Network.Socket.Internal                  (SockAddr)

import Network.WireGuard.Internal.Data.Types    (PublicKey, KeyPair,
                                                 PresharedKey)
-- | Kind of client operation. 
--
--  See <https://www.wireguard.com/xplatform/#configuration-protocol> for more informations.
data OpType = Get | Set deriving (Eq, Show)

-- | Request wrapper. The payload is set only for Set operations. 
--
--  See <https://www.wireguard.com/xplatform/#configuration-protocol> for more informations.
data RpcRequest = RpcRequest {
  opType  ::  !OpType,
  payload ::  !(Maybe RpcSetPayload)
} deriving (Eq, Show)

-- | Payload sent together with a set RPC operation.
data RpcSetPayload = RpcSetPayload {
  devicePayload :: !RpcDevicePayload,
  peersPayload  :: [RpcPeerPayload]
} deriving (Eq, Show)

-- | Device related payload sent together with a set RPC operation.
data RpcDevicePayload = RpcDevicePayload {
  pk           :: !(Maybe KeyPair),
  listenPort   :: !Int,
  fwMark       :: !(Maybe Word),
  replacePeers :: !Bool
} 

instance Show RpcDevicePayload where
  show (RpcDevicePayload kp lp fwM rpp) = show (showKeyPair <$> kp) ++ show lp ++ show fwM ++ show rpp
   where
     showKeyPair (pk, _) = show $ dhSecToBytes pk

instance Eq RpcDevicePayload where
    (==) (RpcDevicePayload pk1 prt1 fw1 rp1) (RpcDevicePayload pk2 prt2 fw2 rp2) =
      ((dhSecToBytes . fst) <$> pk1) == ((dhSecToBytes . fst) <$> pk2) && (prt1 == prt2) &&
      (rp1 == rp2) && (fw1 == fw2)

data RpcDeviceField = RpcPk !(Maybe KeyPair)
                    | RpcPort !Int
                    | RpcFwMark !(Maybe Word)
                    | RpcReplacePeers 

-- | Peer related payload sent together with a set RPC operation.
data RpcPeerPayload  = RpcPeerPayload {
  pubK                        :: !PublicKey,
  remove                      :: !Bool,
  presharedKey                :: !(Maybe PresharedKey),
  endpoint                    :: !SockAddr,
  persistantKeepaliveInterval :: !Int,
  replaceIps                  :: !Bool,
  allowedIp                   :: ![IPRange]
}

instance Eq RpcPeerPayload where
    (==) (RpcPeerPayload pub1 rm1 psk1 e1 k1 rp1 aip1)(RpcPeerPayload pub2 rm2 psk2 e2 k2 rp2 aip2) =
         (dhPubToBytes pub1 == dhPubToBytes pub2) && (rm1 == rm2) && (psk1 == psk2) && (e1 == e2) &&
         (k1 == k2) && (rp1 == rp2) && (aip1 == aip2)

instance Show RpcPeerPayload where
  show (RpcPeerPayload pub1 rm1 psk1 e1 k1 rp1 aip1) 
    = show (dhPubToBytes pub1) ++ show rm1 ++ show psk1 ++ show e1 ++ show k1 ++ 
      show rp1 ++ show aip1

data RpcPeerField = RpcRmFlag    !Bool
                  | RpcPsh       !PresharedKey
                  | RpcEndp      !SockAddr
                  | RpcKA        !Int
                  | RpcDelIps    !Bool
                  | RpcAllIp     !IPRange
