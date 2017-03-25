{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Network.WireGuard.Foreign.UAPI
  ( WgIpmask(..)
  , PeerFlags
  , peerFlagRemoveMe
  , peerFlagReplaceIpmasks
  , WgPeer(..)
  , DeviceFlags
  , deviceFlagReplacePeers
  , deviceFlagRemovePrivateKey
  , deviceFlagRemovePresharedKey
  , deviceFlagRemoveFwmark
  , WgDevice(..)
  , readConfig
  , writeConfig
  ) where

import           Control.Monad                     (unless)
import           Data.ByteString.Internal          (ByteString (..))
import           Network.Socket.Internal           (HostAddress, HostAddress6,
                                                    SockAddr, peekSockAddr,
                                                    pokeSockAddr)
import           System.IO.Unsafe                  (unsafePerformIO)

import           Data.Char
import           Data.Int
import           Data.Word
import           Foreign
import           Foreign.C.String

import qualified Network.WireGuard.Foreign.Key     as K
import           Network.WireGuard.Internal.Util   (zeroMemory)

import           Network.WireGuard.Foreign.In6Addr

#include "uapi.h"

data WgIpmask = WgIpmask
              { ipmaskIp   :: ! (Either HostAddress HostAddress6)
              , ipmaskCidr :: ! #{type typeof((struct wgipmask){0}.cidr)}
              }

type PeerFlags = #{type typeof((struct wgpeer){0}.flags)}

peerFlagRemoveMe       = #{const WGPEER_REMOVE_ME}       :: PeerFlags
peerFlagReplaceIpmasks = #{const WGPEER_REPLACE_IPMASKS} :: PeerFlags

data WgPeer = WgPeer
            { peerPubKey            :: ! ByteString  -- TODO: use Bytes
            , peerFlags             :: ! PeerFlags
            , peerAddr              :: ! (Maybe SockAddr)
            , peerLastHandshakeTime :: ! #{type typeof((struct wgpeer){0}.last_handshake_time.tv_sec)}
            , peerReceivedBytes     :: ! #{type typeof((struct wgpeer){0}.rx_bytes)}
            , peerTransferredBytes  :: ! #{type typeof((struct wgpeer){0}.tx_bytes)}
            , peerKeepaliveInterval :: ! #{type typeof((struct wgpeer){0}.persistent_keepalive_interval)}
            , peerNumIpmasks        :: ! #{type typeof((struct wgpeer){0}.num_ipmasks)}
            }

type DeviceFlags = #{type typeof((struct wgdevice){0}.flags)}

deviceFlagReplacePeers       = #{const WGDEVICE_REPLACE_PEERS}        :: DeviceFlags
deviceFlagRemovePrivateKey   = #{const WGDEVICE_REMOVE_PRIVATE_KEY}   :: DeviceFlags
deviceFlagRemovePresharedKey = #{const WGDEVICE_REMOVE_PRESHARED_KEY} :: DeviceFlags
deviceFlagRemoveFwmark       = #{const WGDEVICE_REMOVE_FWMARK}        :: DeviceFlags

type VersionMagicType = #{type typeof((struct wgdevice){0}.version_magic)}

apiVersionMagic = #{const WG_API_VERSION_MAGIC } :: VersionMagicType

data WgDevice = WgDevice
              { deviceInterface :: ! String
              , deviceFlags     :: ! DeviceFlags
              , devicePubkey    :: ! ByteString  -- TODO: use Bytes
              , devicePrivkey   :: ! ByteString  -- TODO: use ScrubbedBytes
              , devicePSK       :: ! ByteString  -- TODO: use ScrubbedBytes
              , deviceFwmark    :: ! #{type typeof((struct wgdevice){0}.fwmark)}
              , devicePort      :: ! #{type typeof((struct wgdevice){0}.port)}
              , deviceNumPeers  :: ! #{type typeof((struct wgdevice){0}.num_peers)}
              }

type IpmaskIpFamilyType = #{type typeof((struct wgipmask){0}.family)}

instance Storable WgIpmask where
    sizeOf _              = #{size      struct wgipmask}
    alignment _           = #{alignment struct wgipmask}
    peek ptr              = do
        ipFamily <- #{peek struct wgipmask, family} ptr :: IO IpmaskIpFamilyType
        ip <- case ipFamily of
            #{const AF_INET} -> Left <$> #{peek struct wgipmask, ip4.s_addr} ptr
            #{const AF_INET6} -> Right . fromIn6Addr <$> #{peek struct wgipmask, ip6} ptr
            _ -> fail "WgIpmask.peek: unknown ipfamily"
        cidr <- #{peek struct wgipmask, cidr} ptr
        return (WgIpmask ip cidr)

    poke ptr self@WgIpmask{..} = do
        zeroMemory ptr $ fromIntegral $ sizeOf self
        case ipmaskIp of
            Left ip4  -> do
                #{poke struct wgipmask, family} ptr (#{const AF_INET} :: IpmaskIpFamilyType)
                #{poke struct wgipmask, ip4.s_addr} ptr ip4
            Right ip6 -> do
                #{poke struct wgipmask, family} ptr (#{const AF_INET6} :: IpmaskIpFamilyType)
                #{poke struct wgipmask, ip6} ptr (In6Addr ip6)
        #{poke struct wgipmask, cidr} ptr ipmaskCidr

type IpFamilyType = #{type sa_family_t}

sockaddrOffset = #{offset struct wgpeer, endpoint.addr}
ipfamilyOffset = #{offset struct wgpeer, endpoint.addr.sa_family}

instance Storable WgPeer where
    sizeOf _            = #{size      struct wgpeer}
    alignment _         = #{alignment struct wgpeer}
    peek ptr            = do
        ipfamily <- peek (ptr `plusPtr` ipfamilyOffset) :: IO IpFamilyType
        let sockaddrM = case ipfamily of
                0 -> return Nothing
                _ -> Just <$> peekSockAddr (ptr `plusPtr` sockaddrOffset)
        WgPeer <$> (K.toByteString <$> #{peek struct wgpeer, public_key} ptr)
               <*> #{peek struct wgpeer, flags} ptr
               <*> sockaddrM
               <*> #{peek struct wgpeer, last_handshake_time.tv_sec} ptr
               <*> #{peek struct wgpeer, rx_bytes} ptr
               <*> #{peek struct wgpeer, tx_bytes} ptr
               <*> #{peek struct wgpeer, persistent_keepalive_interval} ptr
               <*> #{peek struct wgpeer, num_ipmasks} ptr
    poke ptr self@WgPeer{..} = do
        zeroMemory ptr $ fromIntegral $ sizeOf self
        #{poke struct wgpeer, public_key} ptr (K.fromByteString peerPubKey)
        #{poke struct wgpeer, flags} ptr peerFlags
        case peerAddr of
            Just addr -> pokeSockAddr (ptr `plusPtr` sockaddrOffset) addr
            Nothing   -> poke (ptr `plusPtr` ipfamilyOffset) (0 :: IpFamilyType)
        #{poke struct wgpeer, last_handshake_time.tv_sec} ptr peerLastHandshakeTime
        #{poke struct wgpeer, rx_bytes} ptr peerReceivedBytes
        #{poke struct wgpeer, tx_bytes} ptr peerTransferredBytes
        #{poke struct wgpeer, persistent_keepalive_interval} ptr peerKeepaliveInterval
        #{poke struct wgpeer, num_ipmasks} ptr peerNumIpmasks

instance Storable WgDevice where
    sizeOf _              = #{size struct wgdevice}
    alignment _           = #{alignment struct wgdevice}
    peek ptr              = do
        magic <- #{peek struct wgdevice, version_magic} ptr
        unless (magic == apiVersionMagic) $ fail "unexpected version_magic"
        WgDevice <$> peekCString (ptr `plusPtr` #{offset struct wgdevice, interface})
                 <*> #{peek struct wgdevice, flags} ptr
                 <*> (K.toByteString <$> #{peek struct wgdevice, public_key} ptr)
                 <*> (K.toByteString <$> #{peek struct wgdevice, private_key} ptr)
                 <*> (K.toByteString <$> #{peek struct wgdevice, preshared_key} ptr)
                 <*> #{peek struct wgdevice, fwmark} ptr
                 <*> #{peek struct wgdevice, port} ptr
                 <*> #{peek struct wgdevice, num_peers} ptr
    poke ptr self@WgDevice{..}
        | length deviceInterface >= #{const IFNAMSIZ} = fail "interface name is too long"
        | otherwise                                   = do
            zeroMemory ptr $ fromIntegral $ sizeOf self
            #{poke struct wgdevice, version_magic} ptr apiVersionMagic
            pokeArray0 (0 :: Word8) (ptr `plusPtr` #{offset struct wgdevice, interface}) (map (fromIntegral.ord) deviceInterface)
            #{poke struct wgdevice, flags} ptr deviceFlags
            #{poke struct wgdevice, public_key} ptr (K.fromByteString devicePubkey)
            #{poke struct wgdevice, private_key} ptr (K.fromByteString devicePrivkey)
            #{poke struct wgdevice, preshared_key} ptr (K.fromByteString devicePSK)
            #{poke struct wgdevice, fwmark} ptr deviceFwmark
            #{poke struct wgdevice, port} ptr devicePort
            #{poke struct wgdevice, num_peers} ptr deviceNumPeers

readConfig :: Storable a => ByteString -> a
readConfig (PS fptr off len)
    | len == sizeOf output = output
    | otherwise            = error "UAPI.readConfig: length mismatch"
  where
    output = unsafePerformIO $ withForeignPtr fptr $ \ptr -> peek (ptr `plusPtr` off)

writeConfig :: Storable a => a -> ByteString
writeConfig input = unsafePerformIO $ do
    fptr <- mallocForeignPtr
    withForeignPtr fptr $ \ptr -> poke ptr input
    return $ PS (castForeignPtr fptr) 0 (sizeOf input)
