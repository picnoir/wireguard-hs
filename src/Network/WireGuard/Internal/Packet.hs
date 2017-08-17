{-# LANGUAGE RecordWildCards #-}

module Network.WireGuard.Internal.Packet
  ( Packet(..)
  , parsePacket
  , buildPacket
  ) where

import           Control.Monad                       (replicateM_, unless, when)
import qualified Data.ByteString                     as BS
import           Foreign.Storable                    (sizeOf)

import           Data.Serialize

import           Network.WireGuard.Internal.Constant
import           Network.WireGuard.Internal.Data.Types

data Packet = HandshakeInitiation
              { senderIndex      :: !Index
              , encryptedPayload :: !EncryptedPayload
              }
            | HandshakeResponse
              { senderIndex      :: !Index
              , receiverIndex    :: !Index
              , encryptedPayload :: !EncryptedPayload
              }
            | PacketData
              { receiverIndex    :: !Index
              , counter          :: !Counter
              , encryptedPayload :: !EncryptedPayload
              , authTag          :: !AuthTag
              }
    deriving (Show)

parsePacket :: (BS.ByteString -> BS.ByteString) -> Get Packet
parsePacket getMac1 = do
    packetType <- lookAhead getWord8
    case packetType of
        1 -> verifyLength (==handshakeInitiationPacketLength) $ verifyMac getMac1 parseHandshakeInitiation
        2 -> verifyLength (==handshakeResponsePacketLength) $ verifyMac getMac1 parseHandshakeResponse
        4 -> verifyLength (>=packetDataMinimumPacketLength) parsePacketData
        _ -> fail "unknown packet"
  where
    handshakeInitiationPacketLength = 4 + indexSize + keyLength + aeadLength keyLength + aeadLength timestampLength + mac1Length + mac2Length
    handshakeResponsePacketLength   = 4 + indexSize + indexSize + keyLength + aeadLength 0 + mac1Length + mac2Length
    packetDataMinimumPacketLength   = 4 + indexSize + counterSize + aeadLength 0

    indexSize = sizeOf (undefined :: Index)
    counterSize = sizeOf (undefined :: Counter)

parseHandshakeInitiation :: Get Packet
parseHandshakeInitiation = do
    skip 4
    HandshakeInitiation <$> getWord32le <*> (remaining >>= getBytes)

parseHandshakeResponse :: Get Packet
parseHandshakeResponse = do
    skip 4
    HandshakeResponse <$> getWord32le <*> getWord32le <*> (remaining >>= getBytes)

parsePacketData :: Get Packet
parsePacketData = do
    skip 4
    PacketData <$> getWord32le <*> getWord64le <*>
        (remaining >>= getBytes . subtract authLength) <*> getBytes authLength

buildPacket :: (BS.ByteString -> BS.ByteString) -> Putter Packet
buildPacket getMac1 HandshakeInitiation{..} = appendMac getMac1 $ do
    putWord8 1
    replicateM_ 3 (putWord8 0)
    putWord32le senderIndex
    putByteString encryptedPayload

buildPacket getMac1 HandshakeResponse{..} = appendMac getMac1 $ do
    putWord8 2
    replicateM_ 3 (putWord8 0)
    putWord32le senderIndex
    putWord32le receiverIndex
    putByteString encryptedPayload

buildPacket _getMac1 PacketData{..} = do
    putWord8 4
    replicateM_ 3 (putWord8 0)
    putWord32le receiverIndex
    putWord64le counter
    putByteString encryptedPayload
    putByteString authTag

verifyLength :: (Int -> Bool) -> Get a -> Get a
verifyLength check ga = do
    outcome <- check <$> remaining
    unless outcome $ fail "wrong packet length"
    ga

verifyMac :: (BS.ByteString -> BS.ByteString) -> Get Packet -> Get Packet
verifyMac getMac1 ga = do
    bodyLength <- subtract (mac1Length + mac2Length) <$> remaining
    when (bodyLength < 0) $ fail "packet too small"
    expectedMac1 <- getMac1 <$> lookAhead (getBytes bodyLength)
    parsed <- isolate bodyLength ga
    receivedMac1 <- getBytes mac1Length
    when (expectedMac1 /= receivedMac1) $ fail "wrong mac1"
    skip mac2Length
    return parsed

appendMac :: (BS.ByteString -> BS.ByteString) -> Put -> Put
appendMac getMac1 p = do
    -- TODO: find a smart approach to avoid extra ByteString allocation
    let bs = runPut p
    putByteString bs
    putByteString (getMac1 bs)
    replicateM_ mac2Length (putWord8 0)
