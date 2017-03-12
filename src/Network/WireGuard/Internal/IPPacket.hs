module Network.WireGuard.Internal.IPPacket
  ( IPPacket(..)
  , parseIPPacket
  ) where

import qualified Data.ByteArray   as BA
import           Data.IP          (IPv4, IPv6, fromHostAddress,
                                   fromHostAddress6)
import           Foreign.Ptr      (Ptr)
import           Foreign.Storable (peekByteOff)

import           Data.Bits
import           Data.Word

data IPPacket = InvalidIPPacket
              | IPv4Packet { src4 :: IPv4, dest4 :: IPv4 }
              | IPv6Packet { src6 :: IPv6, dest6 :: IPv6 }

parseIPPacket :: BA.ByteArrayAccess ba => ba -> IO IPPacket
parseIPPacket packet | BA.length packet < 20 = return InvalidIPPacket
parseIPPacket packet = BA.withByteArray packet $ \ptr -> do
    firstByte <- peekByteOff ptr 0 :: IO Word8
    let version = firstByte `shiftR` 4
        parse4 = do
            s4 <- peekByteOff ptr 12
            d4 <- peekByteOff ptr 16
            return (IPv4Packet (fromHostAddress s4) (fromHostAddress d4))
        parse6
            | BA.length packet < 40 = return InvalidIPPacket
            | otherwise = do
                s6a <- peek32be ptr 8
                s6b <- peek32be ptr 12
                s6c <- peek32be ptr 16
                s6d <- peek32be ptr 20
                d6a <- peek32be ptr 24
                d6b <- peek32be ptr 28
                d6c <- peek32be ptr 32
                d6d <- peek32be ptr 36
                let s6 = (s6a, s6b, s6c, s6d)
                    d6 = (d6a, d6b, d6c, d6d)
                return (IPv6Packet (fromHostAddress6 s6) (fromHostAddress6 d6))
    case version of
        4 -> parse4
        6 -> parse6
        _ -> return InvalidIPPacket

peek32be :: Ptr a -> Int -> IO Word32
peek32be ptr offset = do
    a <- peekByteOff ptr offset       :: IO Word8
    b <- peekByteOff ptr (offset + 1) :: IO Word8
    c <- peekByteOff ptr (offset + 2) :: IO Word8
    d <- peekByteOff ptr (offset + 3) :: IO Word8
    return $! (fromIntegral a `unsafeShiftL` 24) .|.
              (fromIntegral b `unsafeShiftL` 16) .|.
              (fromIntegral c `unsafeShiftL` 8)  .|.
              fromIntegral d
