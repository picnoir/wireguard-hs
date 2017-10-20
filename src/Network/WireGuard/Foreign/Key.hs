module Network.WireGuard.Foreign.Key
  ( Key
  , fromByteString
  , toByteString
  ) where

import qualified Data.ByteString as BS (ByteString, length, unpack,
                                        pack)
import           Foreign               (Storable(..), Word8, peekArray,
                                        castPtr, pokeArray)

import           Network.WireGuard.Internal.Constant (keyLength)

newtype Key = Key { fromKey :: [Word8] }

instance Storable Key where
    sizeOf _         = sizeOf (undefined :: Word8) * keyLength
    alignment _      = alignment (undefined :: Word8)
    peek ptr         = Key <$> peekArray keyLength (castPtr ptr)
    poke ptr (Key k)
        | length k == keyLength = pokeArray (castPtr ptr) k
        | otherwise             = error "Key.poke: key length mismatch"

fromByteString :: BS.ByteString -> Key
fromByteString bs
    | BS.length bs == keyLength = Key (BS.unpack bs)
    | otherwise                 = error "Key.fromByteString: key length mismatch"

toByteString :: Key -> BS.ByteString
toByteString = BS.pack . fromKey
