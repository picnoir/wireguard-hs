{-# LANGUAGE CPP #-}

module Network.WireGuard.Foreign.Tun
  ( openTun
  , fdReadBuf
  , fdWriteBuf
  ) where

import           System.Posix.Types (Fd (..))

import           Foreign
import           Foreign.C

#ifdef OS_LINUX
import           System.Posix.IO    (fdReadBuf, fdWriteBuf)
#endif

openTun :: String -> Int -> IO (Maybe [Fd])
openTun intfName threads =
    withCString intfName $ \intf_name_c ->
    allocaArray threads $ \fds_c -> do
        res <- tun_alloc_c intf_name_c (fromIntegral threads) fds_c  -- TODO: handle exception
        if res > 0
            then Just . map Fd <$> peekArray (fromIntegral res) fds_c
            else return Nothing

foreign import ccall safe "tun.h tun_alloc" tun_alloc_c :: CString -> CInt -> Ptr CInt -> IO CInt

#ifdef OS_MACOS
fdReadBuf :: Fd -> Ptr Word8 -> CSize -> IO CSize
fdReadBuf _fd _buf 0 = return 0
fdReadBuf fd buf nbytes =
    fmap fromIntegral $
        throwErrnoIfMinus1Retry "fdReadBuf" $
            utun_read_c (fromIntegral fd) (castPtr buf) nbytes

fdWriteBuf :: Fd -> Ptr Word8 -> CSize -> IO CSize
fdWriteBuf fd buf len =
    fmap fromIntegral $
        throwErrnoIfMinus1Retry "fdWriteBuf" $
            utun_write_c (fromIntegral fd) (castPtr buf) len

foreign import ccall safe "tun.h utun_read" utun_read_c :: CInt -> Ptr CChar -> CSize -> IO CSize
foreign import ccall safe "tun.h utun_write" utun_write_c :: CInt -> Ptr CChar -> CSize -> IO CSize
#endif
