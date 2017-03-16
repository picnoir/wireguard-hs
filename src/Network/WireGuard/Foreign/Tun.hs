{-# LANGUAGE CPP #-}

module Network.WireGuard.Foreign.Tun
  ( openTun
  , tunReadBuf
  , tunWriteBuf
  ) where

import           Control.Concurrent     (threadWaitRead, threadWaitWrite)
import           Control.Monad          (forM_)
import           System.Posix.Internals (setNonBlockingFD)
import           System.Posix.Types     (Fd (..))

import           Foreign
import           Foreign.C

openTun :: String -> Int -> IO [Fd]
openTun intfName threads =
    withCString intfName $ \intf_name_c ->
    allocaArray threads $ \fds_c -> do
        res <- throwErrnoIfMinus1Retry "openTun" $
            tun_alloc_c intf_name_c (fromIntegral threads) fds_c
        fds <- peekArray (fromIntegral res) fds_c
        forM_ fds $ \fd -> setNonBlockingFD fd True
        return (map Fd fds)

tunReadBuf :: Fd -> Ptr Word8 -> CSize -> IO CSize
tunReadBuf _fd _buf 0 = return 0
tunReadBuf fd buf nbytes =
    fmap fromIntegral $
        throwErrnoIfMinus1RetryMayBlock "tunReadBuf"
            (tun_read_c (fromIntegral fd) (castPtr buf) nbytes)
                (threadWaitRead fd)

tunWriteBuf :: Fd -> Ptr Word8 -> CSize -> IO CSize
tunWriteBuf fd buf len =
    fmap fromIntegral $
        throwErrnoIfMinus1RetryMayBlock "tunWriteBuf"
            (tun_write_c (fromIntegral fd) (castPtr buf) len)
                (threadWaitWrite fd)

foreign import ccall unsafe "tun.h tun_alloc" tun_alloc_c :: CString -> CInt -> Ptr CInt -> IO CInt

#ifdef OS_MACOS
foreign import ccall unsafe "tun.h utun_read" tun_read_c :: CInt -> Ptr CChar -> CSize -> IO CSize
foreign import ccall unsafe "tun.h utun_write" tun_write_c :: CInt -> Ptr CChar -> CSize -> IO CSize
#else
foreign import ccall unsafe "read" tun_read_c :: CInt -> Ptr CChar -> CSize -> IO CSize
foreign import ccall unsafe "write" tun_write_c :: CInt -> Ptr CChar -> CSize -> IO CSize
#endif
