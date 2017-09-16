module Network.WireGuard.TunListener
  ( runTunListener
  ) where

import           Control.Concurrent.Async               (wait, withAsync)
import           Control.Monad                          (forever, void)
import qualified Data.ByteArray                         as BA
import           Data.Word                              (Word8)
import           Foreign.Marshal.Alloc                  (allocaBytes)
import           Foreign.Ptr                            (Ptr)
import           System.Posix.Time                      (epochTime)
import           System.Posix.Types                     (Fd)

import           Network.WireGuard.Foreign.Tun
import           Network.WireGuard.Internal.Constant
import           Network.WireGuard.Internal.PacketQueue
import           Network.WireGuard.Internal.Data.Types
import           Network.WireGuard.Internal.Util

runTunListener :: [Fd] -> PacketQueue (Time, TunPacket) -> PacketQueue TunPacket -> IO ()
runTunListener fds readTunChan writeTunChan = loop fds []
  where
    loop [] asyncs = mapM_ wait asyncs
    loop (fd:rest) asyncs =
        withAsync (retryWithBackoff $ handleRead readTunChan fd) $ \rt ->
        withAsync (retryWithBackoff $ handleWrite writeTunChan fd) $ \wt ->
            loop rest (rt:wt:asyncs)

handleRead :: PacketQueue (Time, TunPacket) -> Fd -> IO ()
handleRead readTunChan fd = allocaBytes tunReadBufferLength $ \buf ->
    forever (((,) <$> epochTime <*> readTun buf fd) >>= pushPacketQueue readTunChan)

handleWrite :: PacketQueue TunPacket -> Fd -> IO ()
handleWrite writeTunChan fd =
    forever (popPacketQueue writeTunChan >>= writeTun fd)

readTun :: BA.ByteArray ba => Ptr Word8 -> Fd -> IO ba
readTun buf fd = do
    nbytes <- tunReadBuf fd buf (fromIntegral tunReadBufferLength)
    snd <$> BA.allocRet (fromIntegral nbytes)
        (\ptr -> copyMemory ptr buf nbytes >> zeroMemory buf nbytes)

writeTun :: BA.ByteArrayAccess ba => Fd -> ba -> IO ()
writeTun fd ba = BA.withByteArray ba $ \ptr -> 
    void $ tunWriteBuf fd ptr (fromIntegral (BA.length ba))
