module Network.WireGuard.Daemon
  ( runDaemon
  ) where

import           Control.Concurrent.Async               (async, cancel)
import           Control.Concurrent.STM                 (atomically)
import           Control.Monad                          (void)
import           GHC.Conc.IO                            (closeFdWith)
import           System.Directory                       (removeFile)
import           System.Posix.IO                        (closeFd)
import           System.Posix.Types                     (Fd)

import           Control.Concurrent.MVar                (newEmptyMVar, putMVar,
                                                         takeMVar)
import           System.Posix.Signals                   (installHandler, sigTERM,
                                                         Handler(Catch), sigINT)

import           Network.WireGuard.Core                 (runCore)
import           Network.WireGuard.Internal.State       (createDevice)
import           Network.WireGuard.RPC                  (runRPC)
import           Network.WireGuard.TunListener          (runTunListener)
import           Network.WireGuard.UdpListener          (runUdpListener)

import           Network.WireGuard.Internal.PacketQueue (newPacketQueue)
import           Network.WireGuard.Internal.Util        (catchIOExceptionAnd)

runDaemon :: String -> FilePath -> [Fd] -> IO ()
runDaemon intfName sockPath tunFds = do
    device <- atomically $ createDevice intfName

    rpcThread <- async $ runRPC sockPath device

    readTunChan <- newPacketQueue
    writeTunChan <- newPacketQueue
    tunListenerThread <- async $ runTunListener tunFds readTunChan writeTunChan

    -- TODO: Support per-host packet queue
    readUdpChan <- newPacketQueue
    writeUdpChan <- newPacketQueue
    udpListenerThread <- async $ runUdpListener device readUdpChan writeUdpChan

    coreThread <- async $ runCore device readTunChan writeTunChan readUdpChan writeUdpChan

    died <- newEmptyMVar

    let dieGracefully = do
            mapM_ cancel [rpcThread, tunListenerThread, udpListenerThread, coreThread]
            mapM_ (closeFdWith closeFd) tunFds
            catchIOExceptionAnd (return ()) (removeFile sockPath)
            putMVar died ()

    void $ installHandler sigTERM (Catch dieGracefully) Nothing
    void $ installHandler sigINT (Catch dieGracefully) Nothing

    takeMVar died
