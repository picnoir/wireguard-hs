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

import           Control.Concurrent.MVar
import           System.Posix.Signals

import           Network.WireGuard.Core                 (runCore)
import           Network.WireGuard.Internal.State       (createDevice)
import           Network.WireGuard.RPC                  (runRPC)
import           Network.WireGuard.TunListener          (runTunListener)
import           Network.WireGuard.UdpListener          (runUdpListener)

import           Network.WireGuard.Internal.Constant
import           Network.WireGuard.Internal.PacketQueue
import           Network.WireGuard.Internal.Util

runDaemon :: String -> FilePath -> [Fd] -> IO ()
runDaemon intfName sockPath tunFds = do
    device <- atomically $ createDevice intfName

    rpcThread <- async $ runRPC sockPath device

    readTunChan <- atomically $ newPacketQueue maxQueuedTunPackets
    writeTunChan <- atomically $ newPacketQueue maxQueuedTunPackets
    tunListenerThread <- async $ runTunListener tunFds readTunChan writeTunChan

    -- TODO: Support per-host packet queue
    -- TODO: Add timestamp and discard really ancient UDP packets
    readUdpChan <- atomically $ newPacketQueue maxQueuedUdpPackets
    writeUdpChan <- atomically $ newPacketQueue maxQueuedUdpPackets
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
