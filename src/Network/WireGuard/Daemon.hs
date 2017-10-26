module Network.WireGuard.Daemon
  ( runDaemon
  ) where

import           Control.Concurrent.Async                    (async, cancel)
import           Control.Concurrent.STM                      (atomically)
import           Control.Monad                               (void)
import           GHC.Conc.IO                                 (closeFdWith)
import           System.Directory                            (removeFile)
import           System.Posix.IO                             (closeFd)
import           System.Posix.Types                          (Fd)

import           Control.Concurrent.MVar                     (newEmptyMVar, putMVar,
                                                              takeMVar)
import           System.Posix.Signals                        (installHandler, sigTERM,
                                                              Handler(Catch), sigINT)

import           Network.WireGuard.Core                      (runCore)
import           Network.WireGuard.Internal.State            (createDevice)
import           Network.WireGuard.RPC                       (runRPC)
import           Network.WireGuard.TunListener               (runTunListener)
import           Network.WireGuard.UdpListener               (runUdpListener)
import           Network.WireGuard.Internal.Data.QueueSystem (DeviceQueues(..))
import           Network.WireGuard.Internal.PacketQueue      (newPacketQueue)
import           Network.WireGuard.Internal.Util             (catchIOExceptionAnd)

runDaemon :: String -> FilePath -> [Fd] -> IO ()
runDaemon intfName sockPath tunFds = do
    device <- atomically $ createDevice intfName

    rpcThread <- async $ runRPC sockPath device

    readTunChan <- newPacketQueue
    writeTunChan <- newPacketQueue
    readUdpChan <- newPacketQueue
    writeUdpChan <- newPacketQueue
    let devQueues = DeviceQueues readUdpChan writeUdpChan readTunChan writeTunChan
    tunListenerThread <- async $ runTunListener tunFds (readTunQueue devQueues) $ writeTunQueue devQueues
    udpListenerThread <- async $ runUdpListener device (readUdpQueue devQueues) $ writeUdpQueue devQueues

    coreThread <- async $ runCore device devQueues

    died <- newEmptyMVar

    let dieGracefully = do
            mapM_ cancel [rpcThread, tunListenerThread, udpListenerThread, coreThread]
            mapM_ (closeFdWith closeFd) tunFds
            catchIOExceptionAnd (return ()) (removeFile sockPath)
            putMVar died ()

    void $ installHandler sigTERM (Catch dieGracefully) Nothing
    void $ installHandler sigINT (Catch dieGracefully) Nothing

    takeMVar died
