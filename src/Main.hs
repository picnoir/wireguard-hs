{-# LANGUAGE RecordWildCards #-}

module Main where

import           Control.Concurrent              (getNumCapabilities)
import           Control.Monad                   (void)
import           Data.Monoid                     ((<>))
import           System.Directory                (createDirectoryIfMissing,
                                                  doesDirectoryExist)
import           System.Exit                     (die)
import           System.FilePath.Posix           (takeDirectory, (</>))
import           System.Info                     (os)
import           System.Posix.IO                 (OpenMode (..), closeFd,
                                                  defaultFileFlags, dupTo,
                                                  openFd, stdError, stdInput,
                                                  stdOutput)
import           System.Posix.Process            (forkProcess)
import           System.Posix.Types              (Fd)

import           Options.Applicative

import           Network.WireGuard.Daemon        (runDaemon)
import           Network.WireGuard.Foreign.Tun   (openTun)
import           Network.WireGuard.Internal.Util (catchIOExceptionAnd)

data Opts = Opts
          { foreground :: Bool
          , intfName   :: String
          }

parser :: ParserInfo Opts
parser = info (helper <*> opts) fullDesc
  where
    opts = Opts <$> _foreground
                <*> _intfName

    _foreground = switch
                ( long "foreground"
               <> short 'f'
               <> help "run in the foreground")

    _intfName = argument str
              ( metavar "interface"
             <> help ("device interface name (e.g. " ++ intfNameExample ++ ")"))

    intfNameExample | os == "darwin" = "utun1"
                    | otherwise      = "wg0"


main :: IO ()
main = do
    Opts{..} <- execParser parser

    runPath <- maybe (die "failed to find path to bind socket") return =<< findVarRun
    let sockPath = runPath </> "wireguard" </> (intfName ++ ".sock")
    createDirectoryIfMissing False (takeDirectory sockPath)

    fds <- maybe (die "failed to open device") return =<< openTun intfName =<< getNumCapabilities

    let runner daemon | foreground = daemon
                      | otherwise  = void $ forkProcess $ do
                          mapM_ redirectToNull [stdInput, stdOutput, stdError]
                          daemon

    runner $ runDaemon intfName sockPath fds

redirectToNull :: Fd -> IO ()
redirectToNull fd = catchIOExceptionAnd (return ()) $ do
    nullFd <- openFd "/dev/null" ReadWrite Nothing defaultFileFlags
    closeFd fd
    void $ dupTo nullFd fd

findVarRun :: IO (Maybe FilePath)
findVarRun = loop ["/var/run", "/run"]
  where
    loop [] = return Nothing
    loop (d:ds) = do
        exists <- doesDirectoryExist d
        if exists
          then return (Just d)
          else loop ds
