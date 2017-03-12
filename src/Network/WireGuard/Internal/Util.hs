{-# LANGUAGE ScopedTypeVariables #-}

module Network.WireGuard.Internal.Util
  ( retryWithBackoff
  , ignoreSyncExceptions
  , foreverWithBackoff
  , catchIOExceptionAnd
  , catchSomeExceptionAnd
  , withJust
  , zeroMemory
  , copyMemory
  ) where

import           Control.Concurrent                  (threadDelay)
import           Control.Exception                   (Exception (..),
                                                      IOException,
                                                      SomeAsyncException,
                                                      SomeException, throwIO)
import           Control.Monad.Catch                 (MonadCatch (..))
import           System.IO                           (hPutStrLn, stderr)

import           Foreign
import           Foreign.C

import           Network.WireGuard.Internal.Constant

retryWithBackoff :: IO () -> IO ()
retryWithBackoff = foreverWithBackoff . ignoreSyncExceptions

ignoreSyncExceptions :: IO () -> IO ()
ignoreSyncExceptions m = catch m handleExcept
  where
    handleExcept e = case fromException e of
        Just asyncExcept -> throwIO (asyncExcept :: SomeAsyncException)
        Nothing          -> hPutStrLn stderr (displayException e)  -- TODO: proper logging

foreverWithBackoff :: IO () -> IO ()
foreverWithBackoff m = loop 1
  where
    loop t = m >> threadDelay t >> loop (min (t * 2) retryMaxWaitTime)

catchIOExceptionAnd :: MonadCatch m => m () -> m () -> m ()
catchIOExceptionAnd what m = catch m $ \(_ :: IOException) -> what

catchSomeExceptionAnd :: MonadCatch m => m () -> m () -> m ()
catchSomeExceptionAnd what m = catch m $ \(_ :: SomeException) -> what

withJust :: Monad m => m (Maybe a) -> (a -> m ()) -> m ()
withJust mma func = do
    ma <- mma
    case ma of
        Nothing -> return ()
        Just a  -> func a

zeroMemory :: Ptr a -> CSize -> IO ()
zeroMemory dest nbytes = memset dest 0 (fromIntegral nbytes)

copyMemory :: Ptr a -> Ptr b -> CSize -> IO ()
copyMemory dest src nbytes = memcpy dest src nbytes

foreign import ccall unsafe "string.h" memset :: Ptr a -> CInt -> CSize -> IO ()
foreign import ccall unsafe "string.h" memcpy :: Ptr a -> Ptr b -> CSize -> IO ()
