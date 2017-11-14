{-# LANGUAGE ScopedTypeVariables #-}

module Network.WireGuard.Internal.Util
  ( retryWithBackoff
  , ignoreSyncExceptions
  , foreverWithBackoff
  , catchIOExceptionAnd
  , catchSomeExceptionAnd
  , withJust
  , dropUntilM
  , zeroMemory
  , copyMemory
  , assertJust
  , tryReadTMVar
  , writeMaybeTMVar
  ) where

import           Control.Concurrent                  (threadDelay)
import           Control.Monad                       (void)
import           Control.Exception                   (Exception (..),
                                                      IOException,
                                                      SomeAsyncException,
                                                      SomeException, throwIO)
import           Control.Monad.Catch                 (MonadCatch (..))
import           Control.Monad.Trans.Except          (ExceptT, throwE)
import           Data.Foldable                       (forM_)
import           System.IO                           (hPutStrLn, stderr)
import           Foreign                             (Ptr)
import           Foreign.C                           (CSize(..), CInt(..))
import           Control.Concurrent.STM              (STM, TMVar, isEmptyTMVar,
                                                      tryTakeTMVar, swapTMVar,
                                                      putTMVar)

import           Network.WireGuard.Internal.Constant (retryMaxWaitTime)

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
    forM_ ma func 

dropUntilM :: Monad m => (a -> Bool) -> m a -> m a
dropUntilM cond ma = loop
  where
    loop = do
        a <- ma
        if cond a
          then return a
          else loop

zeroMemory :: Ptr a -> CSize -> IO ()
zeroMemory dest nbytes = memset dest 0 (fromIntegral nbytes)

copyMemory :: Ptr a -> Ptr b -> CSize -> IO ()
copyMemory = memcpy 

assertJust :: Monad m => e -> ExceptT e m (Maybe a) -> ExceptT e m a
assertJust err ma = do
    res <- ma
    case res of
        Just a  -> return a
        Nothing -> throwE err

tryReadTMVar :: TMVar a -> STM (Maybe a)
tryReadTMVar tv = do
    v <- tryTakeTMVar tv
    resetTMVar v tv
    return v
    where
        resetTMVar (Just var) stv = putTMVar stv var
        resetTMVar _ _ = return ()

writeMaybeTMVar :: TMVar a -> Maybe a -> STM ()
writeMaybeTMVar tv (Just v) = do
                                isEmpty <- isEmptyTMVar tv
                                if isEmpty
                                  then putTMVar  tv v
                                  else void $ swapTMVar tv v
writeMaybeTMVar tv Nothing = void $ tryTakeTMVar tv 

foreign import ccall unsafe "string.h" memset :: Ptr a -> CInt -> CSize -> IO ()
foreign import ccall unsafe "string.h" memcpy :: Ptr a -> Ptr b -> CSize -> IO ()
