{-# LANGUAGE OverloadedStrings #-}

module Network.WireGuard.Internal.RpcParsers(
  RpcRequest(..),
  OpType(..),
  RpcSetPayload(..),
  RpcDevicePayload(..),
  RpcPeerPayload(..),
  requestParser,
  deviceParser
) where

import           Control.Applicative                       ((*>), (<|>))
import           Control.Monad                             (liftM, join)
import           Crypto.Noise.DH                           (dhSecToBytes, dhBytesToPair)
import           Data.Attoparsec.ByteString.Char8          (Parser, string,
                                                            takeTill, option)
import           Data.Attoparsec.Combinator                ((<?>))                                                            
import qualified Data.ByteArray                      as BA (convert)
import qualified Data.ByteString                     as BS (head)
import           Data.ByteString.Conversion
import qualified Data.ByteString.Char8               as BC (pack)
import           Data.Maybe                                (fromMaybe)
import           Data.IP                                   (IPRange(..))
import           Data.Hex                                  (unhex)
import           Data.Word                                 (Word, Word64)
import           Data.ByteString                           (ByteString)
import           Network.Socket.Internal                   (SockAddr)


import Network.WireGuard.Internal.Data.RpcTypes (OpType(..),
                                                 RpcRequest(..),
                                                 RpcDevicePayload(..),
                                                 RpcPeerPayload(..),
                                                 RpcSetPayload(..))


-- | Attoparsec parser used to parse a RPC request, both Set or Get.
requestParser :: Parser RpcRequest 
requestParser = do
  op <- requestTypeParser
  let p = case op of
                  Set -> undefined
                  Get -> Nothing
  _ <- string $ BC.pack "\n\n"
  return $ RpcRequest op p

requestTypeParser :: Parser OpType
requestTypeParser = "get=1" *> return Get
                <|> "set=1" *> return Set

setPayloadParser :: Parser RpcSetPayload
setPayloadParser = undefined

deviceParser :: Parser RpcDevicePayload 
deviceParser = do
  pkHex  <- option Nothing (unhex <$> keyParser "private_key") <?> "Primary key parser"
  "\n"
  let pk = join $ (dhBytesToPair . BA.convert) <$> pkHex 
  p      <- (fromMaybe 0 . fromByteString) <$> keyParser "listen_port" <?> "Port parser"
  "\n"
  fwmark <- option Nothing (fromByteString <$> keyParser "fwmark") <?> "Fwmark parser"
  return $ RpcDevicePayload pk p fwmark False

keyParser :: ByteString -> Parser ByteString
keyParser str = (string str *> "=")  *> takeTill (=='\n') 
