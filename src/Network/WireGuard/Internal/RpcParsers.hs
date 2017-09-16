{-# LANGUAGE OverloadedStrings #-}

{-|
Module      : Network.WireGuard.Internal.RpcParsers
Description : Collection of parsers related to the communication with the wg CLI utility.
Copyright   : Félix Baylac-Jacqué, 2017
License     : GPL-3
Maintainer  : felix@alternativebit.fr
Stability   : experimental
Portability : POSIX

Collection of attoparsec parsers related to the communication with the wg CLI utility.
|-}

module Network.WireGuard.Internal.RpcParsers(
  requestParser,
  deviceParser,
  peerParser,
  setPayloadParser
) where
import           Control.Applicative                       ((*>), (<|>))
import           Control.Monad                             (join)
import           Crypto.Noise.DH                           (dhBytesToPair, dhBytesToPub)
import           Data.Attoparsec.ByteString.Char8          (Parser, string,
                                                            takeTill, option,
                                                            endOfLine, peekChar')
import           Data.Attoparsec.Text                      (isEndOfLine)
import           Data.Attoparsec.Combinator                ((<?>), many')
import qualified Data.ByteArray                      as BA (convert, )
import           Data.ByteString                           (ByteString)
import           Data.ByteString.Conversion                (fromByteString)
import qualified Data.ByteString.Char8               as BC (pack, unpack)
import           Data.Maybe                                (fromMaybe, listToMaybe,
                                                            fromJust)
import           Data.IP                                   (IPRange, toHostAddress6)
import           Data.Hex                                  (unhex)
import           Network.Socket                            (SockAddr, tupleToHostAddress,
                                                            SockAddr(..))


import Network.WireGuard.Internal.Data.RpcTypes (OpType(..),
                                                 RpcRequest(..),
                                                 RpcDevicePayload(..),
                                                 RpcPeerPayload(..),
                                                 RpcSetPayload(..),
                                                 RpcDeviceField(..),
                                                 RpcPeerField(..))

-- | Parses a RPC operation coming from the wg CLI.
--
--   See <https://www.wireguard.com/xplatform/> for more informations about the RPC set operation.
requestParser :: Parser RpcRequest 
requestParser = do
  op <- requestTypeParser
  p  <- case op of
          Set -> Just <$> setPayloadParser
          Get -> return Nothing
  _ <- string $ BC.pack "\n"
  return $ RpcRequest op p

-- | Parses a set operation.
--
--   See <https://www.wireguard.com/xplatform/> for more informations about the RPC set operation.
setPayloadParser :: Parser RpcSetPayload
setPayloadParser = do
  dev <- deviceParser
  peers <- many' peerParser
  return $ RpcSetPayload dev peers

-- | Parses a device entry during a RPC set operation.
--
--   See <https://www.wireguard.com/xplatform/> for more informations about the RPC set operation.
deviceParser :: Parser RpcDevicePayload 
deviceParser = do
  fields <- deviceFieldsParser
  let devPk = join $ listToMaybe [ pkF | RpcPk pkF <- fields]
  let p  = head [ pF | RpcPort pF <- fields]
  let fw = join $ listToMaybe [ fwF | RpcFwMark fwF <- fields]
  let rmDev = not $ null [True | RpcReplacePeers <- fields] 
  return $ RpcDevicePayload devPk p fw rmDev

-- | Parses a peer entry during a RPC set operation.
--
--   See <https://www.wireguard.com/xplatform/> for more informations about the RPC set operation.
peerParser :: Parser RpcPeerPayload
peerParser = do
    peerPubK   <- parsePubKey
    fields     <- peerFieldsParser
    let rm = not $ null [rmF | RpcRmFlag rmF <- fields] 
    let psh = listToMaybe [pshF | RpcPsh pshF <- fields]
    let endPL = [endPF | RpcEndp endPF <- fields]
    endP <- if null endPL
                then fail "Cannot parse Peer endpoint" 
                else return $ head endPL
    let ka   = fromMaybe 0 $ listToMaybe [kaF | RpcKA kaF <- fields]
    let rmIps = not $ null [rmIpsF | RpcDelIps rmIpsF <- fields]
    let allIpR = [ipRF | RpcAllIp ipRF <- fields]
    return $ RpcPeerPayload peerPubK rm psh endP ka rmIps allIpR
  where
    parsePubKey = do        
        _ <- "public_key=" <?> "Peer delimiter"
        pubHex <- unhex <$> takeTill isEndOfLine :: Parser (Maybe ByteString)
        _ <- "\n"
        let pubMaybe = join $ (dhBytesToPub . BA.convert) <$> pubHex
        maybe (fail "Cannot parse peer's public key") return pubMaybe

requestTypeParser :: Parser OpType
requestTypeParser = "get=1\n" *> return Get 
                <|> "set=1\n" *> return Set

deviceFieldsParser :: Parser [RpcDeviceField]
deviceFieldsParser = many' (deviceFieldParser <* endOfLine)
  
deviceFieldParser :: Parser RpcDeviceField
deviceFieldParser = do
  key <- takeTill (=='=')
  _ <- "="
  case key of       
    "private_key" -> do
      pkHex <- option Nothing (unhex <$> takeTill isEndOfLine) <?> "Primary Key parser"
      return . RpcPk . join $ (dhBytesToPair . BA.convert) <$> pkHex
    "listen_port" -> do
      p <- (fromMaybe 0 . fromByteString) <$> takeTill isEndOfLine <?> "Listen Port parser"
      return $ RpcPort p
    "fwmark" -> do
      fwmark <- option Nothing (fromByteString <$> takeTill isEndOfLine) <?> "fwmark parser"
      return $ RpcFwMark fwmark
    "replace_peers" -> do
      _ <- "true"
      return RpcReplacePeers
    _ -> fail "Not a device key"


peerFieldsParser :: Parser [RpcPeerField]
peerFieldsParser = many' (peerFieldParser <* endOfLine)

peerFieldParser :: Parser RpcPeerField
peerFieldParser = do
  key <- takeTill (=='=') 
  _ <- "="
  case key of
    "remove" -> (do 
      _ <- "true"
      return $ RpcRmFlag True) <?> "Remove peer parser"
    "preshared_key" -> (do
      pshHex <- unhex <$> takeTill isEndOfLine
      return . RpcPsh . BA.convert . fromJust $ pshHex) <?> "Psh key peer parser"
    "endpoint" -> RpcEndp <$> parseIpAddress <?> "Endpoint peer parser"
    "persistent_keepalive_interval" -> (RpcKA . read . BC.unpack) <$> takeTill isEndOfLine <?> "Persistant keepalive parser"
    "replace_allowed_ips" -> (do
      _ <- "true"
      return $ RpcDelIps True) <?> "Replace allowed Ips parser"
    "allowed_ip" -> RpcAllIp <$> parseIpRange <?> "Allowed ips parser"
    _ -> fail "Not a peer key"

parseIpAddress :: Parser SockAddr
parseIpAddress = do
  f <- peekChar'
  if f == '[' 
    then parseIpv6
    else parseIpv4
  where
    parseIpv6 = do
      _ <- "["
      host1 <- (fromJust . fromByteString) <$> takeTill (=='%')
      _ <- "%"
      scope_id <- (fromJust . fromByteString) <$> takeTill (==']')
      _ <- "]:"
      port <- (read . fromJust . fromByteString) <$> takeTill isEndOfLine
      let host = toHostAddress6 $ read host1
      return $ SockAddrInet6 port 0 host scope_id 
    parseIpv4 = do
      ip1 <- (fromJust . fromByteString) <$> takeTill (=='.')
      _   <- "."
      ip2 <- (fromJust . fromByteString) <$> takeTill (=='.')
      _   <- "."
      ip3 <- (fromJust . fromByteString) <$> takeTill (=='.')
      _   <- "."
      ip4 <- (fromJust . fromByteString) <$> takeTill (==':')
      _   <- ":"
      p   <- (fromInteger . fromJust . fromByteString) <$> takeTill isEndOfLine 
      return . SockAddrInet p $ tupleToHostAddress (ip1,ip2,ip3,ip4)

parseIpRange :: Parser IPRange
parseIpRange = do
  f <- peekChar'
  if f == '['
    then parseIpv6Range
    else parseIpv4Range
  where
    parseIpv4Range = do
        line <- takeTill isEndOfLine
        return . read . fromJust $ fromByteString line
    parseIpv6Range = do
        _ <- "["
        rng <- takeTill (==']')
        _ <- "]"
        return . read . fromJust $ fromByteString rng
 
