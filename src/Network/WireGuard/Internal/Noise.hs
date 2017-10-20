{-# LANGUAGE OverloadedStrings #-}
module Network.WireGuard.Internal.Noise
  ( NoiseStateWG
  , newNoiseState
  , sendFirstMessage
  , recvFirstMessageAndReply
  , recvSecondMessage
  , encryptMessage
  , decryptMessage
  ) where

import           Control.Exception                  (SomeException)
import           Control.Lens                       ((&), (.~), (^.))
import           Control.Monad                      (unless)
import           Control.Monad.Catch                (throwM)
import qualified Crypto.Cipher.ChaChaPoly1305       as CCP
import           Crypto.Error                       (throwCryptoError)
import           Crypto.Noise.Cipher                (cipherSymToBytes)
import           Crypto.Noise.Cipher.ChaChaPoly1305 (ChaChaPoly1305)
import           Crypto.Noise.DH.Curve25519         (Curve25519)
import           Crypto.Noise.HandshakePatterns     (noiseIK)
import           Crypto.Noise.Hash.BLAKE2s          (BLAKE2s)
import           Crypto.Noise.Internal.CipherState  (csk)
import           Crypto.Noise.Internal.NoiseState   (nsReceivingCipherState,
                                                     nsSendingCipherState)
import           Data.ByteArray                     (ScrubbedBytes, convert)
import           Data.ByteString                    (ByteString)
import qualified Data.ByteString                    as BS
import           Data.Maybe                         (fromJust)
import           Data.Serialize                     (putWord64le, runPut)

import           Crypto.Noise                       (NoiseState, HandshakeRole,
                                                     noiseState, defaultHandshakeOpts,
                                                     hoPrologue, hoLocalStatic,
                                                     hoPreSharedKey, hoRemoteStatic,
                                                     hoLocalEphemeral, writeMessage,
                                                     readMessage, handshakeComplete,
                                                     remoteStaticKey, NoiseException(..))

import           Network.WireGuard.Internal.Data.Types (KeyPair, PresharedKey,
                                                        PublicKey, SessionKey,
                                                        Counter, EncryptedPayload,
                                                        AuthTag, SessionKey,
                                                        sendKey, recvKey,
                                                        SessionKey(..))

type NoiseStateWG = NoiseState ChaChaPoly1305 Curve25519 BLAKE2s

newNoiseState :: KeyPair -> Maybe PresharedKey -> KeyPair -> Maybe PublicKey -> HandshakeRole -> NoiseStateWG
newNoiseState staticKey presharedKey ephemeralKey remotePub role =
    noiseState $ defaultHandshakeOpts noiseIK role
               & hoPrologue       .~ "WireGuard v0 zx2c4 Jason@zx2c4.com"
               & hoLocalStatic    .~ Just staticKey
               & hoPreSharedKey   .~ presharedKey
               & hoRemoteStatic   .~ remotePub
               & hoLocalEphemeral .~ Just ephemeralKey

sendFirstMessage :: NoiseStateWG -> ScrubbedBytes
                 -> Either SomeException (ByteString, NoiseStateWG)
sendFirstMessage = writeMessage

recvFirstMessageAndReply :: NoiseStateWG -> ByteString -> ScrubbedBytes
                         -> Either SomeException (ByteString, ScrubbedBytes, PublicKey, SessionKey)
recvFirstMessageAndReply state0 ciphertext1 plaintext2 = do
    (plaintext1, state1) <- readMessage state0 ciphertext1
    (ciphertext2, state2) <- writeMessage state1 plaintext2
    unless (handshakeComplete state2) internalError
    case remoteStaticKey state2 of
        Nothing   -> internalError
        Just rpub -> return (ciphertext2, plaintext1, rpub, extractSessionKey state2)

recvSecondMessage :: NoiseStateWG -> ByteString
                  -> Either SomeException (ScrubbedBytes, SessionKey)
recvSecondMessage state1 ciphertext2 = do
    (plaintext2, state2) <- readMessage state1 ciphertext2
    unless (handshakeComplete state2) internalError
    return (plaintext2, extractSessionKey state2)

encryptMessage :: SessionKey -> Counter -> ScrubbedBytes -> (EncryptedPayload, AuthTag)
encryptMessage key counter plaintext = (ciphertext, convert authtag)
  where
    st0 = throwCryptoError (CCP.initialize (sendKey key) (getNonce counter))
    (ciphertext, st) = CCP.encrypt (convert plaintext) st0
    authtag = CCP.finalize st

decryptMessage :: SessionKey -> Counter -> (EncryptedPayload, AuthTag) -> Maybe ScrubbedBytes
decryptMessage key counter (ciphertext, authtag)
    | authtag == authtagExpected = Just (convert plaintext)
    | otherwise                  = Nothing
  where
    st0 = throwCryptoError (CCP.initialize (recvKey key) (getNonce counter))
    (plaintext, st) = CCP.decrypt ciphertext st0
    authtagExpected = convert $ CCP.finalize st

getNonce :: Counter -> CCP.Nonce
getNonce counter = throwCryptoError (CCP.nonce8 constant iv)
  where
    constant = BS.replicate 4 0
    iv = runPut (putWord64le counter)

extractSessionKey :: NoiseStateWG -> SessionKey
extractSessionKey ns =
    SessionKey (cipherSymToBytes $ fromJust (ns ^. nsSendingCipherState) ^. csk)
               (cipherSymToBytes $ fromJust (ns ^. nsReceivingCipherState) ^. csk)

internalError :: Either SomeException a
internalError = throwM (InvalidHandshakeOptions "internal error")
