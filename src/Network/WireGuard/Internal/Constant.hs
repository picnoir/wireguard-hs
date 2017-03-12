module Network.WireGuard.Internal.Constant where

authLength :: Int
authLength = 16

aeadLength :: Int -> Int
aeadLength payload = payload + authLength

keyLength :: Int
keyLength = 32

timestampLength :: Int
timestampLength = 12

mac1Length :: Int
mac1Length = 16

mac2Length :: Int
mac2Length = 16

maxQueuedUdpPackets :: Int
maxQueuedUdpPackets = 4096

maxQueuedTunPackets :: Int
maxQueuedTunPackets = 4096

udpReadBufferLength :: Int
udpReadBufferLength = 4096

tunReadBufferLength :: Int
tunReadBufferLength = 4096

retryMaxWaitTime :: Int
retryMaxWaitTime = 5 * 1000000 -- 5 seconds

handshakeRetryTime :: Int
handshakeRetryTime = 5

handshakeStopTime :: Int
handshakeStopTime = 90

sessionRenewTime :: Int
sessionRenewTime = 120

sessionExpireTime :: Int
sessionExpireTime = 180

sessionKeepaliveTime :: Int
sessionKeepaliveTime = 10

maxActiveSessions :: Int
maxActiveSessions = 2

heartbeatWaitTime :: Int
heartbeatWaitTime = 250 * 1000 -- 0.25 second
