{-# LANGUAGE ScopedTypeVariables #-}
-- |
-- Module      : Crypto.Hash.SHA1
-- License     : BSD-style
-- Maintainer  : Herbert Valerio Riedel <hvr@gnu.org>
-- Stability   : stable
-- Portability : unknown
--
-- A module containing <https://en.wikipedia.org/wiki/SHA-1 SHA-1> bindings
--
module Crypto.Hash.SHA1
    (

    -- * Incremental API
    --
    -- | This API is based on 4 different functions, similar to the
    -- lowlevel operations of a typical hash:
    --
    --  - 'init': create a new hash context
    --  - 'update': update non-destructively a new hash context with a strict bytestring
    --  - 'updates': same as update, except that it takes a list of strict bytestrings
    --  - 'finalize': finalize the context and returns a digest bytestring.
    --
    -- all those operations are completely pure, and instead of
    -- changing the context as usual in others language, it
    -- re-allocates a new context each time.
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.SHA1 as SHA1
    -- >
    -- > main = print digest
    -- >   where
    -- >     digest = SHA1.finalize ctx
    -- >     ctx    = foldl SHA1.update ctx0 (map Data.ByteString.pack [ [1,2,3], [4,5,6] ])
    -- >     ctx0   = SHA1.init

      Ctx
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , updates  -- :: Ctx -> [ByteString] -> Ctx
    , finalize -- :: Ctx -> ByteString
    , start    -- :: ByteString -> Ctx
    , startlazy -- :: L.ByteString -> Ctx

    -- * Single Pass API
    --
    -- | This API use the incremental API under the hood to provide
    -- the common all-in-one operations to create digests out of a
    -- 'ByteString' and lazy 'L.ByteString'.
    --
    --  - 'hash': create a digest ('init' + 'update' + 'finalize') from a strict 'ByteString'
    --  - 'hashlazy': create a digest ('init' + 'update' + 'finalize') from a lazy 'L.ByteString'
    --
    -- Example:
    --
    -- > import qualified Data.ByteString
    -- > import qualified Crypto.Hash.SHA1 as SHA1
    -- >
    -- > main = print $ SHA1.hash (Data.ByteString.pack [0..255])
    --
    -- __NOTE__: The returned digest is a binary 'ByteString'. For
    -- converting to a base16/hex encoded digest the
    -- <https://hackage.haskell.org/package/base16-bytestring base16-bytestring>
    -- package is recommended.

    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: L.ByteString -> ByteString

    -- ** HMAC-SHA1
    --
    -- | <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
    -- <https://en.wikipedia.org/wiki/HMAC HMAC>-SHA1 digests

    , hmac     -- :: ByteString -> ByteString -> ByteString
    , hmaclazy -- :: ByteString -> L.ByteString -> ByteString
    ) where

import Prelude hiding (init)
import Control.Monad
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.Bits (xor)
import Data.Word

import Java

-- | perform IO for hashes that do allocation and ffi.
-- unsafeDupablePerformIO is used when possible as the
-- computation is pure and the output is directly linked
-- to the input. we also do not modify anything after it has
-- been returned to the user.
-- unsafeDoIO :: IO a -> a
-- unsafeDoIO = unsafeDupablePerformIO

-- | SHA-1 Context
--
-- The context data is exactly 92 bytes long, however
-- the data in the context is stored in host-endianness.
--
-- The context data is made up of
--
--  * a 'Word64' representing the number of bytes already feed to hash algorithm so far,
--
--  * a 64-element 'Word8' buffer holding partial input-chunks, and finally
--
--  * a 5-element 'Word32' array holding the current work-in-progress digest-value.
--
-- Consequently, a SHA-1 digest as produced by 'hash', 'hashlazy', or 'finalize' is 20 bytes long.
data MessageDigest = MessageDigest @java.security.MessageDigest
  deriving (Eq, Class)

type Ctx = MessageDigest

foreign import java unsafe "@static MessageDigest.getInstance" messageDigestGetInstance :: String -> Java a MessageDigest

foreign import java unsafe "@interface clone" cloneMessageDigest :: Java MessageDigest MessageDigest
foreign import java unsafe "@interface update" updateMessageDigest :: JByteArray -> Java MessageDigest ()
foreign import java unsafe "@interface getDigestLength" getDigestLength :: Java MessageDigest Int
foreign import java unsafe "@interface digest" digestMessageDigest :: Java MessageDigest JByteArray

init :: Ctx
init = unsafePerformJava $ messageDigestGetInstance "SHA-1"

primitiveUpdate :: Ctx -> ByteString -> Java a ()
primitiveUpdate ctx bytes = do
  byteArray :: JByteArray <- anew (B.length bytes)

  forM_ [0..(B.length bytes) - 1] (copyWord8ToByte bytes byteArray)

  ctx <.> updateMessageDigest byteArray

  pure ()
  where
    copyWord8ToByte :: ByteString -> JByteArray -> Int -> Java b ()
    copyWord8ToByte bytestr byteArray idx = do
       let
         theByteWord8 = B.index bytestr idx
         theByte :: Byte = fromIntegral theByteWord8

       byteArray <.> aset idx theByte

update :: Ctx -> ByteString -> Ctx
update ctx bytes = unsafePerformJava $ do
  newCtx <- ctx <.> cloneMessageDigest
  primitiveUpdate newCtx bytes
  pure $ newCtx

updates :: Ctx -> [ByteString] -> Ctx
updates ctx updatelist = unsafePerformJava $ do
  newCtx <- ctx <.> cloneMessageDigest
  runUpdates newCtx updatelist
  pure $ newCtx
  where
    runUpdates :: Ctx -> [ByteString] -> Java a ()
    runUpdates _ [] = pure ()
    runUpdates ctx' (h : hs) = do
      primitiveUpdate ctx' h
      runUpdates ctx' hs

finalize :: Ctx -> ByteString
finalize ctx = unsafePerformJava $ do
  len <- ctx <.> getDigestLength
  byteArray :: JByteArray <- ctx <.> digestMessageDigest
  digestBytes :: [Word8] <-
    mapM
      (\idx -> do
          theByte :: Byte <- byteArray <.> aget idx
          pure $ (fromIntegral . toInteger) theByte
      )
      [0 .. len - 1]
  pure $ B.pack digestBytes

start :: ByteString -> Ctx
start bs = update init bs

startlazy :: L.ByteString -> Ctx
startlazy lbs = start $ (B.pack . L.unpack) lbs

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring (20 bytes)
hash :: ByteString -> ByteString
hash d = finalize $ start d

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring (20 bytes)
hashlazy :: L.ByteString -> ByteString
hashlazy l = finalize $ startlazy l

{-# NOINLINE hmac #-}
-- | Compute 20-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-SHA1 digest for a strict bytestring message
--
-- @since 0.11.100.0
hmac :: ByteString -- ^ secret
     -> ByteString -- ^ message
     -> ByteString
hmac secret msg = hash $ B.append opad (hash $ B.append ipad msg)
  where
    opad = B.map (xor 0x5c) k'
    ipad = B.map (xor 0x36) k'

    k'  = B.append kt pad
    kt  = if B.length secret > 64 then hash secret else secret
    pad = B.replicate (64 - B.length kt) 0


{-# NOINLINE hmaclazy #-}
-- | Compute 20-byte <https://tools.ietf.org/html/rfc2104 RFC2104>-compatible
-- HMAC-SHA1 digest for a lazy bytestring message
--
-- @since 0.11.100.0
hmaclazy :: ByteString   -- ^ secret
         -> L.ByteString -- ^ message
         -> ByteString
hmaclazy secret msg = hash $ B.append opad (hashlazy $ L.append ipad msg)
  where
    opad = B.map (xor 0x5c) k'
    ipad = L.fromChunks [B.map (xor 0x36) k']

    k'  = B.append kt pad
    kt  = if B.length secret > 64 then hash secret else secret
    pad = B.replicate (64 - B.length kt) 0
