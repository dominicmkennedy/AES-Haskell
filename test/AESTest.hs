-- test all debug ciphers and inverciphers,
-- maybe print the debug output to a file// buffer
-- and just campare with hardcoded strings to ensure that it's correct
-- test key creation functions
module Main where

import AES
import Data.Word
import Test.Hspec

-- TODO tests for
-- cipherDebug, 
-- invCipherDebug, 
-- eqInvCipherDebug
--
-- Done tests
-- cipher, 
-- invCipher, 
-- eqInvCipher, 

-- TODO consider moving these constants to another file
plainText     :: [Word8]
key128        :: [Word8]
key192        :: [Word8]
key256        :: [Word8]
cipherText128 :: [Word8]
cipherText192 :: [Word8]
cipherText256 :: [Word8]
plainText     = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff] :: [Word8]
key128        = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f] :: [Word8]
key192        = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17] :: [Word8]
key256        = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f] :: [Word8]
cipherText128 = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a] :: [Word8]
cipherText192 = [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91] :: [Word8]
cipherText256 = [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89] :: [Word8]

eqInvCipherSpec :: Spec
eqInvCipherSpec = describe "eqInvCipher" $ do 
  it "Decrypts cipher text with a 128 bit key using the equivalent inverse cipher" $
    eqInvCipher cipherText128 (keyExpansionEIC key128) `shouldBe` plainText
  it "Decrypts cipher text with a 192 bit key using the equivalent inverse cipher" $
    eqInvCipher cipherText192 (keyExpansionEIC key192) `shouldBe` plainText
  it "Decrypts cipher text with a 256 bit key using the equivalent inverse cipher" $
    eqInvCipher cipherText256 (keyExpansionEIC key256) `shouldBe` plainText

invCipherSpec :: Spec
invCipherSpec = describe "invCipher" $ do
  it "Decrypts cipher text with a 128 bit key" $
    invCipher cipherText128 (keyExpansion key128) `shouldBe` plainText
  it "Decrypts cipher text with a 192 bit key" $
    invCipher cipherText192 (keyExpansion key192) `shouldBe` plainText
  it "Decrypts cipher text with a 256 bit key" $
    invCipher cipherText256 (keyExpansion key256) `shouldBe` plainText

cipherSpec :: Spec
cipherSpec = describe "cipher" $ do
  it "Encrypts plain text with a 128 bit key" $
    cipher plainText (keyExpansion key128) `shouldBe` cipherText128
  it "Encrypts plain text with a 192 bit key" $
    cipher plainText (keyExpansion key192) `shouldBe` cipherText192
  it "Encrypts plain text with a 256 bit key" $
    cipher plainText (keyExpansion key256) `shouldBe` cipherText256

main :: IO ()
main = hspec $ do 
  cipherSpec
  invCipherSpec
  eqInvCipherSpec
