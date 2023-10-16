module Types where

import Data.Word (Word8)
import Text.Printf (printf)

type Byte = Word8

data Row = Row Byte Byte Byte Byte deriving (Eq)

data Block = Block Row Row Row Row deriving (Eq)

getRow :: Block -> (Row, Row, Row, Row)
getRow = undefined

getCol :: Block -> (Row, Row, Row, Row)
getCol = undefined

class (Eq a, Show a) => CryptPrim a where
  makeBytes :: a -> [Byte]
  make :: [Byte] -> Maybe a

instance CryptPrim Row where
  makeBytes (Row a b c d) = [a, b, c, d]
  make [w0, w1, w2, w3] = Just $ Row w0 w1 w2 w3
  make _ = Nothing

instance Show Row where
  show (Row w0 w1 w2 w3) = printf "%02x%02x%02x%02x" w0 w1 w2 w3

instance Show Block where
  show (Block w0 w1 w2 w3) = concatMap show [w0, w1, w2, w3]

instance CryptPrim Block where
  makeBytes (Block w0 w1 w2 w3) = concatMap makeBytes [w0, w1, w2, w3]

  make [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] =
    Just $
      Block
        (Row w0 w1 w2 w3)
        (Row w4 w5 w6 w7)
        (Row w8 w9 w10 w11)
        (Row w12 w13 w14 w15)
  make _ = Nothing

data Key
  = Key128 Row Row Row Row
  | Key192 Row Row Row Row Row Row
  | Key256 Row Row Row Row Row Row Row Row
  deriving (Eq)

instance Show Key where
  show (Key128 w0 w1 w2 w3) = concatMap show [w0, w1, w2, w3]
  show (Key192 w0 w1 w2 w3 w4 w5) = concatMap show [w0, w1, w2, w3, w4, w5]
  show (Key256 w0 w1 w2 w3 w4 w5 w6 w7) = concatMap show [w0, w1, w2, w3, w4, w5, w6, w7]

instance CryptPrim Key where
  makeBytes key = case key of
    Key128 w0 w1 w2 w3 -> concatMap makeBytes [w0, w1, w2, w3]
    Key192 w0 w1 w2 w3 w4 w5 -> concatMap makeBytes [w0, w1, w2, w3, w4, w5]
    Key256 w0 w1 w2 w3 w4 w5 w6 w7 -> concatMap makeBytes [w0, w1, w2, w3, w4, w5, w6, w7]

  make [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] =
    Just $
      Key128
        (Row w0 w1 w2 w3)
        (Row w4 w5 w6 w7)
        (Row w8 w9 w10 w11)
        (Row w12 w13 w14 w15)
  make
    [ w0,
      w1,
      w2,
      w3,
      w4,
      w5,
      w6,
      w7,
      w8,
      w9,
      w10,
      w11,
      w12,
      w13,
      w14,
      w15,
      w16,
      w17,
      w18,
      w19,
      w20,
      w21,
      w22,
      w23
      ] =
      Just $
        Key192
          (Row w0 w1 w2 w3)
          (Row w4 w5 w6 w7)
          (Row w8 w9 w10 w11)
          (Row w12 w13 w14 w15)
          (Row w16 w17 w18 w19)
          (Row w20 w21 w22 w23)
  make
    [ w0,
      w1,
      w2,
      w3,
      w4,
      w5,
      w6,
      w7,
      w8,
      w9,
      w10,
      w11,
      w12,
      w13,
      w14,
      w15,
      w16,
      w17,
      w18,
      w19,
      w20,
      w21,
      w22,
      w23,
      w24,
      w25,
      w26,
      w27,
      w28,
      w29,
      w30,
      w31
      ] =
      Just $
        Key256
          (Row w0 w1 w2 w3)
          (Row w4 w5 w6 w7)
          (Row w8 w9 w10 w11)
          (Row w12 w13 w14 w15)
          (Row w16 w17 w18 w19)
          (Row w20 w21 w22 w23)
          (Row w24 w25 w26 w27)
          (Row w28 w29 w30 w31)
  make _ = Nothing
