module AES
  ( Key,
    Block,
    CryptPrim (..),
    cipher,
    invCipher,
    eqInvCipher,
    cipherDebug,
    invCipherDebug,
    eqInvCipherDebug,
  )
where

-- TODO do I really need shift, shiftL, AND shiftR
import Data.Bits (shift, shiftR, shiftL, testBit, xor)
import Data.List (transpose, unfoldr)
import Data.Word (Word64, Word8)
import Text.Printf (printf)
import Data.Maybe (mapMaybe)

---- AES Magic Constants -------------------------------------------------------

subBox :: [Word8]
subBox = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  ] :: [Word8]

invSubBox :: [Word8]
invSubBox = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xC2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xD9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xEd, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xBc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xAd, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xD2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xB5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  ] :: [Word8]

rcon :: [KeyWord]
rcon =
  [ KeyWord 0x01 0x00 0x00 0x00,
    KeyWord 0x02 0x00 0x00 0x00,
    KeyWord 0x04 0x00 0x00 0x00,
    KeyWord 0x08 0x00 0x00 0x00,
    KeyWord 0x10 0x00 0x00 0x00,
    KeyWord 0x20 0x00 0x00 0x00,
    KeyWord 0x40 0x00 0x00 0x00,
    KeyWord 0x80 0x00 0x00 0x00,
    KeyWord 0x1b 0x00 0x00 0x00,
    KeyWord 0x36 0x00 0x00 0x00
  ]

---- Key data type, Block data type and supporting functions -------------------

-- TODO some of the stuff in here should probs be renamed
class (Eq a, Show a) => CryptPrim a where
  makeBytes :: a -> [Word8]
  make :: [Word8] -> Maybe a

data KeyWord = KeyWord Word8 Word8 Word8 Word8 deriving (Eq)

instance CryptPrim KeyWord where
  makeBytes (KeyWord a b c d) = [a, b, c, d]
  make [w0, w1, w2, w3] = Just $ KeyWord w0 w1 w2 w3
  make _ = Nothing

instance Show KeyWord where
  show (KeyWord w0 w1 w2 w3) = printf "%02x%02x%02x%02x" w0 w1 w2 w3

makeKeyWords :: Key -> [KeyWord]
makeKeyWords = mapMaybe make . groupsOf 4 . makeBytes

data Key
  = Key128 Word64 Word64
  | Key192 Word64 Word64 Word64
  | Key256 Word64 Word64 Word64 Word64
  deriving (Eq)

instance Show Key where
  show (Key128 w0 w1) = printf "%016x%016x" w0 w1
  show (Key192 w0 w1 w2) = printf "%016x%016x%016x" w0 w1 w2
  show (Key256 w0 w1 w2 w3) = printf "%016x%016x%016x%016x" w0 w1 w2 w3

instance CryptPrim Key where
  makeBytes key = concatMap unPkW64 keyBytes
    where
      keyBytes = case key of
        Key128 w0 w1 -> [w0, w1]
        Key192 w0 w1 w2 -> [w0, w1, w2]
        Key256 w0 w1 w2 w3 -> [w0, w1, w2, w3]
      unPkW64 :: Word64 -> [Word8]
      unPkW64 x = [fromIntegral $ shiftR x b | b <- [56, 48 .. 0]]

  make l
    | length l == 16 = Just $ Key128 (head ls) (ls !! 1)
    | length l == 24 = Just $ Key192 (head ls) (ls !! 1) (ls !! 2)
    | length l == 32 = Just $ Key256 (head ls) (ls !! 1) (ls !! 2) (ls !! 3)
    | otherwise = Nothing
    where
      ls = map pkW64 $ groupsOf 8 l
      pkW64 :: [Word8] -> Word64
      pkW64 ws = sum $ zipWith shiftL (map fromIntegral ws) [56, 48 .. 0]

data Block = Block KeyWord KeyWord KeyWord KeyWord deriving (Eq)

instance Show Block where
  show (Block w0 w1 w2 w3) = concatMap show [w0, w1, w2, w3]

instance CryptPrim Block where
  makeBytes (Block w0 w1 w2 w3) = concatMap makeBytes [w0, w1, w2, w3]

  make [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] =
    Just $ Block
      (KeyWord w0 w1 w2 w3)
      (KeyWord w4 w5 w6 w7)
      (KeyWord w8 w9 w10 w11)
      (KeyWord w12 w13 w14 w15)
  make _ = Nothing

---- Galois Field functions ----------------------------------------------------

ffAdd :: Word8 -> Word8 -> Word8
ffAdd = xor

xtime :: Word8 -> Word8
xtime b
  | testBit b 7 = shifted
  | otherwise = ffAdd shifted 0x1b
  where
    shifted = shift b 1

ffMultiply :: Word8 -> Word8 -> Word8
ffMultiply b0 b1 = foldl (flip mulOne) 0 $ zip b0s bits
  where
    bits = map (testBit b1) [0 .. 7]
    b0s = iterate xtime b0
    mulOne (b0d, True) = ffAdd b0d
    mulOne (_, _) = id

---- AES subfunctions ----------------------------------------------------------

subByte :: Word8 -> Word8
subByte = (subBox !!) . fromIntegral

invSubByte :: Word8 -> Word8
invSubByte = (invSubBox !!) . fromIntegral

-- TODO should work on blocks instead of [word8]
mixColumnsGen :: [Word8] -> [Word8] -> [Word8]
mixColumnsGen offsets = concatMap mixCol . groupsOf 4
  where
    magicNums = take 4 $ iterate (shiftRow 3) offsets
    mixCol col = map (foldl ffAdd 0 . zipWith ffMultiply col) magicNums

-- TODO should work on blocks instead of [word8]
mixColumns :: [Word8] -> [Word8]
mixColumns = mixColumnsGen [0x2, 0x3, 0x1, 0x1]

-- TODO should work on blocks instead of [word8]
invMixColumns :: [Word8] -> [Word8]
invMixColumns = mixColumnsGen [0xe, 0xb, 0xd, 0x9]

-- TODO should work on KeyWords instead of [Word8]
shiftRow :: Int -> [Word8] -> [Word8]
shiftRow = drop <> take

-- TODO should work on KeyWords instead of [Word8]
shiftRowsGen :: [Int] -> [Word8] -> [Word8]
shiftRowsGen offsets state = concat . transpose $
  zipWith shiftRow offsets $ transpose $ groupsOf 4 state

-- TODO should work on KeyWords instead of [Word8]
shiftRows :: [Word8] -> [Word8]
shiftRows = shiftRowsGen [0, 1, 2, 3]

-- TODO should work on KeyWords instead of [Word8]
invShiftRows :: [Word8] -> [Word8]
invShiftRows = shiftRowsGen [0, 3, 2, 1]

---- Key expansion functions ---------------------------------------------------

subKeyWord :: KeyWord -> KeyWord
subKeyWord (KeyWord a b c d) = KeyWord (subByte a) (subByte b) (subByte c) (subByte d)

rotKeyWord :: KeyWord -> KeyWord
rotKeyWord (KeyWord a b c d) = KeyWord b c d a

ffAddKeyWord :: KeyWord -> KeyWord -> KeyWord
ffAddKeyWord (KeyWord a0 b0 c0 d0) (KeyWord a1 b1 c1 d1) =
  KeyWord (ffAdd a0 a1) (ffAdd b0 b1) (ffAdd c0 c1) (ffAdd d0 d1)

makeKeyBlock :: [KeyWord] -> Block
makeKeyBlock [w0, w1, w2, w3] = Block w0 w1 w2 w3
makeKeyBlock _ = undefined

keyExpansionNew :: Key -> [KeyWord]
keyExpansionNew key = keyExpansionRecNew (makeKeyWords key) nk
  where
    nk = case key of
      Key128 {} -> 4
      Key192 {} -> 6
      Key256 {} -> 8

keyExpansionRecNew :: [KeyWord] -> Int -> [KeyWord]
keyExpansionRecNew w nk
  | length w == 4 * nk + 28 = w
  | otherwise = keyExpansionRecNew (w ++ [newByte]) nk
  where
    lastKey = last w
    thisRcon = rcon !! ((d `div` nk) - 1)
    newByte
      | (d `mod` nk) == 0 = ffAddKeyWord (addFKey thisRcon) $ subKeyWord $ rotKeyWord lastKey
      | (nk > 6) && ((d `mod` nk) == 4) = addFKey (subKeyWord lastKey)
      | otherwise = addFKey lastKey
    addFKey = ffAddKeyWord $ w !! (d - nk)
    d = length w

keyExpansion :: Key -> [[Word8]]
keyExpansion = map makeBytes . keyExpansionNew

-- keyExpansion key = keyExpansionRec (groupsOf 4 $ makeBytes key) nk nk
  -- where
    -- nk = case key of
      -- Key128 {} -> 4
      -- Key192 {} -> 6
      -- Key256 {} -> 8

-- keyExpansionRec :: [[Word8]] -> Int -> Int -> [[Word8]]
-- keyExpansionRec key 4 44 = key
-- keyExpansionRec key 6 52 = key
-- keyExpansionRec key 8 60 = key
-- keyExpansionRec w nk depth = keyExpansionRec (w ++ [newByte]) nk (depth + 1)
--   where
--     firstKey = w !! (depth - nk)
--     lastKey = w !! (depth - 1)
--     thisRcon = rcon !! ((depth `div` nk) - 1)
--     newByte
--       | (depth `mod` nk) == 0 = foldl (zipWith ffAdd) (map subByte $ rotWord lastKey) [thisRcon, firstKey]
--       | (nk > 6) && ((depth `mod` nk) == 4) = zipWith ffAdd (map subByte lastKey) firstKey
--       | otherwise = zipWith ffAdd lastKey firstKey

-- keyExpansionEICNew :: Key -> [KeyWord]
-- keyExpansionEICNew key = f: m ++ [e]
--   where
--     fme = keyExpansionNew key
--     f = head fme
--     e = last fme
--     m = map (makeOneKeyWord . invMixColumns . makeBytes) $ init $ tail fme

keyExpansionEIC :: Key -> [[Word8]]
-- keyExpansionEIC = map makeBytes . keyExpansionEICNew
keyExpansionEIC key = f ++ map invMixColumns m ++ e
  where
    fme = keyExpansion key
    (f, me) = splitAt 4 fme
    (m, e) = splitAt (length me - 4) me

addRoundKey :: [Word8] -> [[Word8]] -> Int -> [Word8]
addRoundKey state key roundNum = zipWith ffAdd state roundKey
  where
    -- roundKey = drop (roundNum * 16) (concat key)
    roundKey = getRoundKey key !! roundNum

-- addRoundKeyNew :: [Word8] -> [Block] -> Int -> [Word8]
-- addRoundKeyNew state key roundNum = zipWith ffAdd state roundKey
--   where
--     -- roundKey = drop (roundNum * 16) (concat key)
--     roundKey = makeBytes $ key !! roundNum


---- AES cipher ----------------------------------------------------------------

makeRoundKeys :: [Word8] -> [[Word8]] -> [[Word8]]
makeRoundKeys state key = map (zipWith ffAdd state) a
  where
    roundKey roundNum = drop (roundNum * 16) (concat key)
    a = map roundKey [0..]

-- cipher :: Key -> Block -> [Word8]
-- cipher key blk = foldl (cipherNotRec expKey) roundKey [0 .. ni]
--   where
--     expKey = keyExpansion key
--     roundKey = addRoundKey (makeBytes blk) expKey 0
--     ni = case key of
--       Key128 {} -> 9
--       Key192 {} -> 11
--       Key256 {} -> 13
--
-- cipherNotRec :: [[Word8]] -> [Word8] -> Int -> [Word8]
-- cipherNotRec key state depth
--   | ((length key `div` 4) - 2) == depth = addRoundKey s_row key (depth + 1)
--   | otherwise = addRoundKey m_col key (depth + 1)
--   where
--     s_box = map subByte state
--     s_row = shiftRows s_box
--     m_col = mixColumns s_row

getRoundKey :: [[Word8]] -> [[Word8]]
getRoundKey key = map (flip drop $ concat key) [0, 16 ..]

cipher :: Key -> Block -> [Word8]
cipher key blk = lst
  where
    state = foldl (cipherNotRec expKey) roundKey [0 .. ni]
    expKey = keyExpansion key
    roundKey = addRoundKey (makeBytes blk) expKey 0
    ni = case key of
      Key128 {} -> 8
      Key192 {} -> 10
      Key256 {} -> 12

    s_box = map subByte state
    s_row = shiftRows s_box
    lst = addRoundKey s_row expKey (ni + 2)

cipherNotRec :: [[Word8]] -> [Word8] -> Int -> [Word8]
cipherNotRec key state depth = addRoundKey m_col key (depth + 1)
  where
    s_box = map subByte state
    s_row = shiftRows s_box
    m_col = mixColumns s_row

cipherOld :: Key -> Block -> [Word8]
cipherOld key blk = cipherRec roundKey expKey 0
  where
    expKey = keyExpansion key
    roundKey = addRoundKey (makeBytes blk) expKey 0

cipherRec :: [Word8] -> [[Word8]] -> Int -> [Word8]
cipherRec state key depth
  | ((length key `div` 4) - 2) == depth = addRoundKey s_row key (depth + 1)
  | otherwise = cipherRec (addRoundKey m_col key (depth + 1)) key (depth + 1)
  where
    s_box = map subByte state
    s_row = shiftRows s_box
    m_col = mixColumns s_row

---- AES debug cipher ----------------------------------------------------------

cipherDebug :: Key -> Block -> String
cipherDebug key blk =
  "round[ 0].input     " ++ showBytes plainText ++ "\n" ++
  "round[ 0].k_sch     " ++ showBytes (head (groupsOf 16 (concat expKey))) ++ "\n" ++
  snd recOutput
  where
    expKey = keyExpansion key
    recOutput = cipherDebugRec (addRoundKey plainText expKey 0) expKey 0
    plainText = makeBytes blk

cipherDebugRec :: [Word8] -> [[Word8]] -> Int -> ([Word8], String)
cipherDebugRec state key depth
  | ((length key `div` 4) - 2) == depth = (cipherText, buildStr)
  | otherwise = addDebugStr recCipherTuple buildStr
  where
    s_box = map subByte state
    s_row = shiftRows s_box
    m_col = mixColumns s_row
    buildStr =
      printf "round[%2d].start     " newDepth ++ showBytes state ++ "\n" ++
      printf "round[%2d].s_box     " newDepth ++ showBytes s_box ++ "\n" ++
      printf "round[%2d].s_row     " newDepth ++ showBytes s_row ++ "\n" ++
      condStr
    condStr
      | ((length key `div` 4) - 2) == depth =
          printf "round[%2d].k_sch     " newDepth ++ showBytes (groupsOf 16 (concat key) !! newDepth) ++ "\n" ++
          printf "round[%2d].output    " newDepth ++ showBytes cipherText
      | otherwise =
          printf "round[%2d].m_col     " newDepth ++ showBytes m_col ++ "\n" ++
          printf "round[%2d].k_sch     " newDepth ++ showBytes (groupsOf 16 (concat key) !! newDepth) ++ "\n"
    recCipherTuple = cipherDebugRec (addRoundKey m_col key newDepth) key newDepth
    cipherText = addRoundKey s_row key ((length key `div` 4) - 1)
    newDepth = depth + 1

---- AES inverse cipher --------------------------------------------------------

invCipher :: Key -> Block -> [Word8]
invCipher key blk = invCipherRec roundKey expKey 0
  where
    expKey = keyExpansion key
    roundKey = addRoundKey (makeBytes blk) expKey ((length expKey `div` 4) - 1)

invCipherRec :: [Word8] -> [[Word8]] -> Int -> [Word8]
invCipherRec state key depth
  | ((length key `div` 4) - 2) == depth = addRoundKey is_box key 0
  | otherwise = invCipherRec (invMixColumns (addRoundKey is_box key invRoundNum)) key (depth + 1)
  where
    is_row = invShiftRows state
    is_box = map invSubByte is_row
    invRoundNum = ((length key `div` 4) - 2) - depth

---- AES inverse debug cipher --------------------------------------------------

invCipherDebug :: Key -> Block -> String
invCipherDebug key blk =
  "round[ 0].iinput    " ++ showBytes cipherText ++ "\n" ++
  "round[ 0].ik_sch    " ++ showBytes (groupsOf 16 (concat expKey) !! invRoundNum) ++ "\n" ++
  snd recOutput
  where
    expKey = keyExpansion key
    recOutput = invCipherDebugRec (addRoundKey cipherText expKey invRoundNum) expKey 0
    cipherText = makeBytes blk
    invRoundNum = (length expKey `div` 4) - 1

invCipherDebugRec :: [Word8] -> [[Word8]] -> Int -> ([Word8], String)
invCipherDebugRec state key depth
  | invRoundNum == 0 = (plainText, buildStr)
  | otherwise = addDebugStr recInvCipherTuple buildStr
  where
    is_row = invShiftRows state
    is_box = map invSubByte is_row
    ik_add = addRoundKey is_box key invRoundNum
    buildStr =
      printf "round[%2d].istart    " newDepth ++ showBytes state ++ "\n" ++
      printf "round[%2d].is_row    " newDepth ++ showBytes is_row ++ "\n" ++
      printf "round[%2d].is_box    " newDepth ++ showBytes is_box ++ "\n" ++
      printf "round[%2d].ik_sch    " newDepth ++ showBytes (groupsOf 16 (concat key) !! invRoundNum) ++ "\n" ++
      condStr
    condStr
      | invRoundNum == 0 = printf "round[%2d].ioutput   " newDepth ++ showBytes plainText
      | otherwise = printf "round[%2d].ik_add    " newDepth ++ showBytes ik_add ++ "\n"
    recInvCipherTuple = invCipherDebugRec (invMixColumns ik_add) key newDepth
    plainText = addRoundKey is_box key 0
    invRoundNum = (length key `div` 4) - 2 - depth
    newDepth = depth + 1

---- AES equivalent inverse cipher ---------------------------------------------

eqInvCipher :: Key -> Block -> [Word8]
eqInvCipher key blk = eqInvCipherRec roundKey expKey 0
  where
    expKey = keyExpansionEIC key
    roundKey = addRoundKey (makeBytes blk) expKey ((length expKey `div` 4) - 1)

eqInvCipherRec :: [Word8] -> [[Word8]] -> Int -> [Word8]
eqInvCipherRec state key depth
  | ((length key `div` 4) - 2) == depth = addRoundKey is_row key 0
  | otherwise = eqInvCipherRec (addRoundKey is_col key invRoundNum) key (depth + 1)
  where
    is_box = map invSubByte state
    is_row = invShiftRows is_box
    is_col = invMixColumns is_row
    invRoundNum = (length key `div` 4) - 2 - depth

---- AES equivalent inverse debug cipher ---------------------------------------

eqInvCipherDebug :: Key -> Block -> String
eqInvCipherDebug key blk =
  "round[ 0].iinput    " ++ showBytes cipherText ++ "\n" ++
  "round[ 0].ik_sch    " ++ showBytes (groupsOf 16 (concat expKey) !! invRoundNum) ++ "\n" ++
  snd recOutput
  where
    expKey = keyExpansionEIC key
    recOutput = eqInvCipherDebugRec (addRoundKey cipherText expKey invRoundNum) expKey 0
    cipherText = makeBytes blk
    invRoundNum = (length expKey `div` 4) - 1

eqInvCipherDebugRec :: [Word8] -> [[Word8]] -> Int -> ([Word8], String)
eqInvCipherDebugRec state key depth
  | invRoundNum == 0 = (plainText, buildStr)
  | otherwise = addDebugStr recEqInvCipherTuple buildStr
  where
    is_box = map invSubByte state
    is_row = invShiftRows is_box
    im_col = invMixColumns is_row
    buildStr =
      printf "round[%2d].istart    " newDepth ++ showBytes state ++ "\n" ++
      printf "round[%2d].is_box    " newDepth ++ showBytes is_box ++ "\n" ++
      printf "round[%2d].is_row    " newDepth ++ showBytes is_row ++ "\n" ++
      condStr
    condStr
      | invRoundNum == 0 =
          printf "round[%2d].ik_sch    " newDepth ++ showBytes (groupsOf 16 (concat key) !! invRoundNum) ++ "\n" ++
          printf "round[%2d].ioutput   " newDepth ++ showBytes plainText
      | otherwise =
          printf "round[%2d].im_col    " newDepth ++ showBytes im_col ++ "\n" ++
          printf "round[%2d].ik_sch    " newDepth ++ showBytes (groupsOf 16 (concat key) !! invRoundNum) ++ "\n"
    recEqInvCipherTuple = eqInvCipherDebugRec (addRoundKey im_col key invRoundNum) key newDepth
    plainText = addRoundKey is_row key 0
    invRoundNum = (length key `div` 4) - 2 - depth
    newDepth = depth + 1

---- Helper functions ----------------------------------------------------------


groupsOf :: Int -> [a] -> [[a]]
groupsOf n = takeWhile (not . null) . unfoldr (Just . splitAt n)

addDebugStr :: (a, String) -> String -> (a, String)
addDebugStr (state, recDebug) newDebug = (state, newDebug ++ recDebug)

showBytes :: [Word8] -> String
showBytes = concatMap (printf "%02x")
