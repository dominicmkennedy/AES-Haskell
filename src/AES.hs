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

import Constants
import Data.Bits (shift, testBit, xor)
import Data.List (transpose, unfoldr)
import Text.Printf (printf)
import Types

---- Galois Field functions ----------------------------------------------------

ffAdd :: Byte -> Byte -> Byte
ffAdd = xor

xtime :: Byte -> Byte
xtime b
  | testBit b 7 = shifted
  | otherwise = ffAdd shifted 0x1b
  where
    shifted = shift b 1

ffMultiply :: Byte -> Byte -> Byte
ffMultiply b0 b1 = foldl (flip mulOne) 0 $ zip b0s bits
  where
    bits = map (testBit b1) [0 .. 7]
    b0s = iterate xtime b0
    mulOne (b0d, True) = ffAdd b0d
    mulOne (_, _) = id

---- AES subfunctions ----------------------------------------------------------

subByte :: Byte -> Byte
subByte = (subBox !!) . fromIntegral

invSubByte :: Byte -> Byte
invSubByte = (invSubBox !!) . fromIntegral

-- TODO should work on blocks instead of [Byte]
mixColumnsGen :: [Byte] -> [Byte] -> [Byte]
mixColumnsGen offsets = concatMap mixCol . groupsOf 4
  where
    magicNums = take 4 $ iterate (shiftRow 3) offsets
    mixCol col = map (foldl ffAdd 0 . zipWith ffMultiply col) magicNums

-- TODO should work on blocks instead of [Byte]
mixColumns :: [Byte] -> [Byte]
mixColumns = mixColumnsGen [0x2, 0x3, 0x1, 0x1]

-- TODO should work on blocks instead of [Byte]
invMixColumns :: [Byte] -> [Byte]
invMixColumns = mixColumnsGen [0xe, 0xb, 0xd, 0x9]

-- TODO should work on KeyWords instead of [Byte]
shiftRow :: Int -> [Byte] -> [Byte]
shiftRow = drop <> take

-- TODO should work on KeyWords instead of [Byte]
shiftRowsGen :: [Int] -> [Byte] -> [Byte]
shiftRowsGen offsets state =
  concat . transpose $
    zipWith shiftRow offsets $
      transpose $
        groupsOf 4 state

-- TODO should work on KeyWords instead of [Byte]
shiftRows :: [Byte] -> [Byte]
shiftRows = shiftRowsGen [0, 1, 2, 3]

-- TODO should work on KeyWords instead of [Byte]
invShiftRows :: [Byte] -> [Byte]
invShiftRows = shiftRowsGen [0, 3, 2, 1]

---- Key expansion functions ---------------------------------------------------

subRow :: Row -> Row
subRow (Row a b c d) = Row (subByte a) (subByte b) (subByte c) (subByte d)

rotRow :: Row -> Row
rotRow (Row a b c d) = Row b c d a

ffAddRow :: Row -> Row -> Row
ffAddRow (Row a0 b0 c0 d0) (Row a1 b1 c1 d1) =
  Row (ffAdd a0 a1) (ffAdd b0 b1) (ffAdd c0 c1) (ffAdd d0 d1)

keyExpansionNew :: Key -> [Row]
keyExpansionNew key = keyExpansionRecNew rows $ length rows
  where
    rows = case key of
      Key128 w0 w1 w2 w3 -> [w0, w1, w2, w3]
      Key192 w0 w1 w2 w3 w4 w5 -> [w0, w1, w2, w3, w4, w5]
      Key256 w0 w1 w2 w3 w4 w5 w6 w7 -> [w0, w1, w2, w3, w4, w5, w6, w7]

keyExpansionRecNew :: [Row] -> Int -> [Row]
keyExpansionRecNew w nk
  | length w == 4 * nk + 28 = w
  | otherwise = keyExpansionRecNew (w ++ [newByte]) nk
  where
    lastKey = last w
    thisRcon = rcon !! ((d `div` nk) - 1)
    newByte
      | (d `mod` nk) == 0 = ffAddRow (addFKey thisRcon) $ subRow $ rotRow lastKey
      | (nk > 6) && ((d `mod` nk) == 4) = addFKey (subRow lastKey)
      | otherwise = addFKey lastKey
    addFKey = ffAddRow $ w !! (d - nk)
    d = length w

keyExpansion :: Key -> [[Byte]]
keyExpansion = map makeBytes . keyExpansionNew

-- keyExpansionEICNew :: Key -> [KeyWord]
-- keyExpansionEICNew key = f: m ++ [e]
--   where
--     fme = keyExpansionNew key
--     f = head fme
--     e = last fme
--     m = map (makeOneKeyWord . invMixColumns . makeBytes) $ init $ tail fme

keyExpansionEIC :: Key -> [[Byte]]
-- keyExpansionEIC = map makeBytes . keyExpansionEICNew
keyExpansionEIC key = f ++ map invMixColumns m ++ e
  where
    fme = keyExpansion key
    (f, me) = splitAt 4 fme
    (m, e) = splitAt (length me - 4) me

addRoundKey :: [Byte] -> [[Byte]] -> Int -> [Byte]
addRoundKey state key roundNum = zipWith ffAdd state roundKey
  where
    -- roundKey = drop (roundNum * 16) (concat key)
    roundKey = getRoundKey key !! roundNum

-- addRoundKeyNew :: [Byte] -> [Block] -> Int -> [Byte]
-- addRoundKeyNew state key roundNum = zipWith ffAdd state roundKey
--   where
--     -- roundKey = drop (roundNum * 16) (concat key)
--     roundKey = makeBytes $ key !! roundNum

---- AES cipher ----------------------------------------------------------------

getRoundKey :: [[Byte]] -> [[Byte]]
getRoundKey key = map (flip drop $ concat key) [0, 16 ..]

cipher :: Key -> Block -> [Byte]
cipher key blk = lst
  where
    state = foldl (cipherWorker expKey) roundKey [0 .. ni]
    expKey = keyExpansion key
    roundKey = addRoundKey (makeBytes blk) expKey 0
    s_box = map subByte state
    s_row = shiftRows s_box
    lst = addRoundKey s_row expKey (ni + 2)
    ni = case key of
      Key128 {} -> 8
      Key192 {} -> 10
      Key256 {} -> 12

cipherWorker :: [[Byte]] -> [Byte] -> Int -> [Byte]
cipherWorker key state depth = addRoundKey m_col key (depth + 1)
  where
    s_box = map subByte state
    s_row = shiftRows s_box
    m_col = mixColumns s_row

---- AES debug cipher ----------------------------------------------------------

cipherDebug :: Key -> Block -> String
cipherDebug key blk =
  "round[ 0].input     "
    ++ showBytes plainText
    ++ "\n"
    ++ "round[ 0].k_sch     "
    ++ showBytes (head (groupsOf 16 (concat expKey)))
    ++ "\n"
    ++ snd recOutput
  where
    expKey = keyExpansion key
    recOutput = cipherDebugRec (addRoundKey plainText expKey 0) expKey 0
    plainText = makeBytes blk

cipherDebugRec :: [Byte] -> [[Byte]] -> Int -> ([Byte], String)
cipherDebugRec state key depth
  | ((length key `div` 4) - 2) == depth = (cipherText, buildStr)
  | otherwise = addDebugStr recCipherTuple buildStr
  where
    s_box = map subByte state
    s_row = shiftRows s_box
    m_col = mixColumns s_row
    buildStr =
      printf "round[%2d].start     " newDepth
        ++ showBytes state
        ++ "\n"
        ++ printf "round[%2d].s_box     " newDepth
        ++ showBytes s_box
        ++ "\n"
        ++ printf "round[%2d].s_row     " newDepth
        ++ showBytes s_row
        ++ "\n"
        ++ condStr
    condStr
      | ((length key `div` 4) - 2) == depth =
          printf "round[%2d].k_sch     " newDepth
            ++ showBytes (groupsOf 16 (concat key) !! newDepth)
            ++ "\n"
            ++ printf "round[%2d].output    " newDepth
            ++ showBytes cipherText
      | otherwise =
          printf "round[%2d].m_col     " newDepth
            ++ showBytes m_col
            ++ "\n"
            ++ printf "round[%2d].k_sch     " newDepth
            ++ showBytes (groupsOf 16 (concat key) !! newDepth)
            ++ "\n"
    recCipherTuple = cipherDebugRec (addRoundKey m_col key newDepth) key newDepth
    cipherText = addRoundKey s_row key ((length key `div` 4) - 1)
    newDepth = depth + 1

---- AES inverse cipher --------------------------------------------------------

invCipher :: Key -> Block -> [Byte]
invCipher key blk = invCipherRec roundKey expKey 0
  where
    expKey = keyExpansion key
    roundKey = addRoundKey (makeBytes blk) expKey ((length expKey `div` 4) - 1)

invCipherRec :: [Byte] -> [[Byte]] -> Int -> [Byte]
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
  "round[ 0].iinput    "
    ++ showBytes cipherText
    ++ "\n"
    ++ "round[ 0].ik_sch    "
    ++ showBytes (groupsOf 16 (concat expKey) !! invRoundNum)
    ++ "\n"
    ++ snd recOutput
  where
    expKey = keyExpansion key
    recOutput = invCipherDebugRec (addRoundKey cipherText expKey invRoundNum) expKey 0
    cipherText = makeBytes blk
    invRoundNum = (length expKey `div` 4) - 1

invCipherDebugRec :: [Byte] -> [[Byte]] -> Int -> ([Byte], String)
invCipherDebugRec state key depth
  | invRoundNum == 0 = (plainText, buildStr)
  | otherwise = addDebugStr recInvCipherTuple buildStr
  where
    is_row = invShiftRows state
    is_box = map invSubByte is_row
    ik_add = addRoundKey is_box key invRoundNum
    buildStr =
      printf "round[%2d].istart    " newDepth
        ++ showBytes state
        ++ "\n"
        ++ printf "round[%2d].is_row    " newDepth
        ++ showBytes is_row
        ++ "\n"
        ++ printf "round[%2d].is_box    " newDepth
        ++ showBytes is_box
        ++ "\n"
        ++ printf "round[%2d].ik_sch    " newDepth
        ++ showBytes (groupsOf 16 (concat key) !! invRoundNum)
        ++ "\n"
        ++ condStr
    condStr
      | invRoundNum == 0 = printf "round[%2d].ioutput   " newDepth ++ showBytes plainText
      | otherwise = printf "round[%2d].ik_add    " newDepth ++ showBytes ik_add ++ "\n"
    recInvCipherTuple = invCipherDebugRec (invMixColumns ik_add) key newDepth
    plainText = addRoundKey is_box key 0
    invRoundNum = (length key `div` 4) - 2 - depth
    newDepth = depth + 1

---- AES equivalent inverse cipher ---------------------------------------------

eqInvCipher :: Key -> Block -> [Byte]
eqInvCipher key blk = eqInvCipherRec roundKey expKey 0
  where
    expKey = keyExpansionEIC key
    roundKey = addRoundKey (makeBytes blk) expKey ((length expKey `div` 4) - 1)

eqInvCipherRec :: [Byte] -> [[Byte]] -> Int -> [Byte]
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
  "round[ 0].iinput    "
    ++ showBytes cipherText
    ++ "\n"
    ++ "round[ 0].ik_sch    "
    ++ showBytes (groupsOf 16 (concat expKey) !! invRoundNum)
    ++ "\n"
    ++ snd recOutput
  where
    expKey = keyExpansionEIC key
    recOutput = eqInvCipherDebugRec (addRoundKey cipherText expKey invRoundNum) expKey 0
    cipherText = makeBytes blk
    invRoundNum = (length expKey `div` 4) - 1

eqInvCipherDebugRec :: [Byte] -> [[Byte]] -> Int -> ([Byte], String)
eqInvCipherDebugRec state key depth
  | invRoundNum == 0 = (plainText, buildStr)
  | otherwise = addDebugStr recEqInvCipherTuple buildStr
  where
    is_box = map invSubByte state
    is_row = invShiftRows is_box
    im_col = invMixColumns is_row
    buildStr =
      printf "round[%2d].istart    " newDepth
        ++ showBytes state
        ++ "\n"
        ++ printf "round[%2d].is_box    " newDepth
        ++ showBytes is_box
        ++ "\n"
        ++ printf "round[%2d].is_row    " newDepth
        ++ showBytes is_row
        ++ "\n"
        ++ condStr
    condStr
      | invRoundNum == 0 =
          printf "round[%2d].ik_sch    " newDepth
            ++ showBytes (groupsOf 16 (concat key) !! invRoundNum)
            ++ "\n"
            ++ printf "round[%2d].ioutput   " newDepth
            ++ showBytes plainText
      | otherwise =
          printf "round[%2d].im_col    " newDepth
            ++ showBytes im_col
            ++ "\n"
            ++ printf "round[%2d].ik_sch    " newDepth
            ++ showBytes (groupsOf 16 (concat key) !! invRoundNum)
            ++ "\n"
    recEqInvCipherTuple = eqInvCipherDebugRec (addRoundKey im_col key invRoundNum) key newDepth
    plainText = addRoundKey is_row key 0
    invRoundNum = (length key `div` 4) - 2 - depth
    newDepth = depth + 1

---- Helper functions ----------------------------------------------------------

groupsOf :: Int -> [a] -> [[a]]
groupsOf n = takeWhile (not . null) . unfoldr (Just . splitAt n)

addDebugStr :: (a, String) -> String -> (a, String)
addDebugStr (state, recDebug) newDebug = (state, newDebug ++ recDebug)

showBytes :: [Byte] -> String
showBytes = concatMap (printf "%02x")
