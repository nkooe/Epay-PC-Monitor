package main

// SQLCipher 第一页 HMAC 验证（不依赖 WCDB）
//
// 微信 4.1+ 用的是 SQLCipher 4 默认参数（见 wechat-wcdb-v4.json）：
//   page_size      = 4096
//   kdf_hash       = SHA512
//   kdf_iterations = 256000
//   mac_kdf_iter   = 2      ← MAC 子密钥只用 2 次迭代
//   hmac_hash      = SHA512
//   hmac_salt_mask = 0x3A   ← 派生 MAC 密钥时 salt 首字节异或 0x3A
//   reserve_size   = 80     ← 每页尾部 80 字节（IV 16 + HMAC 64）
//
// 第一页布局：
//   [0, 16)              salt
//   [16, 4096-80)        加密数据
//   [4096-80, 4096-64)   IV
//   [4096-64, 4096)      HMAC
//
// HMAC 输入：加密数据 + IV + page_number（小端 4 字节，第一页为 1）

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	scPageSize     = 4096
	scSaltSize     = 16
	scIVSize       = 16
	scHMACSize     = 64
	scReserveSize  = 80
	scKDFIter      = 256000
	scMACKDFIter   = 2
	scHMACSaltMask = 0x3A
)

// pbkdf2SHA512 实现 PBKDF2-HMAC-SHA512
// （golang.org/x/crypto/pbkdf2 也能用，这里手写避免额外依赖）
func pbkdf2SHA512(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha512.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// scSample 一个数据库的第一页
type scSample struct {
	Path  string
	Page1 []byte
}

// readFirstPage 读取数据库第一页（共享读，不影响微信）
func readFirstPage(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, scPageSize)
	n, err := f.Read(buf)
	if err != nil || n < scPageSize {
		return nil, fmt.Errorf("首页长度不足: %d", n)
	}
	return buf, nil
}

// scVerifyPage1 用候选密钥验证第一页 HMAC
func scVerifyPage1(key []byte, page1 []byte) bool {
	if len(key) != 32 || len(page1) < scPageSize {
		return false
	}
	salt := page1[:scSaltSize]
	dataEnd := scPageSize - scReserveSize

	// 1) 加密密钥
	encKey := pbkdf2SHA512(key, salt, scKDFIter, 32)

	// 2) MAC 子密钥
	//    注意：SQLCipher 是对 salt 的「每一个字节」都异或 hmac_salt_mask，
	//    不是只异或首字节。这一步写错就永远验证不过。
	macSalt := make([]byte, len(salt))
	for i := range salt {
		macSalt[i] = salt[i] ^ scHMACSaltMask
	}
	macKey := pbkdf2SHA512(encKey, macSalt, scMACKDFIter, 32)

	// 3) 计算 HMAC
	mac := hmac.New(sha512.New, macKey)
	mac.Write(page1[scSaltSize:dataEnd])   // 加密数据
	mac.Write(page1[dataEnd : dataEnd+scIVSize]) // IV
	var pn [4]byte
	binary.LittleEndian.PutUint32(pn[:], 1)
	mac.Write(pn[:])
	sum := mac.Sum(nil)

	want := page1[scPageSize-scHMACSize:]
	return hmac.Equal(sum, want)
}

// verifyKeyByHMAC 用第一页 HMAC 快速验证密钥
func verifyKeyByHMAC(keyHex string, samples []scSample) bool {
	if len(keyHex) != 64 || len(samples) == 0 {
		return false
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		if _, err := fmt.Sscanf(keyHex[i*2:i*2+2], "%02x", &b); err != nil {
			return false
		}
		key[i] = b
	}
	for _, s := range samples {
		if !scVerifyPage1(key, s.Page1) {
			return false
		}
	}
	return true
}
