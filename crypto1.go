package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	BlockSize   = 8
	KeySize     = 32
	RoundCount  = 32
	SubkeyCount = 8
)

var sBox = [8][16]byte{
	{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
	{14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
	{5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
	{7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
	{6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
	{4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
	{13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
	{1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12},
}

type MagmaCore struct {
	subkeys [32]uint32
}

func NewMagmaCore(key []byte) (*MagmaCore, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid key length")
	}
	m := &MagmaCore{}
	m.expandKey(key)
	return m, nil
}

func (m *MagmaCore) expandKey(key []byte) {
	for i := 0; i < 8; i++ {
		m.subkeys[i] = binary.LittleEndian.Uint32(key[i*4 : (i+1)*4])
	}
	for i := 8; i < 24; i++ {
		m.subkeys[i] = m.subkeys[i%8]
	}
	for i := 24; i < 32; i++ {
		m.subkeys[i] = m.subkeys[7-(i%8)]
	}
}

func (m *MagmaCore) EncryptBlock(dst, src []byte) {
	if len(src) < BlockSize {
		panic("source block too small")
	}
	if len(dst) < BlockSize {
		panic("destination buffer too small")
	}

	left := binary.LittleEndian.Uint32(src[:4])
	right := binary.LittleEndian.Uint32(src[4:])

	for i := 0; i < RoundCount; i++ {
		roundKey := m.subkeys[i]
		newRight := left ^ m.f(right, roundKey)
		left = right
		right = newRight
	}

	binary.LittleEndian.PutUint32(dst[:4], right)
	binary.LittleEndian.PutUint32(dst[4:], left)
}

func (m *MagmaCore) f(block uint32, key uint32) uint32 {
	value := block + key
	value32 := uint32(value)

	var result uint32
	for i := 0; i < 8; i++ {
		sboxIndex := (value32 >> (4 * i)) & 0x0F
		sboxValue := sBox[i][sboxIndex]
		result |= uint32(sboxValue) << (4 * i)
	}

	return (result << 11) | (result >> (32 - 11))
}

type MGM struct {
	E      *MagmaCore
	H      uint64
	nonce  []byte
	buffer [BlockSize]byte
}

func NewMGM(key, nonce []byte) (*MGM, error) {
	if len(nonce) != BlockSize {
		return nil, errors.New("nonce must be 8 bytes")
	}

	core, err := NewMagmaCore(key)
	if err != nil {
		return nil, err
	}

	mgm := &MGM{
		E:     core,
		nonce: make([]byte, BlockSize),
	}
	copy(mgm.nonce, nonce)

	var zero [BlockSize]byte
	mgm.E.EncryptBlock(mgm.buffer[:], zero[:])
	mgm.H = binary.LittleEndian.Uint64(mgm.buffer[:])

	return mgm, nil
}

func (m *MGM) EncryptFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer outputFile.Close()

	buf := make([]byte, 4096)
	for {
		n, err := inputFile.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading: %v", err)
		}
		if n == 0 {
			break
		}

		encrypted := make([]byte, n)
		m.processBlocks(encrypted, buf[:n])

		if _, err := outputFile.Write(encrypted); err != nil {
			return fmt.Errorf("error writing: %v", err)
		}
	}

	return nil
}

func (m *MGM) DecryptFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer outputFile.Close()

	buf := make([]byte, 4096)
	for {
		n, err := inputFile.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("error reading: %v", err)
		}
		if n == 0 {
			break
		}

		decrypted := make([]byte, n)
		m.processBlocks(decrypted, buf[:n])

		if _, err := outputFile.Write(decrypted); err != nil {
			return fmt.Errorf("error writing: %v", err)
		}
	}

	return nil
}

func (m *MGM) processBlocks(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if i%BlockSize == 0 {
			m.incCounter()
			m.E.EncryptBlock(m.buffer[:], m.nonce)
		}
		if i < len(dst) {
			dst[i] = src[i] ^ m.buffer[i%BlockSize]
		}
	}
}

func (m *MGM) incCounter() {
	counter := binary.LittleEndian.Uint64(m.nonce)
	counter++
	binary.LittleEndian.PutUint64(m.nonce, counter)
}

func ReadKeyFromFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	keyStr := strings.TrimSpace(string(data))
	return hex.DecodeString(keyStr)
}

func ReadNonceFromFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	nonceStr := strings.TrimSpace(string(data))
	return hex.DecodeString(nonceStr)
}

// 🔐 Очистка памяти (затирание ключа)
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
