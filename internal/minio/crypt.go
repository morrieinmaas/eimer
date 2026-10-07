package minio

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"crypto/pbkdf2"
	"github.com/secure-io/sio-go"
	"golang.org/x/crypto/argon2"
)

// MinIO encrypts sensitive admin responses with the caller's secret key:
//
//	salt (32 bytes) | kdf+cipher id (1 byte) | nonce (8 bytes) | sio stream
//
// id 0: argon2id + AES-256-GCM, id 1: argon2id + ChaCha20-Poly1305,
// id 2: PBKDF2-SHA256 + AES-256-GCM (FIPS builds).
const (
	idArgon2AESGCM   = 0x00
	idArgon2ChaCha20 = 0x01
	idPBKDF2AESGCM   = 0x02

	saltSize  = 32
	nonceSize = 8
	headerLen = saltSize + 1 + nonceSize
)

func deriveKey(id byte, password string, salt []byte) ([]byte, error) {
	switch id {
	case idArgon2AESGCM, idArgon2ChaCha20:
		return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32), nil
	case idPBKDF2AESGCM:
		return pbkdf2.Key(sha256.New, password, salt, 8192, 32)
	}
	return nil, fmt.Errorf("unknown encryption id %#x", id)
}

func streamFor(id byte, key []byte) (*sio.Stream, error) {
	if id == idArgon2ChaCha20 {
		return sio.ChaCha20Poly1305.Stream(key)
	}
	return sio.AES_256_GCM.Stream(key)
}

func decrypt(password string, data []byte) ([]byte, error) {
	if len(data) < headerLen {
		return nil, errors.New("encrypted response too short")
	}
	salt, id, nonce, body := data[:saltSize], data[saltSize], data[saltSize+1:headerLen], data[headerLen:]
	key, err := deriveKey(id, password, salt)
	if err != nil {
		return nil, err
	}
	stream, err := streamFor(id, key)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(stream.DecryptReader(bytes.NewReader(body), nonce, nil))
	if err != nil {
		return nil, fmt.Errorf("decrypt admin response: %w", err)
	}
	return plain, nil
}

// encrypt is the inverse, used by tests to build responses the way the server does.
func encrypt(password string, id byte, salt, nonce, plain []byte) ([]byte, error) {
	key, err := deriveKey(id, password, salt)
	if err != nil {
		return nil, err
	}
	stream, err := streamFor(id, key)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(salt)
	buf.WriteByte(id)
	buf.Write(nonce)
	w := stream.EncryptWriter(&buf, nonce, nil)
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
