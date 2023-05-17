package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SM3WithSM2Sign SM3WithSM2签名 Hex ToUpper
func SM3WithSM2Sign(privateKey *sm2.PrivateKey, forSignStr string, uid []byte) (string, error) {

	r, s, err := sm2.Sm2Sign(privateKey, []byte(forSignStr), uid, rand.Reader)
	if err != nil {
		return "", err
	}

	rByte := r.Bytes()
	sByte := s.Bytes()
	if len(rByte) < 32 {
		rByte = append([]byte{0}, rByte...)
	}
	if len(sByte) < 32 {
		sByte = append([]byte{0}, sByte...)
	}
	var buffer bytes.Buffer
	buffer.Write(rByte)
	buffer.Write(sByte)

	return string(buffer.Bytes()), nil

}

func FormatPri(priByte []byte) (*sm2.PrivateKey, error) {
	c := sm2.P256Sm2()
	k := new(big.Int).SetBytes(priByte)
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func FormatPub(pubByte []byte) (*sm2.PublicKey, error) {
	c := sm2.P256Sm2()
	k := new(big.Int).SetBytes(pubByte)
	pub := new(sm2.PublicKey)
	pub.Curve = c
	pub.X, pub.Y = c.ScalarBaseMult(k.Bytes())
	return pub, nil
}

func CMBSM4EncryptWithCBC(key, iv, input []byte) ([]byte, error) {
	if key == nil || iv == nil || input == nil {
		return nil, errors.New("CMBSM4EncryptWithCBC 非法输入")
	}
	sm4.SetIV(iv)

	return sm4.Sm4Cbc(key, input, true)
}

func CMBSM4DecryptWithCBC(key, iv, input []byte) ([]byte, error) {
	if key == nil || iv == nil || input == nil {
		return nil, errors.New("CMBSM4DecryptWithCBC 非法输入")
	}

	sm4.SetIV(iv)

	return sm4.Sm4Cbc(key, input, false)
}

func CMBSM2VerifyWithSM3(key *sm2.PublicKey, id, msg, signature []byte) (bool, error) {
	if key == nil || msg == nil || signature == nil {
		return false, errors.New("CMBSM2VerifyWithSM3 input error")
	}
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(signature)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false, errors.New("CMBSM2VerifyWithSM3 input error")
	}

	return sm2.Sm2Verify(key, msg, id, r, s), nil

}
