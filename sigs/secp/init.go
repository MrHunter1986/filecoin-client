package secp

import (
	"fmt"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/minio/blake2b-simd"
	gosecp256k1 "github.com/filecoin-project/go-crypto"
	//"github.com/MrHunter1986/filecoin-client/pkg/gosecp256k1"
	"github.com/MrHunter1986/filecoin-client/sigs"
)

type secpSigner struct{}

func (secpSigner) GenPrivate() ([]byte, error) {
	priv, err := gosecp256k1.GenerateKey()
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (secpSigner) ToPublic(pk []byte) ([]byte, error) {
	return gosecp256k1.PublicKey(pk), nil
}

func (secpSigner) Sign(pk []byte, msg []byte) ([]byte, error) {
	b2sum := blake2b.Sum256(msg)
	sig, err := gosecp256k1.Sign(pk, b2sum[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (secpSigner) Verify(sig []byte, a address.Address, msg []byte) error {
	b2sum := blake2b.Sum256(msg)
	pubk, err := gosecp256k1.EcRecover(b2sum[:], sig)
	if err != nil {
		return err
	}

	maybeaddr, err := address.NewSecp256k1Address(pubk)
	if err != nil {
		return err
	}

	if a != maybeaddr {
		return fmt.Errorf("signature did not match")
	}

	return nil
}

func init() {
	sigs.RegisterSignature(crypto.SigTypeSecp256k1, secpSigner{})
}
