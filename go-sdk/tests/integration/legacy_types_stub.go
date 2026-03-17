package integration

import (
	"math/big"

	nodesig "github.com/vocdoni/davinci-node/crypto/signatures/ethereum"
)

type sigJSON struct {
	PublicKeyX string `json:"public_key_x"`
	PublicKeyY string `json:"public_key_y"`
	SignatureR string `json:"signature_r"`
	SignatureS string `json:"signature_s"`
	SignatureV byte   `json:"signature_v"`
	VoteID     uint64 `json:"vote_id"`
	Address    string `json:"address"`
}

type Voter struct {
	Signer        *nodesig.Signer
	AddressBytes  []byte
	AddressBigInt *big.Int
	CensusIdx     int
	Weight        *big.Int
}
