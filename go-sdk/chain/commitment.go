// commitment.go reproduces, host-side, the aggregator guest's election-identity
// commitment: config_commitment = sha256(config frame ‖ batch_vk ‖ fold_vk).
// An independent verifier holding only the published initial parameters and the
// circuit-release vks can recompute this and check it against the finalize
// digest, binding the proof to exactly those parameters and that circuit.
package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// configFrameLen is the byte length of the guest config frame.
const configFrameLen = 200

// hex32 decodes a 32-byte arbo-LE hex field (with or without 0x). The bytes are
// used verbatim, exactly as the guest's parse_config consumes them.
func hex32(name, s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("config %s: bad hex: %w", name, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("config %s: want 32 bytes, got %d", name, len(b))
	}
	return b, nil
}

// ConfigFrame encodes the 200-byte guest config frame from the wire ChainConfig,
// byte-identical to input-gen's ChainConfig::encode.
func ConfigFrame(c *davinci.ChainConfig) ([]byte, error) {
	frame := make([]byte, 0, configFrameLen)
	for _, f := range []struct{ name, hex string }{
		{"process_id", c.ProcessID},
		{"ballot_mode", c.BallotMode},
		{"enc_x", c.EncX},
		{"enc_y", c.EncY},
	} {
		b, err := hex32(f.name, f.hex)
		if err != nil {
			return nil, err
		}
		frame = append(frame, b...)
	}
	frame = binary.LittleEndian.AppendUint64(frame, c.CensusOrigin)
	for _, f := range []struct{ name, hex string }{
		{"census_root", c.CensusRoot},
		{"ballot_vk_hash", c.BallotVKHash},
	} {
		b, err := hex32(f.name, f.hex)
		if err != nil {
			return nil, err
		}
		frame = append(frame, b...)
	}
	if len(frame) != configFrameLen {
		return nil, fmt.Errorf("config frame: got %d bytes, want %d", len(frame), configFrameLen)
	}
	return frame, nil
}

// VKWords decodes a 0x-prefixed big-endian vk hex (the form digest.BatchVK /
// digest.FoldVK and PlonkSnark.ProgramVK use) into the guest's 4 native u64
// words. Each 8-byte big-endian group is one word.
func VKWords(vkHex string) ([4]uint64, error) {
	s := strings.TrimPrefix(vkHex, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return [4]uint64{}, fmt.Errorf("vk hex: %w", err)
	}
	if len(b) != 32 {
		return [4]uint64{}, fmt.Errorf("vk: want 32 bytes, got %d", len(b))
	}
	var w [4]uint64
	for i := 0; i < 4; i++ {
		w[i] = binary.BigEndian.Uint64(b[i*8:])
	}
	return w, nil
}

// CanonicalConfigCommitment recomputes the guest's config_commitment over the
// config frame plus the two circuit verification keys. batchVK/foldVK are the
// native guest words (see VKWords); they are appended little-endian, matching
// the guest's `w.to_le_bytes()`.
func CanonicalConfigCommitment(c *davinci.ChainConfig, batchVK, foldVK [4]uint64) ([32]byte, error) {
	frame, err := ConfigFrame(c)
	if err != nil {
		return [32]byte{}, err
	}
	buf := make([]byte, 0, len(frame)+64)
	buf = append(buf, frame...)
	for _, w := range batchVK {
		buf = binary.LittleEndian.AppendUint64(buf, w)
	}
	for _, w := range foldVK {
		buf = binary.LittleEndian.AppendUint64(buf, w)
	}
	return sha256.Sum256(buf), nil
}

// ConfigCommitment recomputes this state's election-identity commitment under
// the given circuit-release vks. Compare it against a finalize digest's
// ConfigCommitment to bind the proof to these initial parameters and circuit.
func (s *State) ConfigCommitment(batchVK, foldVK [4]uint64) ([32]byte, error) {
	return CanonicalConfigCommitment(s.ChainConfig(), batchVK, foldVK)
}
