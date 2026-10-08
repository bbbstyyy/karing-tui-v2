package urilist

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	MaxBase64URIListSourceBytes  = 12 << 20
	MaxBase64URIListDecodedBytes = 8 << 20
)

var ErrInvalidBase64URIList = errors.New("invalid base64 URI-list subscription")

// AnalyzeBase64Profile accepts only a base64 envelope around the existing
// strictly validated decoded URI-list format. It does not extend URI protocol
// compatibility or interpret source-provided routes and DNS.
func AnalyzeBase64Profile(
	data []byte,
	profileID string,
) (singboximport.ProfileAnalysis, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return singboximport.ProfileAnalysis{}, err
	}
	if len(data) == 0 || len(data) > MaxBase64URIListSourceBytes {
		return singboximport.ProfileAnalysis{}, fmt.Errorf(
			"%w: encoded input is empty or too large",
			ErrInvalidBase64URIList,
		)
	}

	encoded := make([]byte, 0, len(data))
	for _, value := range data {
		switch {
		case value == ' ', value == '\n', value == '\r', value == '\t':
			continue
		case value >= 'A' && value <= 'Z',
			value >= 'a' && value <= 'z',
			value >= '0' && value <= '9',
			value == '+', value == '/', value == '-', value == '_', value == '=':
			encoded = append(encoded, value)
		default:
			return singboximport.ProfileAnalysis{}, fmt.Errorf(
				"%w: encoded input contains invalid characters",
				ErrInvalidBase64URIList,
			)
		}
	}
	if len(encoded) == 0 {
		return singboximport.ProfileAnalysis{}, fmt.Errorf(
			"%w: encoded input is blank",
			ErrInvalidBase64URIList,
		)
	}

	var (
		decoded   []byte
		decodedOK bool
	)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding.Strict(),
		base64.RawStdEncoding.Strict(),
		base64.URLEncoding.Strict(),
		base64.RawURLEncoding.Strict(),
	} {
		var err error
		decoded, err = encoding.DecodeString(string(encoded))
		if err == nil {
			decodedOK = true
			break
		}
	}
	if !decodedOK || len(decoded) == 0 {
		return singboximport.ProfileAnalysis{}, fmt.Errorf(
			"%w: base64 decoding failed or produced no content",
			ErrInvalidBase64URIList,
		)
	}
	if len(decoded) > MaxBase64URIListDecodedBytes {
		return singboximport.ProfileAnalysis{}, fmt.Errorf(
			"%w: decoded content exceeds %d bytes",
			ErrInvalidBase64URIList,
			MaxBase64URIListDecodedBytes,
		)
	}

	analysis, err := AnalyzeBasicProfile(decoded, profileID)
	if err != nil {
		return analysis, fmt.Errorf(
			"%w: decoded content does not match a URI-list",
			ErrInvalidBase64URIList,
		)
	}
	sum := sha256.Sum256(data)
	// The immutable snapshot tracks the actual source bytes, while each node
	// keeps the canonical sing-box payload emitted by the strict URI importer.
	analysis.SourceSHA256 = hex.EncodeToString(sum[:])
	return analysis, nil
}
