package pkcs7

import (
	"bytes"
	"fmt"
)

func BerFuzzer(ber []byte) int {
	der, err := ber2der(ber)
	if err != nil {
		// Return 0 because we want to probe error cases
		fmt.Printf("ber2der failed with error: %v", err)
		return 0
	}

	if der2, err := ber2der(der); err != nil {
		fmt.Printf("ber2der on DER bytes failed with error: %v", err)
		panic("Bad output!")
	} else {
		if !bytes.Equal(der, der2) {
			panic("ber2der is not idempotent")
		}
	}
	return 0
}
