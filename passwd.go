package go_passwd

/*
   Copyright 2024 Andrei Merlescu

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

import (
	"errors"
	"math"
	"strings"
	"unicode"
)

const (
	PwComplexityDigitsOnly = iota
	PwComplexityLowerOnly
	PwComplexityUpperOnly
	PwComplexityLowerDigits
	PwComplexityUpperDigits
	PwComplexityMixedOnly
	PwComplexityDigitsMixed
	PwComplexitySymbolsOnly
	PwComplexitySymbolsDigits
	PwComplexitySymbolsUpper
	PwComplexitySymbolsLower
	PwComplexitySymbolsMixed
	PwComplexitySymbolsDigitsMixed
	PwComplexityExtendedOnly
	PwComplexityExtendedMixed // Includes extended characters and other types
)

type Options struct {
	MinLength         uint
	MaxLength         uint
	UseDigits         bool
	UseLower          bool
	UseUpper          bool
	UseSymbols        bool
	UseExtended       bool // Check for extended Unicode characters
	MinimumComplexity int64
}

type Result struct {
	Entropy     float64
	Strong      bool
	Length      int64
	Complexity  int64
	HasExtended bool // True if the password contains extended characters
	Err         error
}

func Audit(pass string, opts Options) Result {
	var audit Result

	length := len(pass)
	audit.Length = int64(length)

	if length < int(opts.MinLength) {
		audit.Err = errors.New("password too short")
		return audit
	}

	if opts.MaxLength > 0 && length > int(opts.MaxLength) {
		audit.Err = errors.New("password too long")
		return audit
	}

	// Initialize character type flags
	hasDigits := strings.ContainsAny(pass, "0123456789")
	hasLower := strings.ContainsAny(pass, "abcdefghijklmnopqrstuvwxyz")
	hasUpper := strings.ContainsAny(pass, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasSymbols := strings.ContainsAny(pass, "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~")
	hasExtended := containsExtended(pass)

	// Check requirements
	if opts.UseDigits && !hasDigits {
		audit.Err = errors.New("password must contain digits")
		return audit
	}

	if opts.UseLower && !hasLower {
		audit.Err = errors.New("password must contain lowercase letters")
		return audit
	}

	if opts.UseUpper && !hasUpper {
		audit.Err = errors.New("password must contain uppercase letters")
		return audit
	}

	if opts.UseSymbols && !hasSymbols {
		audit.Err = errors.New("password must contain symbols")
		return audit
	}

	if opts.UseExtended && !hasExtended {
		audit.Err = errors.New("password must contain extended Unicode characters")
		return audit
	}

	// Calculate entropy
	charsetSize := 0
	if hasDigits {
		charsetSize += 10
	}
	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasSymbols {
		charsetSize += len("!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~")
	}
	if hasExtended {
		charsetSize += 100 // Rough estimate for Unicode letters beyond ASCII
	}

	audit.Entropy = float64(length) * math.Log2(float64(charsetSize))
	audit.HasExtended = hasExtended

	// Determine complexity
	switch {
	case hasExtended && !(hasSymbols || hasDigits || hasLower || hasUpper):
		audit.Complexity = PwComplexityExtendedOnly
	case hasExtended && (hasSymbols || hasDigits || hasLower || hasUpper):
		audit.Complexity = PwComplexityExtendedMixed
	case hasSymbols && hasDigits && hasLower && hasUpper:
		audit.Complexity = PwComplexitySymbolsDigitsMixed
	case hasSymbols && hasDigits:
		audit.Complexity = PwComplexitySymbolsDigits
	case hasSymbols && hasLower && hasUpper:
		audit.Complexity = PwComplexitySymbolsMixed
	case hasSymbols && hasLower:
		audit.Complexity = PwComplexitySymbolsLower
	case hasSymbols && hasUpper:
		audit.Complexity = PwComplexitySymbolsUpper
	case hasSymbols:
		audit.Complexity = PwComplexitySymbolsOnly
	case hasDigits && hasLower && hasUpper:
		audit.Complexity = PwComplexityDigitsMixed
	case hasLower && hasDigits:
		audit.Complexity = PwComplexityLowerDigits
	case hasUpper && hasDigits:
		audit.Complexity = PwComplexityUpperDigits
	case hasLower && hasUpper:
		audit.Complexity = PwComplexityMixedOnly
	case hasDigits:
		audit.Complexity = PwComplexityDigitsOnly
	case hasLower:
		audit.Complexity = PwComplexityLowerOnly
	case hasUpper:
		audit.Complexity = PwComplexityUpperOnly
	default:
		audit.Complexity = PwComplexityDigitsOnly // Fallback to weakest
	}

	audit.Strong = audit.Complexity >= opts.MinimumComplexity

	return audit
}

// containsExtended checks if the password contains any extended Unicode letters (beyond ASCII).
func containsExtended(pass string) bool {
	for _, r := range pass {
		if r > unicode.MaxASCII && unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
