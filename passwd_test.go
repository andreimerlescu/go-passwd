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
	"testing"
)

func TestAudit(t *testing.T) {
	tests := []struct {
		name     string
		password string
		options  Options
		wantErr  bool
		wantComp int64
	}{
		{
			name:     "Short password fails",
			password: "abc",
			options:  Options{MinLength: 8},
			wantErr:  true,
		},
		{
			name:     "Simple password, no requirements",
			password: "password",
			options:  Options{MinLength: 8},
			wantErr:  false,
			wantComp: PwComplexityLowerOnly,
		},
		{
			name:     "Password with digits and lowercase",
			password: "pass1234",
			options:  Options{MinLength: 8, UseDigits: true, UseLower: true},
			wantErr:  false,
			wantComp: PwComplexityLowerDigits,
		},
		{
			name:     "Password with upper and symbols",
			password: "PASS@1234",
			options:  Options{MinLength: 8, UseUpper: true, UseSymbols: true},
			wantErr:  false,
			wantComp: PwComplexitySymbolsDigits,
		},
		{
			name:     "Password with extended characters",
			password: "P@sswørd",
			options:  Options{MinLength: 8, UseExtended: true},
			wantErr:  false,
			wantComp: PwComplexityExtendedMixed,
		},
		{
			name:     "Fails without required symbols",
			password: "Password123",
			options:  Options{MinLength: 8, UseSymbols: true},
			wantErr:  true,
		},
		{
			name:     "Fails without required uppercase",
			password: "password123!",
			options:  Options{MinLength: 8, UseUpper: true},
			wantErr:  true,
		},
		{
			name:     "Maximum length exceeded",
			password: "ThisIsAVeryLongPassword123!",
			options:  Options{MaxLength: 20},
			wantErr:  true,
		},
		{
			name:     "Complex password with symbols and digits",
			password: "Complex@123",
			options:  Options{MinLength: 8, UseSymbols: true, UseDigits: true},
			wantErr:  false,
			wantComp: PwComplexitySymbolsDigits,
		},
		{
			name:     "Extended password only",
			password: "Øversættelse",
			options:  Options{MinLength: 8, UseExtended: true},
			wantErr:  false,
			wantComp: PwComplexityExtendedOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Audit(tt.password, tt.options)
			if (result.Err != nil) != tt.wantErr {
				t.Errorf("Audit() error = %v, wantErr %v", result.Err, tt.wantErr)
			}
			if result.Complexity < tt.wantComp && !tt.wantErr {
				t.Errorf("Audit() complexity = %v, want < %v", result.Complexity, tt.wantComp)
			}
		})
	}
}

func BenchmarkAudit(b *testing.B) {
	password := "P@sswørd12345!"
	options := Options{
		MinLength:         8,
		MaxLength:         20,
		UseDigits:         true,
		UseLower:          true,
		UseUpper:          true,
		UseSymbols:        true,
		UseExtended:       true,
		MinimumComplexity: PwComplexitySymbolsDigitsMixed,
	}

	for i := 0; i < b.N; i++ {
		Audit(password, options)
	}
}
