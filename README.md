# Go Passwd

This package makes auditing passwords easy.

## Installation 

```bash
go get -u github.com/andreimerlescu/go-passwd
```

## Example

```go
package main

import (
	"fmt"
	"github.com/andreimerlescu/go-passwd"
)

func main() {
	password := "P@sswørd123"
	options := go_passwd.Options{
		MinLength:         8,
		MaxLength:         32,
		UseDigits:         true,
		UseLower:          true,
		UseUpper:          true,
		UseSymbols:        true,
		UseExtended:       true,
		MinimumComplexity: go_passwd.PwComplexitySymbolsDigitsMixed,
	}

	result := go_passwd.Audit(password, options)
	if result.Err != nil {
		fmt.Printf("Password failed: %v\n", result.Err)
	} else {
		fmt.Printf("Password passed! Entropy: %.2f, Complexity: %d, Strong: %t\n",
			result.Entropy, result.Complexity, result.Strong)
	}
}

```

## Breakdown of `Options`

| **Option**          | **Type** | **Description**                                                               |
|---------------------|----------|-------------------------------------------------------------------------------|
| `MinLength`         | `uint`   | Minimum required length of the password.                                      |
| `MaxLength`         | `uint`   | Maximum allowed length of the password.                                       |
| `UseDigits`         | `bool`   | Require the password to include digits (`0-9`).                               |
| `UseLower`          | `bool`   | Require the password to include lowercase letters (`a-z`).                    |
| `UseUpper`          | `bool`   | Require the password to include uppercase letters (`A-Z`).                    |
| `UseSymbols`        | `bool`   | Require the password to include symbols (e.g., `@`, `#`, `$`).                |
| `UseExtended`       | `bool`   | Require the password to include extended Unicode characters (e.g., `ø`, `ß`). |
| `MinimumComplexity` | `int64`  | Minimum acceptable password complexity level (see Complexity Levels below).   |

---

## Breakdown of Audit Results `Result`

| **Result Field** | **Type**  | **Description**                                                         |
|------------------|-----------|-------------------------------------------------------------------------|
| `Entropy`        | `float64` | The calculated entropy of the password (higher is better).              |
| `Strong`         | `bool`    | Indicates if the password meets the minimum complexity requirement.     |
| `Length`         | `int64`   | The length of the password.                                             |
| `Complexity`     | `int64`   | Complexity level of the password (see Complexity Levels below).         |
| `HasExtended`    | `bool`    | True if the password contains extended Unicode characters.              |
| `Err`            | `error`   | An error describing why the password failed validation (if applicable). |

---

## Complexity Levels

| **Constant**                     | **Value** | **Description**                                                       |
|----------------------------------|-----------|-----------------------------------------------------------------------|
| `PwComplexityDigitsOnly`         | `0`       | Password contains only digits.                                        |
| `PwComplexityLowerOnly`          | `1`       | Password contains only lowercase letters.                             |
| `PwComplexityUpperOnly`          | `2`       | Password contains only uppercase letters.                             |
| `PwComplexityLowerDigits`        | `3`       | Password contains lowercase letters and digits.                       |
| `PwComplexityUpperDigits`        | `4`       | Password contains uppercase letters and digits.                       |
| `PwComplexityMixedOnly`          | `5`       | Password contains both lowercase and uppercase letters.               |
| `PwComplexityDigitsMixed`        | `6`       | Password contains digits, lowercase, and uppercase letters.           |
| `PwComplexitySymbolsOnly`        | `7`       | Password contains only symbols.                                       |
| `PwComplexitySymbolsDigits`      | `8`       | Password contains symbols and digits.                                 |
| `PwComplexitySymbolsUpper`       | `9`       | Password contains symbols and uppercase letters.                      |
| `PwComplexitySymbolsLower`       | `10`      | Password contains symbols and lowercase letters.                      |
| `PwComplexitySymbolsMixed`       | `11`      | Password contains symbols, lowercase, and uppercase letters.          |
| `PwComplexitySymbolsDigitsMixed` | `12`      | Password contains symbols, digits, lowercase, and uppercase letters.  |
| `PwComplexityExtendedOnly`       | `13`      | Password contains only extended Unicode letters.                      |
| `PwComplexityExtendedMixed`      | `14`      | Password contains extended Unicode characters along with other types. |

---

## Test Results

### Unit Test

```bash
go test -v
```

```log
=== RUN   TestAudit
--- PASS: TestAudit (0.00s)
=== RUN   TestAudit/Short_password_fails
    --- PASS: TestAudit/Short_password_fails (0.00s)
=== RUN   TestAudit/Simple_password,_no_requirements
    --- PASS: TestAudit/Simple_password,_no_requirements (0.00s)
=== RUN   TestAudit/Password_with_digits_and_lowercase
    --- PASS: TestAudit/Password_with_digits_and_lowercase (0.00s)
=== RUN   TestAudit/Password_with_upper_and_symbols
    --- PASS: TestAudit/Password_with_upper_and_symbols (0.00s)
=== RUN   TestAudit/Password_with_extended_characters
    --- PASS: TestAudit/Password_with_extended_characters (0.00s)
=== RUN   TestAudit/Fails_without_required_symbols
    --- PASS: TestAudit/Fails_without_required_symbols (0.00s)
=== RUN   TestAudit/Fails_without_required_uppercase
    --- PASS: TestAudit/Fails_without_required_uppercase (0.00s)
=== RUN   TestAudit/Maximum_length_exceeded
    --- PASS: TestAudit/Maximum_length_exceeded (0.00s)
=== RUN   TestAudit/Complex_password_with_symbols_and_digits
    --- PASS: TestAudit/Complex_password_with_symbols_and_digits (0.00s)
=== RUN   TestAudit/Extended_password_only
    --- PASS: TestAudit/Extended_password_only (0.00s)
PASS

Process finished with the exit code 0
```

### Benchmark Test

```bash
go test -bench=.
```

```log
goos: linux
goarch: amd64
pkg: github.com/andreimerlescu/go-passwd
cpu: Intel(R) Xeon(R) W-3245 CPU @ 3.20GHz
BenchmarkAudit
BenchmarkAudit-16    	 6615944	       167.9 ns/op
PASS

Process finished with the exit code 0
```

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

```plaintext
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### Contributions

Contributions are welcome! Please fork this repository, make your changes, and submit a pull request.
