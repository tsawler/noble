# Noble

A simple wrapper to make working with [Go](https://go.dev)'s implementation of
[Argon2](https://en.wikipedia.org/wiki/Argon2) (specifically Argon2id) much easier. Argon2 is a modern ASIC-resistant
and GPU-resistant secure key derivation function. It has better password cracking resistance (when configured correctly)
than PBKDF2 , Bcrypt and Scrypt (for similar configuration parameters for CPU and RAM usage)

Argon2 is a key derivation function that was selected as the winner of the 2015 Password Hashing Competition. It was
designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg. There are three
different versions of the algorithm, and according to OWASP, the Argon2id variant should be used, as it provides a
balanced approach to resisting both side-channel and GPU-based attacks.

## Example

```go
package main

import (
	"fmt"
	"github.com/tsawler/noble"
	"log"
)

func main() {
	// Create an instance of the type noble.Argon.
	n := noble.New()

	// Try creating a hash from a password. The returned value will 
	// include the hash, as well as all information need to validate a 
	// password against that hash using argon2.
	password := "verysecret"
	hash, err := n.GeneratePasswordKey(password)
	if err != nil {
		log.Println(err)
	}

	fmt.Println("hash for", password, "\n\t", hash)

	// Try comparing a valid password against this hash.
	valid, err := n.ComparePasswordAndHash(password, hash)
	fmt.Println("First password/hash compare is", valid)

	// Now compare with an invalid password.
	valid, err = n.ComparePasswordAndHash(password+"fish", hash)
	fmt.Println("Second password/hash compare is", valid)
}
```