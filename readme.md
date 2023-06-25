
# Noble

A simple wrapper to make working with Go's implementation of argon2 much simpler.

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