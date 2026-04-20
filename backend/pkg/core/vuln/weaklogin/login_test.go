package login

import (
	"fmt"
	"testing"
)

func TestLogin(t *testing.T) {
	res, err := TestWeakFormLogin("http://localhost:8080/", []string{"admin:admin"})
	fmt.Printf("err: %v\n", err)
	fmt.Printf("res: %v\n", res)
}
