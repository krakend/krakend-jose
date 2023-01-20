package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
)

func Example() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// use "smGbjm71Nxd1Ig5FS0wj9SlbzAIrnolCz9bQQ6uAhl4=" as secret
	c, err := New(ctx, "base64key://smGbjm71Nxd1Ig5FS0wj9SlbzAIrnolCz9bQQ6uAhl4=")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer c.Close()

	plainKey := make([]byte, 32)
	rand.Read(plainKey)

	cypherKey, err := c.EncryptKey(ctx, plainKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	plainText := "asdfghjklñqwertyuiozxcvbnm,"

	cypherText, err := c.Encrypt(ctx, []byte(plainText), cypherKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	result, err := c.Decrypt(ctx, cypherText, cypherKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	if r := string(result); r != plainText {
		fmt.Printf("unexpected result: %s", r)
	}

	// output:
}

func ExampleEncrypt() {
	msg := "zxcvbnmasdfghjklqwertyuiop1234567890"
	passphrase := "some secret"

	cypherMsg, err := Encrypt([]byte(msg), []byte(passphrase))
	if err != nil {
		fmt.Println(err)
		return
	}

	cypherMsg2, err2 := Encrypt([]byte(msg), []byte(passphrase))
	if err2 != nil {
		fmt.Println(err2)
		return
	}

	if bytes.Equal(cypherMsg, cypherMsg2) {
		fmt.Println("two executions with the same input shall not generate the same output")
	}

	// output:
}

func ExampleDecrypt() {
	msg := "zxcvbnmasdfghjklqwertyuiop1234567890"
	passphrase := "some secret"

	cypherMsg, err := Encrypt([]byte(msg), []byte(passphrase))
	if err != nil {
		fmt.Println(err)
		return
	}

	cypherMsg2, err2 := Encrypt([]byte(msg), []byte(passphrase))
	if err2 != nil {
		fmt.Println(err2)
		return
	}

	if bytes.Equal(cypherMsg, cypherMsg2) {
		fmt.Println("two executions with the same input shall not generate the same output")
		return
	}

	res1, err3 := Decrypt(cypherMsg, []byte(passphrase))
	if err != nil {
		fmt.Println(err3)
		return
	}

	res2, err4 := Decrypt(cypherMsg2, []byte(passphrase))
	if err != nil {
		fmt.Println(err4)
		return
	}

	if !bytes.Equal(res1, res2) {
		fmt.Println("results are different:", string(res1), string(res2))
		return
	}

	// output:
}
