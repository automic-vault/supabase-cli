package main

import (
	"fmt"
	"io"
	"os"
)

const keyringService = "Supabase CLI"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "av-keyring" {
		return fmt.Errorf("usage: supabase-go av-keyring get|set|delete|delete-all [ACCOUNT]")
	}

	switch args[1] {
	case "get":
		if len(args) != 3 {
			return fmt.Errorf("usage: supabase-go av-keyring get ACCOUNT")
		}
		value, err := keyringGet(keyringService, args[2])
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, value)
		return err
	case "set":
		if len(args) != 3 {
			return fmt.Errorf("usage: supabase-go av-keyring set ACCOUNT")
		}
		value, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		return keyringSet(keyringService, args[2], string(value))
	case "delete":
		if len(args) != 3 {
			return fmt.Errorf("usage: supabase-go av-keyring delete ACCOUNT")
		}
		return keyringDelete(keyringService, args[2])
	case "delete-all":
		if len(args) != 2 {
			return fmt.Errorf("usage: supabase-go av-keyring delete-all")
		}
		return keyringDeleteAll(keyringService)
	default:
		return fmt.Errorf("usage: supabase-go av-keyring get|set|delete|delete-all [ACCOUNT]")
	}
}
