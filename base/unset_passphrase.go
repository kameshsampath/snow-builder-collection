package main

import (
    "os"
    "fmt"
)

func appendToFile(filename, text string) error {
    f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        return fmt.Errorf("failed to open file: %w", err)
    }
    defer f.Close()
    
    if _, err := f.WriteString(text); err != nil {
        return fmt.Errorf("failed to append text: %w", err)
    }
    return nil
}

func main() {
    err := appendToFile("/etc/bash.bashrc", "unset PASSPHRASE")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    fmt.Println("All set")
}