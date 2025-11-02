package main

import (
	"github.com/joho/godotenv"
	"os"
)

func InitEnv() error {
	err := godotenv.Load(".env")
	if err != nil {
		return err
	}
	return nil
}

func GetEnv(key string) string {
	return os.Getenv(key)
}