package main

import (
        "log"

        "github.com/spf13/viper"
)

func InitConfig() {
        viper.SetConfigName("constants")
        viper.SetConfigType("yaml")
        viper.AddConfigPath(".")
        err := viper.ReadInConfig()
        if err != nil {
                log.Fatalf("Error reading config file, %s", err)
        }
}

func GetIntFromConfig(key string) int {
        if viper.IsSet(key) {
                return viper.GetInt(key)
        }
        panic(viper.GetString("error.missing_config") + key)
}

func GetStringFromConfig(key string) string {
        if viper.IsSet(key) {
                return viper.GetString(key)
        }
        panic(viper.GetString("error.missing_config") + key)
}

func GetBoolFromConfig(key string) bool {
        if viper.IsSet(key) {
                return viper.GetBool(key)
        }
        panic(viper.GetString("error.missing_config") + key)
}

func GetFloat64FromConfig(key string) float64 {
        if viper.IsSet(key) {
                return viper.GetFloat64(key)
        }
        panic(viper.GetString("error.missing_config") + key)
}

func GetUint32FromConfig(key string) uint32 {
        if viper.IsSet(key) {
                return viper.GetUint32(key)
        }
        panic(viper.GetString("error.missing_config") + key)
}

func GetUint8FromConfig(key string) uint8 {
        if viper.IsSet(key) {
                return viper.GetUint8(key)
        }
        panic(viper.GetString("error.missing_config") + key)
}