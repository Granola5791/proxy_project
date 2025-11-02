package main

import (
	"fmt"

	"github.com/go-redis/redis"
	"time"
)

var redisClient *redis.Client

func InitRedisClient() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     GetEnv("REDIS_ADDR"),
		Password: GetEnv("REDIS_PASSWORD"),
		DB:       0, // use default DB
	})
	fmt.Println("password: ", GetEnv("REDIS_PASSWORD"))
}

func RedisGet(key string) (string, error) {
	return redisClient.Get(key).Result()
}

func RedisSet(key string, value string) error {
	return redisClient.Set(key, value, 0).Err()
}

func RedisDel(key string) error {
	return redisClient.Del(key).Err()
}

func RedisSetTTL(key string, ttl time.Duration) error {
	return redisClient.Expire(key, ttl).Err()
}