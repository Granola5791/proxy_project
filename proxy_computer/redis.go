package main

import (
	"fmt"
	"log"
	"strings"

	"time"

	"github.com/go-redis/redis"
)

var redisClient *redis.Client

func InitRedisClient() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     GetEnv("REDIS_ADDR"),
		Password: GetEnv("REDIS_PASSWORD"),
		DB:       0, // use default DB
	})
}

func RedisGet(key string) (string, error) {
	return redisClient.Get(key).Result()
}

// RedisSet sets a key-value pair in Redis.
// if ttl is 0, it will not expire.
func RedisSet(key string, value string, ttl time.Duration) error {
	return redisClient.Set(key, value, ttl).Err()
}

func RedisDel(key string) error {
	return redisClient.Del(key).Err()
}

func RedisSetTTL(key string, ttl time.Duration) (bool, error) {
	return redisClient.Expire(key, ttl).Result()
}

func RedisSetTTLAt(key string, ttl time.Time) (bool, error) {
	return redisClient.ExpireAt(key, ttl).Result()
}

func RedisSubscribe(channel string) *redis.PubSub {
	return redisClient.Subscribe(channel)
}

func RedisSetNotifyOnExpire(key string) error {
	return redisClient.ConfigSet(
		GetStringFromConfig("redis.redis_expressions.notify_on_event"),
		GetStringFromConfig("redis.redis_expressions.expired_events"),
	).Err()
}

func RedisCreateQueueInRange(key string, start int, end int) error {
	pipe := redisClient.Pipeline()
	for i := start; i <= end; i++ {
		err := pipe.LPush(key, i).Err()
		if err != nil {
			return err
		}
	}
	_, err := pipe.Exec()
	return err
}

func RedisEnqueue(key string, value string) error {
	return redisClient.LPush(key, value).Err()
}

func RedisDequeue(key string) (string, error) {
	return redisClient.RPop(key).Result()
}

func IsPortKey(key string) bool {
	return strings.HasPrefix(key, GetStringFromConfig("redis.ip_key_prefix"))
}

func GetAvailablePort() (string, error) {
	return RedisDequeue(GetStringFromConfig("redis.available_ports_queue_name"))
}

func InitAvailablePortsQueue() error {
	return RedisCreateQueueInRange(
		GetStringFromConfig("redis.available_ports_queue_name"),
		GetIntFromConfig("redis.first_available_port"),
		GetIntFromConfig("redis.last_available_port"),
	)
}

func HandleAvailablePorts() {
	pubsub := RedisSubscribe(GetStringFromConfig("redis.redis_expressions.expired_keys_channel"))
	ch := pubsub.Channel()
	for msg := range ch {
		go HandleExpiredKey(msg.Payload)
	}
}

func HandleExpiredKey(key string) {
	if !IsPortKey(key) {
		return
	}
	RedisEnqueue(GetStringFromConfig("redis.available_ports_queue_name"), key)
}

func InitRedis() {
	InitRedisClient()
	err := InitAvailablePortsQueue()
	if err != nil {
		panic(err)
	}
	go HandleAvailablePorts()
}

func RedisPrintAllKeys() {
	var cursor uint64
	for {
		keys, nextCursor, err := redisClient.Scan(cursor, "*", 100).Result()
		if err != nil {
			log.Fatal(err)
		}

		for _, key := range keys {
			fmt.Println(key)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}
