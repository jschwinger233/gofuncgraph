package log

import (
	"log"
	"math/rand"
	"time"
)

func Debug(format string, v ...interface{}) {
	time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
}

func Fatal(v ...interface{}) {
	log.Fatal(v...)
}
