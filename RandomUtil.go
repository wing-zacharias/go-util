package util

import (
	"math/rand"
	"time"
)

func StringSliceRandom(slice []string, num int) []string {
	oldSlice := slice
	var res []string
	rand.Seed(time.Now().Unix())
	for i := 0; i < num; i++ {
		index := rand.Intn(len(oldSlice))
		res = append(res, oldSlice[index])
		oldSlice = append(oldSlice[:index], oldSlice[index+1:]...)
	}
	return res
}
