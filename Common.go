package util

import (
	"reflect"
)

func StructToMap(structObj interface{}) map[string]interface{} {
	resMap := make(map[string]interface{})
	t := reflect.TypeOf(structObj)
	v := reflect.ValueOf(structObj)
	for i := 0; i < t.NumField(); i++ {
		resMap[t.Field(i).Name] = v.Field(i).Interface()
	}
	return resMap
}
