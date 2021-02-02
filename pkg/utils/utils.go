package utils

import (
	"encoding/json"

	logr "github.com/sirupsen/logrus"
)

// ConvertByteToString - defines ConvertByteToString
func ConvertByteToString(data []byte) string {
	return string(data[:])
}

// ConvertByteToStruct - defines ConvertByteToStruct
func ConvertByteToStruct(data []byte) []map[string]interface{} {

	jsonMap := []map[string]interface{}{}

	errUnmarshal := json.Unmarshal(data, &jsonMap)
	if errUnmarshal != nil {
		logr.WithFields(logr.Fields{
			"errUnmarshal": errUnmarshal,
			"dataAsString": ConvertByteToString(data),
		}).Debugf("errUnmarshal")
	} else {
		logr.WithFields(logr.Fields{
			"jsonMap": jsonMap,
		}).Debugf("jsonMap")
	}

	return jsonMap
}
