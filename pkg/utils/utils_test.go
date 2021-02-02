package utils

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Utils Suite")
}

var _ = Describe("Utils tests", func() {

	It("Can convert bytes to map", func() {
		stringAsByte := []byte("[{\"sample\":\"sample\"}]")
		dataMap := []map[string]interface{}{}

		mp1 := map[string]interface{}{
			"sample": "sample",
		}
		dataMap = append(dataMap, mp1)

		valueAsString := ConvertByteToStruct(stringAsByte)

		Expect(valueAsString).To(Equal(dataMap))
	})

	It("Can convert bytes to string", func() {
		stringAsByte := []byte("sample")

		valueAsString := ConvertByteToString(stringAsByte)

		Expect(valueAsString).To(Equal("sample"))
	})

})
