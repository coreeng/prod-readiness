package kubebench

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "KubeBench Suite")
}

var _ = Describe("KubeBench Images", func() {

	// var (
	// 	kubebench *KubeBench
	// )

	// BeforeEach(func() {
	// 	kubebench = &KubeBench{}
	// })

})
