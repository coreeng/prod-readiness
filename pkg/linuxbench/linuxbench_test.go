package linuxbench

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "LinuxBench Suite")
}

var _ = Describe("LinuxBench Images", func() {

	// var (
	// 	linuxbench *LinuxBench
	// )

	// BeforeEach(func() {
	// 	linuxbench = &LinuxBench{}
	// })

})
