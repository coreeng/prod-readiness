//go:build tools
// +build tools

package tools

import (
	_ "github.com/onsi/ginkgo/v2"
	_ "golang.org/x/lint/golint"
	_ "golang.org/x/tools/cmd/goimports"
	_ "sigs.k8s.io/kind"
)
