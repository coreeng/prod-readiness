package test

import (
	"fmt"

	"github.com/coreeng/production-readiness/production-readiness/pkg/scanner"
	"github.com/onsi/gomega/types"
)

func BeOrderedByHighestSeverity() types.GomegaMatcher {
	return &beOrderBySeverity{map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}}
}

type beOrderBySeverity struct {
	wantedPosition map[string]int
}

func (m *beOrderBySeverity) Match(actual interface{}) (success bool, err error) {
	vulnerabilities := actual.([]scanner.Vulnerabilities)

	for i := 0; i < len(vulnerabilities)-1; i++ {
		itemPosition := m.wantedPosition[vulnerabilities[i].Severity]
		nextItemPosition := m.wantedPosition[vulnerabilities[i+1].Severity]
		if nextItemPosition < itemPosition {
			return false, nil
		}
	}
	return true, nil
}

func (m *beOrderBySeverity) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected: vulnerabilities to be ordered according to position: %v. \nActual order: %v", m.wantedPosition, actual)
}

func (m *beOrderBySeverity) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Expected: vulnerabilities not to be ordered according to position: %v. \nActual order: %v", m.wantedPosition, actual)
}
