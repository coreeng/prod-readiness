module github.com/coreeng/production-readiness/production-readiness

go 1.15

require (
	github.com/gammazero/workerpool v1.1.1
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/onsi/ginkgo v1.13.0
	github.com/onsi/gomega v1.10.1
	github.com/prometheus/client_golang v1.7.1
	github.com/sclevine/agouti v3.0.0+incompatible // indirect
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.0.0
	golang.org/x/lint v0.0.0-20190313153728-d0100b6bd8b3
	golang.org/x/sys v0.0.0-20210112080510-489259a85091 // indirect
	golang.org/x/tools v0.0.0-20201224043029-2b0845dc783e
	k8s.io/api v0.0.0-20190918195907-bd6ac527cfd2
	k8s.io/apimachinery v0.18.8
	k8s.io/client-go v11.0.1-0.20190409021438-1a26190bd76a+incompatible
	k8s.io/klog v1.0.0 // indirect
	k8s.io/utils v0.0.0-20201015054608-420da100c033 // indirect
	sigs.k8s.io/kind v0.9.0 // indirect
)

replace k8s.io/client-go => k8s.io/client-go v0.0.0-20190619194433-921a716ae8da

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20190416092415-3370b4aef5d6
