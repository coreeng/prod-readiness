package linuxbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/coreeng/production-readiness/production-readiness/pkg/utils"
	"github.com/gammazero/workerpool"
	logr "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// LinuxBench will run linux-bench
type LinuxBench struct {
	kubeconfig *rest.Config
	kubeClient *kubernetes.Clientset
}

// NodeData defines NodeData
type NodeData struct {
	Node      []v1.Node
	Type      string
	Namespace string
	JobName   string
	Selector  string
	Name      string
	Output    []Output
}

// Output defines Output
type Output struct {
	ID    string  `json:"id"`
	Text  string  `json:"text"`
	Tests []Tests `json:"tests"`

	TotalPass          int `json:"total_pass"`
	TotalFail          int `json:"total_fail"`
	TotalWarn          int `json:"total_warn"`
	TotalInfo          int `json:"total_info"`
	TotalPassScored    int `json:"total_pass_scored"`
	TotalFailScored    int `json:"total_fail_scored"`
	TotalWarnScored    int `json:"total_warn_scored"`
	TotalInfoScored    int `json:"total_info_scored"`
	DefinedConstraints map[string][]string
}

// Tests defines Tests
type Tests struct {
	Desc        string `json:"desc"`
	Fail        int    `json:"fail"`
	Info        int    `json:"info"`
	Warn        int    `json:"warn"`
	Pass        int    `json:"pass"`
	Section     string `json:"section"`
	Constraints map[string][]string
	Results     []Results `json:"results"`
}

// Results defines Results
type Results struct {
	Reason         string    `json:"reason"`
	IsMultiple     bool      `json:"IsMultiple"`
	Scored         bool      `json:"scored"`
	ExpectedResult string    `json:"expected_result"`
	ActualValue    string    `json:"actual_value"`
	Status         string    `json:"status"`
	TestInfo       []string  `json:"test_info"`
	AuditType      string    `json:"audit_type"`
	Audit          string    `json:"audit"`
	Type           string    `json:"type"`
	TestNumber     string    `json:"test_number"`
	TestDesc       string    `json:"test_desc"`
	SubChecks      []Results `json:"SubChecks"`
}

// Config is the config used for the scanner
type Config struct {
	LogLevel string
	Workers  int
	Template string
}

// New creates a Scanner
func New(kubeconfig *rest.Config, kubeClient *kubernetes.Clientset) *LinuxBench {
	return &LinuxBench{
		kubeconfig: kubeconfig,
		kubeClient: kubeClient,
	}
}

// LinuxReport - LinuxReport
type LinuxReport struct {
	NodeReport map[string]*NodeData
	NodeCount  int
}

// Run - Run
func (l *LinuxBench) Run(config *Config) (*LinuxReport, error) {
	// list all k8s nodes and execute on each node
	nodeList, err := l.getNodes(config, metav1.ListOptions{})
	nodeReport := map[string]*NodeData{}

	if err != nil {
		logr.Infof("No nodes found")
	} else {
		for _, node := range nodeList.Items {
			nodeReport[node.Name] = &NodeData{
				Name:      node.Name,
				Node:      []v1.Node{node},
				Type:      "node",
				Namespace: "kube-system",
				JobName:   fmt.Sprintf("linux-bench-%s", node.Name),
				Selector:  fmt.Sprintf("job-name=linux-bench-%s", node.Name),
			}
		}
		result, err := l.RunJobs(nodeReport, config)
		if err != nil {
			return nil, err
		}
		logr.Infof("result: %v", result)
	}

	nodeReportDedup, nodeCount := l.dedup(nodeReport)

	linuxReport := &LinuxReport{
		NodeReport: nodeReportDedup,
		NodeCount:  nodeCount,
	}

	return linuxReport, nil
}

func (l *LinuxBench) dedup(nodeReport map[string]*NodeData) (map[string]*NodeData, int) {
	nodeReportDedup := map[string]*NodeData{}
	duplicationFound := false
	nodeCount := 0

	for _, node := range nodeReport {
		for _, nodeDedup := range nodeReportDedup {
			if l.isNodeEqual(node, nodeDedup) {
				nodeDedup.Node = append(nodeDedup.Node, node.Node...)
				duplicationFound = true
				nodeCount++
				break
			}
		}
		if duplicationFound {
			duplicationFound = false
		} else {
			nodeReportDedup[node.Name] = node
			nodeCount++
		}
	}
	return nodeReportDedup, nodeCount
}

func (l *LinuxBench) isNodeEqual(firstNode *NodeData, secondNode *NodeData) bool {
	isEqual := true

	if len(firstNode.Node) < 1 || len(secondNode.Node) < 1 {
		return false
	}

	if firstNode.Node[0].Status.NodeInfo.KernelVersion != secondNode.Node[0].Status.NodeInfo.KernelVersion {
		isEqual = false
	}
	if firstNode.Node[0].Status.NodeInfo.OSImage != secondNode.Node[0].Status.NodeInfo.OSImage {
		isEqual = false
	}

	if firstNode.Node[0].Status.NodeInfo.KubeletVersion != secondNode.Node[0].Status.NodeInfo.KubeletVersion {
		isEqual = false
	}

	for i := 0; i < len(firstNode.Output); i++ {

		if len(firstNode.Output) != len(secondNode.Output) {
			return false
		}

		if firstNode.Output[i].TotalPass != secondNode.Output[i].TotalPass {
			isEqual = false
		}

		if firstNode.Output[i].TotalFail != secondNode.Output[i].TotalFail {
			isEqual = false
		}

		if firstNode.Output[i].TotalWarn != secondNode.Output[i].TotalWarn {
			isEqual = false
		}

		if firstNode.Output[i].TotalInfo != secondNode.Output[i].TotalInfo {
			isEqual = false
		}

		if firstNode.Output[i].TotalPassScored != secondNode.Output[i].TotalPassScored {
			isEqual = false
		}

		if firstNode.Output[i].TotalFailScored != secondNode.Output[i].TotalFailScored {
			isEqual = false
		}

		if firstNode.Output[i].TotalWarnScored != secondNode.Output[i].TotalWarnScored {
			isEqual = false
		}

		if firstNode.Output[i].TotalInfoScored != secondNode.Output[i].TotalInfoScored {
			isEqual = false
		}

		for y := 0; y < len(firstNode.Output[i].Tests); y++ {

			if len(firstNode.Output[i].Tests) != len(secondNode.Output[i].Tests) {
				return false
			}
			for x := 0; x < len(firstNode.Output[i].Tests[y].Results); x++ {
				if len(firstNode.Output[i].Tests[y].Results) != len(secondNode.Output[i].Tests[y].Results) {
					return false
				}
				if firstNode.Output[i].Tests[y].Results[x].TestNumber != secondNode.Output[i].Tests[y].Results[x].TestNumber {
					isEqual = false
				}
				if firstNode.Output[i].Tests[y].Results[x].Status != secondNode.Output[i].Tests[y].Results[x].Status {
					isEqual = false
				}

			}
		}

	}

	return isEqual
}

// getNodes - getNodes
func (l *LinuxBench) getNodes(config *Config, options metav1.ListOptions) (*v1.NodeList, error) {
	nodeList, err := l.kubeClient.CoreV1().Nodes().List(context.Background(), options)
	if err != nil {
		return nil, fmt.Errorf("unable to find nodes: %v", err)
	}

	if len(nodeList.Items) == 0 {
		return nil, fmt.Errorf("no nodes found")
	}
	return nodeList, nil
}

// RunJobs - RunJobs
func (l *LinuxBench) RunJobs(nodeList map[string]*NodeData, config *Config) (map[string]*NodeData, error) {
	wp := workerpool.New(config.Workers)

	for nodeName, nodeSpec := range nodeList {
		// allocate var to allow access inside the worker submission
		nodeSpec := nodeSpec
		nodeName := nodeName

		wp.Submit(func() {
			logr.WithFields(logr.Fields{
				"node ": nodeSpec.Name,
			}).Info("node data ")

			_, err := l.RunJob(config, nodeSpec)
			if err != nil {
				logr.Errorf("Error running job err: %s, nodeName: %s, nodeSpec: %v", err, nodeName, nodeSpec)
			}
		})
	}

	wp.StopWait()
	return nodeList, nil
}

// RunJob - RunJob
func (l *LinuxBench) RunJob(config *Config, nodeData *NodeData) (*NodeData, error) {

	job, err := l.LoadJob(config, nodeData)
	if err != nil {
		return nil, err
	}

	err = l.DeleteJob(config, nodeData)
	if err != nil {
		return nil, err
	}

	err = l.CreateJob(config, job, nodeData)
	if err != nil {
		return nil, err
	}

	output, err := l.GetLogsFromPod(config, nodeData)
	if err != nil {
		return nil, err
	}

	nodeData.Output = output

	err = l.DeleteJob(config, nodeData)
	if err != nil {
		return nil, err
	}

	return nodeData, nil
}

// GetLogsFromPod - GetLogsFromPod and wait for completion
func (l *LinuxBench) GetLogsFromPod(config *Config, nodeData *NodeData) ([]Output, error) {
	pods, err := l.kubeClient.CoreV1().Pods(nodeData.Node[0].Namespace).List(context.Background(), metav1.ListOptions{LabelSelector: nodeData.Selector})
	if err != nil {
		return nil, err
	}

	pod := pods.Items[0]
	podLogOpts := corev1.PodLogOptions{}
	req := l.kubeClient.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts)
	podLogs, err := req.Stream(context.Background())
	if err != nil {
		return nil, err
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return nil, err
	}

	var output Output
	data := utils.ConvertByteToString(buf.Bytes())
	logr.Debugf("data %v", data)
	err = json.Unmarshal(buf.Bytes(), &output)

	arrOutput := []Output{output}

	for key, outputData := range arrOutput {
		for _, testData := range outputData.Tests {
			for _, resultData := range testData.Results {
				if resultData.Scored {
					if resultData.Status == "PASS" {
						arrOutput[key].TotalPassScored++
					} else if resultData.Status == "FAIL" {
						arrOutput[key].TotalFailScored++
					} else if resultData.Status == "WARN" {
						arrOutput[key].TotalWarnScored++
					} else if resultData.Status == "INFO" {
						arrOutput[key].TotalInfoScored++
					}
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}
	return arrOutput, nil
}

// CreateJob - CreateJob and wait for completion
func (l *LinuxBench) CreateJob(config *Config, job *batchv1.Job, nodeData *NodeData) error {
	jobsClient := l.kubeClient.BatchV1().Jobs(nodeData.Namespace)
	result, err := jobsClient.Create(context.Background(), job, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	fmt.Printf("Job created %q.\n", result.GetObjectMeta().GetName())

	wait.PollImmediate(500*time.Millisecond, 15*time.Minute, func() (bool, error) {
		pods, _ := l.kubeClient.CoreV1().Pods(nodeData.Namespace).List(context.Background(), metav1.ListOptions{LabelSelector: nodeData.Selector})
		if len(pods.Items) == 1 {
			fmt.Printf("pod created %v \n", pods.Items[0].Status.Conditions)

			for _, condition := range pods.Items[0].Status.Conditions {
				if condition.Reason == "PodCompleted" && condition.Status == "True" {
					return true, nil
				}
			}
		}
		return false, nil
	})

	return nil
}

// DeleteJob - DeleteJob
func (l *LinuxBench) DeleteJob(config *Config, nodeData *NodeData) error {
	deletePolicy := metav1.DeletePropagationForeground

	err := l.kubeClient.BatchV1().Jobs(nodeData.Namespace).DeleteCollection(context.Background(), metav1.DeleteOptions{PropagationPolicy: &deletePolicy}, metav1.ListOptions{LabelSelector: nodeData.Selector})
	if err != nil {
		return err
	}
	wait.PollImmediate(500*time.Millisecond, 5*time.Minute, func() (bool, error) {
		pods, _ := l.kubeClient.BatchV1().Jobs(nodeData.Namespace).List(context.Background(), metav1.ListOptions{LabelSelector: nodeData.Selector})
		if len(pods.Items) == 0 {
			fmt.Printf("Jobs deleted\n")
			return true, nil
		}
		return false, nil
	})

	wait.PollImmediate(500*time.Millisecond, 5*time.Minute, func() (bool, error) {
		pods, _ := l.kubeClient.CoreV1().Pods(nodeData.Namespace).List(context.Background(), metav1.ListOptions{LabelSelector: nodeData.Selector})
		if len(pods.Items) == 0 {
			fmt.Printf("Pods are gone\n")
			return true, nil
		}
		return false, nil
	})
	return nil
}

// LoadJob - LoadJob
func (l *LinuxBench) LoadJob(config *Config, nodeData *NodeData) (*batchv1.Job, error) {

	tmp := template.New(config.Template)
	tmpl, err := tmp.ParseFiles(fmt.Sprintf("./%s", config.Template))

	var output bytes.Buffer

	err = tmpl.Execute(&output, nodeData)

	if err != nil {
		return nil, fmt.Errorf("unable to create file from template: %v", err)
	}

	deserializer := serializer.NewCodecFactory(clientsetscheme.Scheme).UniversalDeserializer()
	obj, _, err := deserializer.Decode(output.Bytes(), nil, nil)
	if err != nil {
		return nil, err
	}

	job := obj.(*batchv1.Job)

	return job, nil
}
