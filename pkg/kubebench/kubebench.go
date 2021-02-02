package kubebench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"regexp"
	"time"

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

// KubeBench will run kube-bench
type KubeBench struct {
	kubeconfig *rest.Config
	kubeClient *kubernetes.Clientset
}

// Report define report
type Report struct {
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
	ID       string  `json:"id"`
	NodeType string  `json:"node_type"`
	Text     string  `json:"text"`
	Version  string  `json:"version"`
	Tests    []Tests `json:"tests"`

	TotalPass       int `json:"total_pass"`
	TotalFail       int `json:"total_fail"`
	TotalWarn       int `json:"total_warn"`
	TotalInfo       int `json:"total_info"`
	TotalPassScored int `json:"total_pass_scored"`
	TotalFailScored int `json:"total_fail_scored"`
	TotalWarnScored int `json:"total_warn_scored"`
	TotalInfoScored int `json:"total_info_scored"`
}

// Tests defines Tests
type Tests struct {
	Desc    string    `json:"desc"`
	Fail    int       `json:"fail"`
	Info    int       `json:"info"`
	Warn    int       `json:"warn"`
	Pass    int       `json:"pass"`
	Section string    `json:"section"`
	Results []Results `json:"results"`
}

// Results defines Results
type Results struct {
	AuditConfig    string   `json:"AuditConfig"`
	IsMultiple     bool     `json:"IsMultiple"`
	ActualValue    string   `json:"actual_value"`
	Audit          string   `json:"audit"`
	ExpectedResult string   `json:"expected_result"`
	Remediation    string   `json:"remediation"`
	Scored         bool     `json:"scored"`
	Status         string   `json:"status"`
	TestDesc       string   `json:"test_desc"`
	TestInfo       []string `json:"test_info"`
	TestNumber     string   `json:"test_number"`
	Type           string   `json:"type"`
}

// Config is the config used for the scanner
type Config struct {
	LogLevel string
	Workers  int
	Template string
}

// New creates a Scanner
func New(kubeconfig *rest.Config, kubeClient *kubernetes.Clientset) *KubeBench {
	return &KubeBench{
		kubeconfig: kubeconfig,
		kubeClient: kubeClient,
	}
}

// KubeReport - KubeReport
type KubeReport struct {
	NodeReport   map[string]*NodeData
	NodeCount    int
	MasterReport map[string]*NodeData
	MasterCount  int
}

// Run - Run
func (l *KubeBench) Run(config *Config) (*KubeReport, error) {

	// list all k8s master and execute on each node
	// node-role.kubernetes.io/apiserver
	// node-role.kubernetes.io/master
	options := metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/apiserver"}
	masterList, err := l.getNodes(config, options)
	masterReport := map[string]*NodeData{}

	if err != nil {
		// return err
		logr.Infof("No master found")
	} else {
		for _, masterNode := range masterList.Items {
			masterReport[masterNode.Name] = &NodeData{
				Name:      masterNode.Name,
				Node:      []v1.Node{masterNode},
				Type:      "master",
				Namespace: "kube-system",
				JobName:   fmt.Sprintf("kube-bench-%s", masterNode.Name),
				Selector:  fmt.Sprintf("job-name=kube-bench-%s", masterNode.Name),
			}
		}
		result, err := l.RunJobs(masterReport, config)
		if err != nil {
			return nil, err
		}
		logr.Infof("Master result %v", result)
	}

	// list all k8s nodes and execute on each node
	options = metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/kubernetes-node"}
	nodeList, err := l.getNodes(config, options)
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
				JobName:   fmt.Sprintf("kube-bench-%s", node.Name),
				Selector:  fmt.Sprintf("job-name=kube-bench-%s", node.Name),
			}
		}
		result, err := l.RunJobs(nodeReport, config)
		if err != nil {
			return nil, err
		}
		logr.Infof("result: %v", result)
	}

	nodeReportDedup, nodeCount := l.dedup(nodeReport)
	masterReportDedup, masterCount := l.dedup(masterReport)

	kubeReport := &KubeReport{
		NodeReport:   nodeReportDedup,
		NodeCount:    nodeCount,
		MasterReport: masterReportDedup,
		MasterCount:  masterCount,
	}

	return kubeReport, nil
}

func (l *KubeBench) dedup(nodeReport map[string]*NodeData) (map[string]*NodeData, int) {
	nodeReportDedup := map[string]*NodeData{}
	duplicationFound := false
	nodeCount := 0

	for _, node := range nodeReport {
		for _, nodeDedup := range nodeReportDedup {
			if l.isNodeEqual(node, nodeDedup) {
				// fmt.Println("Is Map 1 is equal to Map 2: ", res1)
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

func (l *KubeBench) isNodeEqual(firstNode *NodeData, secondNode *NodeData) bool {
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
func (l *KubeBench) getNodes(config *Config, options metav1.ListOptions) (*v1.NodeList, error) {
	nodeList, err := l.kubeClient.CoreV1().Nodes().List(options)
	if err != nil {
		return nil, fmt.Errorf("unable to find nodes: %v", err)
	}

	if len(nodeList.Items) == 0 {
		return nil, fmt.Errorf("no nodes found")
	}
	return nodeList, nil
}

// RunJobs - RunJobs
func (l *KubeBench) RunJobs(nodeList map[string]*NodeData, config *Config) (map[string]*NodeData, error) {
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
func (l *KubeBench) RunJob(config *Config, nodeData *NodeData) (*NodeData, error) {

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

	for key, outputData := range output {
		for _, testData := range outputData.Tests {
			for _, resultData := range testData.Results {
				if resultData.Scored {
					if resultData.Status == "PASS" {
						output[key].TotalPassScored++
					} else if resultData.Status == "FAIL" {
						output[key].TotalFailScored++
					} else if resultData.Status == "WARN" {
						output[key].TotalWarnScored++
					} else if resultData.Status == "INFO" {
						output[key].TotalInfoScored++
					}
				}
			}
		}
	}

	nodeData.Output = output

	err = l.DeleteJob(config, nodeData)
	if err != nil {
		return nil, err
	}

	return nodeData, nil
}

// GetLogsFromPod - GetLogsFromPod and wait for completion
func (l *KubeBench) GetLogsFromPod(config *Config, nodeData *NodeData) ([]Output, error) {
	pods, err := l.kubeClient.CoreV1().Pods(nodeData.Node[0].Namespace).List(metav1.ListOptions{LabelSelector: nodeData.Selector})
	if err != nil {
		return nil, err
	}

	fmt.Printf("%v\n", pods.Items[0])
	pod := pods.Items[0]
	podLogOpts := corev1.PodLogOptions{}
	req := l.kubeClient.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &podLogOpts)
	podLogs, err := req.Stream()
	if err != nil {
		return nil, err
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return nil, err
	}

	str := buf.String()

	// remove output before the array result, will remove everything before the first "["
	re := regexp.MustCompile(`^[^\[]*\[`)
	s := re.ReplaceAllString(str, "[")

	var output []Output
	data := []byte(s)
	err = json.Unmarshal(data, &output)

	if err != nil {
		return nil, err
	}
	return output, nil
}

// CreateJob - CreateJob and wait for completion
func (l *KubeBench) CreateJob(config *Config, job *batchv1.Job, nodeData *NodeData) error {
	jobsClient := l.kubeClient.BatchV1().Jobs(nodeData.Namespace)
	result, err := jobsClient.Create(job)
	if err != nil {
		return err
	}
	fmt.Printf("Job created %q.\n", result.GetObjectMeta().GetName())

	wait.PollImmediate(500*time.Millisecond, 5*time.Minute, func() (bool, error) {
		pods, _ := l.kubeClient.CoreV1().Pods(nodeData.Namespace).List(metav1.ListOptions{LabelSelector: nodeData.Selector})
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
func (l *KubeBench) DeleteJob(config *Config, nodeData *NodeData) error {
	deletePolicy := metav1.DeletePropagationForeground

	err := l.kubeClient.BatchV1().Jobs(nodeData.Namespace).DeleteCollection(&metav1.DeleteOptions{PropagationPolicy: &deletePolicy}, metav1.ListOptions{LabelSelector: nodeData.Selector})
	if err != nil {
		return err
	}
	wait.PollImmediate(500*time.Millisecond, 5*time.Minute, func() (bool, error) {
		pods, _ := l.kubeClient.BatchV1().Jobs(nodeData.Namespace).List(metav1.ListOptions{LabelSelector: nodeData.Selector})
		if len(pods.Items) == 0 {
			fmt.Printf("Jobs deleted\n")
			return true, nil
		}
		return false, nil
	})

	wait.PollImmediate(500*time.Millisecond, 5*time.Minute, func() (bool, error) {
		pods, _ := l.kubeClient.CoreV1().Pods(nodeData.Namespace).List(metav1.ListOptions{LabelSelector: nodeData.Selector})
		if len(pods.Items) == 0 {
			fmt.Printf("Pods are gone\n")
			return true, nil
		}
		return false, nil
	})
	return nil
}

// LoadJob - LoadJob
func (l *KubeBench) LoadJob(config *Config, nodeData *NodeData) (*batchv1.Job, error) {

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
	fmt.Printf("%#v\n", obj)

	job := obj.(*batchv1.Job)

	return job, nil
}
