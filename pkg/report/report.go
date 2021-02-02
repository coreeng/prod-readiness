package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"time"

	logr "github.com/sirupsen/logrus"
)

// GenerateMarkdown - GenerateMarkdown
func GenerateMarkdown(report interface{}, templateFilename string, filename string) (bool, error) {

	tmp := template.New(templateFilename)
	tmp.Funcs(template.FuncMap{
		"safe": func(s string) template.HTML { return template.HTML(s) },
	})
	tmp.Funcs(template.FuncMap{"inc": func(i int) int { return i + 1 }})
	tmp.Funcs(template.FuncMap{"mod": func(i, j int) bool { return i%j == 0 }})
	tmp.Funcs(template.FuncMap{"truncate": func(s string, i int) string {
		runes := []rune(s)
		if len(runes) > i {
			return fmt.Sprintf("%s...", string(runes[:i]))
		}
		return s
	}})
	tmp.Funcs(template.FuncMap{"modsub": func(index, tabSize, additional, modulo int) bool {

		if (index+additional)%modulo == 0 {
			return true
		}
		if additional == 1 {
			if (tabSize-1)-index == 0 {
				return true
			}
		}

		return false

	}})
	tmp.Funcs(template.FuncMap{"mods": func(index, additional, modulo int) bool {

		if (index+additional)%modulo == 0 {
			return true
		}

		return false

	}})
	tmpl, err := tmp.ParseFiles(templateFilename)

	if err != nil {
		return false, err
	}

	var output bytes.Buffer

	err = tmpl.Execute(&output, report)

	if err != nil {
		return false, fmt.Errorf("unable to create file from template: %v", err)
	}

	output.Bytes()
	return writeFile(filename, output.Bytes())
}

// SaveReport - SaveReport
func SaveReport(report interface{}, filename string) error {

	// saving the ouput into a file
	file, _ := json.MarshalIndent(report, "", " ")
	date := time.Now()
	dateFormatted := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d",
		date.Year(), date.Month(), date.Day(),
		date.Hour(), date.Minute(), date.Second())

	directory := "results"
	os.Mkdir(directory, 0755)

	filenameSaved := fmt.Sprintf("%s/%s_%s.json", directory, filename, dateFormatted)
	err := ioutil.WriteFile(filenameSaved, file, 0644)

	if err != nil {
		logr.Errorf("Error saving report %s", err)
		return err
	}

	logr.Infof("Report saved into: %s", filenameSaved)

	return nil
}

func writeFile(location string, contents []byte) (bool, error) {
	err := ioutil.WriteFile(location, contents, 0644)
	if err != nil {
		return false, err
	}
	return true, nil
}
