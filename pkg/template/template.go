package template

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	logr "github.com/sirupsen/logrus"
)

// GenerateReportFromTemplate - Generate the report based on the given template file
func GenerateReportFromTemplate(report interface{}, templateFilename string, reportOutputFilename string) error {
	logr.Infof("Generating report based on template %s", templateFilename)
	tmp := template.New(filepath.Base(templateFilename))
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
		return err
	}

	reportFile, err := os.Create(reportOutputFilename)
	if err != nil {
		return fmt.Errorf("could not create report file %s: %v", reportOutputFilename, err)
	}

	err = tmpl.Execute(reportFile, report)
	if err != nil {
		return err
	}
	logr.Infof("Generated report file: %s", templateFilename)
	return nil
}

// SaveReport - SaveReport
func SaveReport(report interface{}, filename string) error {
	logr.Infof("Saving report to: %s", filename)

	// saving the ouput into a file
	reportJSONFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create report json file %s: %v", filename, err)
	}

	encoder := json.NewEncoder(reportJSONFile)
	err = encoder.Encode(report)
	if err != nil {
		logr.Errorf("Error encoding report to json %v", err)
		return err
	}

	logr.Infof("Report saved into: %s", filename)

	return nil
}
