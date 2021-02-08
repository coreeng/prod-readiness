package report

import (
	"encoding/json"
	"fmt"
	logr "github.com/sirupsen/logrus"
	"html/template"
	"os"
)

// GenerateMarkdown - GenerateMarkdown
func GenerateMarkdown(report interface{}, templateFilename string, filename string) error {
	logr.Infof("Generating mark-down based on template %s", templateFilename)
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
		return err
	}

	reportMarkdownFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create mark-down file %s: %v", filename, err)
	}

	err = tmpl.Execute(reportMarkdownFile, report)
	if err != nil {
		return err
	}
	logr.Infof("Generated mark-down file: %s", templateFilename)
	return nil
}

// SaveReport - SaveReport
func SaveReport(report interface{}, filename string) error {
	logr.Infof("Saving report to: %s", filename)

	// saving the ouput into a file
	reportJsonFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create report json file %s: %v", filename, err)
	}

	encoder := json.NewEncoder(reportJsonFile)
	err = encoder.Encode(report)
	if err != nil {
		logr.Errorf("Error encoding report to json %v", err)
		return err
	}

	logr.Infof("Report saved into: %s", filename)

	return nil
}
