package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"
)

var xSiteScriptingFileTypes = []string{".html", ".js"}

const crossSiteScripting = "Cross Site Scripting"
const sensitiveData = "Sensitive Data"
const sqlInjection = "SQL Injection"

var xSiteScriptingRegex = regexp.MustCompile(`Alert()`)
var sensitiveDataRegex = regexp.MustCompile(`.*Checkmarx.*Hellman & Friedman.*\$1\.15b.*`)
var sqlInjectionRegex = regexp.MustCompile(`.*\".*SELECT.*WHERE.*%s.*\".*`)

func main() {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Insert path to file/directory: ")
	path, _ := reader.ReadString('\n')
	fmt.Print("Select format for report (txt/json): ")
	exportFormat, _ := reader.ReadString('\n')
	path = strings.TrimSpace(path)
	exportFormat = strings.TrimSpace(exportFormat)
	report := scanDir(path, []Vulnerability{})

	if strings.EqualFold(exportFormat, "JSON") {
		exportJsonReport(report)
	} else if strings.EqualFold(exportFormat, "TXT") {
		exportPlainTextReport(report)
	} else {
		panic("Bad format. Shutting down...")
	}
}

func scanDir(path string, vulnerabilities []Vulnerability) []Vulnerability {
	files, err := ioutil.ReadDir(path)
	check(err)
	for _, file := range files {
		if file.IsDir() {
			vulnerabilities = append(vulnerabilities, scanDir(path+`\`+file.Name(), []Vulnerability{})...)
		} else {
			vulnerabilities = append(vulnerabilities, scanFile(file, path+`\`)...)
		}
	}
	return vulnerabilities
}

func scanFile(file os.FileInfo, pathToFile string) []Vulnerability {
	content, err := os.ReadFile(pathToFile + file.Name())
	check(err)
	split := strings.Split(string(content), "\n")

	isXSiteScriptable := false
	for _, filetype := range xSiteScriptingFileTypes {
		if strings.HasSuffix(file.Name(), filetype) {
			isXSiteScriptable = true
		}
	}

	fileVulnerabilities := []Vulnerability{}
	for lineNr, lineContent := range split {
		if isXSiteScriptable && xSiteScriptingRegex.Match([]byte(lineContent)) {
			fileVulnerabilities = append(fileVulnerabilities, Vulnerability{Kind: crossSiteScripting, Filename: file.Name(), Line: lineNr + 1})
		}
		if sensitiveDataRegex.Match([]byte(lineContent)) {
			fileVulnerabilities = append(fileVulnerabilities, Vulnerability{Kind: sensitiveData, Filename: file.Name(), Line: lineNr + 1})
		}
		if sqlInjectionRegex.Match([]byte(lineContent)) {
			fileVulnerabilities = append(fileVulnerabilities, Vulnerability{Kind: sqlInjection, Filename: file.Name(), Line: lineNr + 1})
		}
	}

	return fileVulnerabilities
}

func exportPlainTextReport(vulnerabilities []Vulnerability) {
	var text string
	for _, v := range vulnerabilities {
		text += v.toPlainText()
	}
	writeFile(text, "txt")
}

func exportJsonReport(vulnerabilities []Vulnerability) {
	b, err := json.Marshal(vulnerabilities)
	check(err)
	writeFile(string(b), "json")
}

func writeFile(text string, format string) {
	data := []byte(text)
	filename := "SCS-" + time.Now().Format("01_02_2006_15_04_05") + `.` + format
	err := ioutil.WriteFile(filename, data, 0)
	check(err)
	fmt.Println("Exported file: " + filename)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (v *Vulnerability) toPlainText() string {
	return fmt.Sprintf("[%s] in file %s on line %d\n", v.Kind, v.Filename, v.Line)
}

type Vulnerability struct {
	Kind     string `json:"type"`
	Filename string `json:"filename"`
	Line     int    `json:"line"`
}
