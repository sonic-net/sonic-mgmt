package testhelper

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	log "github.com/golang/glog"
)

var (
	writeToFile = func(filePath string, result string) error {
		return os.WriteFile(filePath, []byte(result), 0644)
	}
	getFromEnv = func(varName string) string {
		return os.Getenv(varName)
	}
)

// ArtifactAbsPath returns the absolute path for a file in the artifact directory.
func ArtifactAbsPath(fileName string) (string, error) {
	outputDirPath := "TEST_UNDECLARED_OUTPUTS_DIR"
	outputDir := getFromEnv(outputDirPath)
	if outputDir == "" {
		return "", fmt.Errorf("undeclared TEST_UNDECLARED_OUTPUTS_DIR in env, expected to be set")
	}
	return path.Join(outputDir, fileName), nil
}

// SaveToArtifact saves the given data to the artifact directory.
func SaveToArtifact(data, fp string) error {
	if fp == "" {
		return fmt.Errorf("file path is empty")
	}
	baseDir, err := ArtifactAbsPath("")
	if err != nil {
		return err
	}
	a := path.Join(baseDir, fp)
	if !strings.HasPrefix(a, baseDir) {
		return fmt.Errorf("file path %v is not inside artifact directory %v", fp, baseDir)
	}
	if err := os.MkdirAll(path.Dir(a), 0755); err != nil {
		return err
	}
	log.Infof("Saving to path: %s", a)
	if err := writeToFile(a, data); err != nil {
		return err
	}
	return nil
}

// Teardown performs the teardown routine after the test completion.
func (o TearDownOptions) Teardown(t *testing.T) {
	if o.configRestorer != nil {
		o.configRestorer.RestoreConfigsAndClose(t)
	}
        if t.Failed() {
		if o.SaveLogs != nil {
			o.SaveLogs(t, t.Name()+"_log", o.DUTDeviceInfo, o.DUTPeerDeviceInfo)
		}
	}
}
