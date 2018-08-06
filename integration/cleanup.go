/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package integration

import (
	integration_util "github.com/grafeas/kritis/pkg/kritis/integration_util"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"os/exec"
	"testing"
)

func deleteFromFile(t *testing.T, path string, shouldSucceed bool) {
	cmd := exec.Command("kubectl", "delete", "-f", path)
	cmd.Dir = "../"
	output, err := integration_util.RunCmdOut(cmd)
	if shouldSucceed && err != nil {
		t.Fatalf("kritis: %s %v", output, err)
	}
}

func deleteObject(object, name string, ns *v1.Namespace) {
	deleteCmd := exec.Command("kubectl", "delete", object, name)
	if ns != nil {
		deleteCmd.Args = append(deleteCmd.Args, []string{"-n", ns.Name}...)
	}
	_, err := integration_util.RunCmdOut(deleteCmd)
	if err != nil {
		logrus.Errorf("error deleting %s %s in namespace %s: %v", object, name, ns.Name, err)
	}
}
