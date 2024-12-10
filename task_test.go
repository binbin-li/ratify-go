/*
Copyright The Ratify Authors.
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

package ratify

import (
	"testing"
)

func TestGetReport(t *testing.T) {
	validationReport := &ValidationReport{}
	subjectReport := newSubjectReport(validationReport)

	report := subjectReport.GetReport()
	if report != validationReport {
		t.Errorf("Expected report to be %v, got %v", validationReport, report)
	}
}

func TestAddNestedArtifactReports(t *testing.T) {
	subjectReport := newSubjectReport(nil)

	nestedReport := &policyenforcer.ArtifactValidationReport{}
	subjectReport.AddNestedArtifactReports([]*policyenforcer.ArtifactValidationReport{nestedReport})

	report := subjectReport.GetReport()
	if len(report.NestedArtifactReports) != 1 {
		t.Errorf("Expected 1 nested report, got %d", len(report.NestedArtifactReports))
	}
	if report.NestedArtifactReports[0] != nestedReport {
		t.Errorf("Expected nested report to be %v, got %v", nestedReport, report.NestedArtifactReports[0])
	}
}
