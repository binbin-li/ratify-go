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
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testRepo       = "test-repo"
	testDigest1    = "sha256:1"
	testDigest2    = "sha256:2"
	testDigest3    = "sha256:3"
	testDigest4    = "sha256:4"
	testDigest5    = "sha256:5"
	testDigest6    = "sha256:6"
	testImage      = testRepo + "/v1"
	testArtifact2  = testRepo + "@sha256:2"
	testArtifact3  = testRepo + "@sha256:3"
	testArtifact4  = testRepo + "@sha256:4"
	invalidMessage = "invalid signature"
	validMessage1  = "valid signature 1"
	validMessage2  = "valid signature 2"
	validMessage3  = "valid signature 3"
	validMessage4  = "valid signature 4"
	validMessage5  = "valid signature 5"
	validMessage6  = "valid signature 6"
)

type mockVerifier struct {
	verifyResult map[string]VerifierResult
}

func (m *mockVerifier) VerifyArtifact(ctx context.Context, subjectRef common.Reference, referenceDesc oci.Descriptor, referrerStore ReferrerStore) ([]VerifierResult, error) {
	if m.verifyResult == nil {
		return []VerifierResult{}, errors.New("verify result not initialized")
	}
	if result, ok := m.verifyResult[referenceDesc.Digest.String()]; ok {
		return []VerifierResult{result}, nil
	}
	return []VerifierResult{}, nil
}

type mockStore struct {
	referrers map[string][]oci.Descriptor
}

func (m *mockStore) Name() string {
	return "mock-store-name"
}

func (m *mockStore) ListReferrers(ctx context.Context, subjectReference common.Reference, artifactTypes []string, nextToken string) (ListReferrersResult, error) {
	if m.referrers == nil {
		return ListReferrersResult{}, errors.New("referrers not initialized")
	}

	if _, ok := m.referrers[subjectReference.Digest.String()]; ok {
		return ListReferrersResult{
			NextToken: "",
			Referrers: m.referrers[subjectReference.Digest.String()],
		}, nil
	}

	return ListReferrersResult{}, nil
}

func (m *mockStore) GetBlobContent(ctx context.Context, subjectReference common.Reference, digest digest.Digest) ([]byte, error) {
	return nil, nil
}

func (m *mockStore) GetReferenceManifest(ctx context.Context, subjectReference common.Reference, referenceDesc oci.Descriptor) (oci.Manifest, error) {
	return oci.Manifest{}, nil
}

func (m *mockStore) GetSubjectDescriptor(ctx context.Context, subjectReference common.Reference) (oci.Descriptor, error) {
	return oci.Descriptor{}, nil
}

type mockPolicyEnforcer struct{}

func (m *mockPolicyEnforcer) ErrorToValidationResult(ctx context.Context, subjectReference string, verifyError error) ValidationResult {
	return ValidationResult{}
}

func (m *mockPolicyEnforcer) EvaluateValidationReports(ctx context.Context, validationReports []*ArtifactValidationReport) bool {
	return true
}

type mockResolver struct {
	tagToDigest map[string]common.Reference
}

func (m *mockResolver) Resolve(ctx context.Context, reference string) (common.Reference, error) {
	if m.tagToDigest == nil {
		return common.Reference{}, errors.New("artifact to reference not initialized")
	}
	if ref, ok := m.tagToDigest[reference]; ok {
		return ref, nil
	}

	return common.Reference{}, nil
}

func TestValidateArtifact(t *testing.T) {
	tests := []struct {
		name           string
		opts           ValidateArtifactOptions
		stores         []ReferrerStore
		verifier       artifactverifier.ArtifactVerifier
		policyEnforcer PolicyEnforcer
		resolver       resolver
		workerNumber   int
		want           ValidationResult
		wantErr        bool
	}{
		{
			name: "Policy Enforcer is not set",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
				ReferenceTypes:  []string{"referenceType"},
			},
			stores:         []ReferrerStore{&mockStore{}},
			verifier:       &mockVerifier{},
			policyEnforcer: nil,
			want:           ValidationResult{},
			wantErr:        true,
		},
		{
			name: "Invalid reference",
			opts: ValidateArtifactOptions{
				SubjectArtifact: "testRepo:v1",
				ReferenceTypes:  []string{"referenceType"},
			},
			stores:         []ReferrerStore{&mockStore{}},
			verifier:       &mockVerifier{},
			policyEnforcer: &mockPolicyEnforcer{},
			resolver:       &mockResolver{},
			want:           ValidationResult{},
			wantErr:        true,
		},
		{
			name: "Error happened when listing referrers",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			stores:   []ReferrerStore{&mockStore{}},
			verifier: &mockVerifier{},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
					},
				},
			},
			policyEnforcer: &mockPolicyEnforcer{},
			want:           ValidationResult{},
			wantErr:        true,
		},
		{
			name: "No referrers attached to the artifact",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			stores: []ReferrerStore{&mockStore{
				referrers: map[string][]oci.Descriptor{},
			}},
			verifier: &mockVerifier{},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
					},
				},
			},
			policyEnforcer: &mockPolicyEnforcer{},
			want: ValidationResult{
				IsSuccess: true,
			},
			wantErr: false,
		},
		{
			name: "Error happened when verifier verifies the artifact",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			stores: []ReferrerStore{&mockStore{
				referrers: map[string][]oci.Descriptor{
					testDigest1: {
						oci.Descriptor{
							Digest: testDigest2,
						},
					},
				},
			}},
			verifier:       &mockVerifier{},
			policyEnforcer: &mockPolicyEnforcer{},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
					},
				},
			},
			want:    ValidationResult{},
			wantErr: true,
		},
		{
			name: "Verifier returned result with failure",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			stores: []ReferrerStore{&mockStore{
				referrers: map[string][]oci.Descriptor{
					testDigest1: {
						oci.Descriptor{
							Digest: testDigest2,
						},
					},
				},
			}},
			verifier: &mockVerifier{
				verifyResult: map[string]VerifierResult{
					testDigest2: {
						IsSuccess: false,
						Message:   invalidMessage,
					},
				},
			},
			policyEnforcer: &mockPolicyEnforcer{},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
					},
				},
			},
			want: ValidationResult{
				IsSuccess: true,
				ArtifactReports: []*ArtifactValidationReport{{
					VerifierReports: []VerifierResult{
						{
							IsSuccess: false,
							Message:   invalidMessage,
						},
					},
				}}},
			wantErr: false,
		},
		{
			name: "2-layer nested artifacts are verified successfully",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			stores: []ReferrerStore{&mockStore{
				referrers: map[string][]oci.Descriptor{
					testDigest1: {
						oci.Descriptor{
							Digest: testDigest2,
						},
						oci.Descriptor{
							Digest: testDigest3,
						},
					},
					testDigest2: {
						oci.Descriptor{
							Digest: testDigest4,
						},
					},
				},
			}},
			verifier: &mockVerifier{
				verifyResult: map[string]VerifierResult{
					testDigest2: {
						IsSuccess: true,
						Message:   validMessage2,
					},
					testDigest3: {
						IsSuccess: true,
						Message:   validMessage3,
					},
					testDigest4: {
						IsSuccess: true,
						Message:   validMessage4,
					},
				},
			},
			policyEnforcer: &mockPolicyEnforcer{},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
						Path:   testRepo,
					},
					testArtifact2: {
						Digest: testDigest2,
						Path:   testRepo,
					},
				},
			},
			want: ValidationResult{
				IsSuccess: true,
				ArtifactReports: []*ArtifactValidationReport{
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage3,
							},
						},
					},
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage2,
							},
						},
						NestedArtifactReports: []*ArtifactValidationReport{{
							VerifierReports: []VerifierResult{
								{
									IsSuccess: true,
									Message:   validMessage4,
								},
							},
						}},
					},
				}},
			wantErr: false,
		},
		{
			name: "2-layer nested artifacts are verified with single goroutine",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			workerNumber: 1,
			stores: []ReferrerStore{&mockStore{
				referrers: map[string][]oci.Descriptor{
					testDigest1: {
						oci.Descriptor{
							Digest: testDigest2,
						},
						oci.Descriptor{
							Digest: testDigest3,
						},
					},
					testDigest2: {
						oci.Descriptor{
							Digest: testDigest4,
						},
					},
				},
			}},
			verifier: &mockVerifier{
				verifyResult: map[string]VerifierResult{
					testDigest2: {
						IsSuccess: true,
						Message:   validMessage2,
					},
					testDigest3: {
						IsSuccess: true,
						Message:   validMessage3,
					},
					testDigest4: {
						IsSuccess: true,
						Message:   validMessage4,
					},
				},
			},
			policyEnforcer: &mockPolicyEnforcer{},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
						Path:   testRepo,
					},
					testArtifact2: {
						Digest: testDigest2,
						Path:   testRepo,
					},
				},
			},
			want: ValidationResult{
				IsSuccess: true,
				ArtifactReports: []*ArtifactValidationReport{
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage3,
							},
						},
					},
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage2,
							},
						},
						NestedArtifactReports: []*ArtifactValidationReport{{
							VerifierReports: []VerifierResult{
								{
									IsSuccess: true,
									Message:   validMessage4,
								},
							},
						}},
					},
				}},
			wantErr: false,
		},
		{
			name: "3-layer nested artifacts are verified",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			stores: []ReferrerStore{&mockStore{
				referrers: map[string][]oci.Descriptor{
					testDigest1: {
						oci.Descriptor{
							Digest: testDigest2,
						},
						oci.Descriptor{
							Digest: testDigest3,
						},
					},
					testDigest2: {
						oci.Descriptor{
							Digest: testDigest4,
						},
					},
					testDigest4: {
						oci.Descriptor{
							Digest: testDigest5,
						},
					},
				},
			}},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
						Path:   testRepo,
					},
					testArtifact2: {
						Digest: testDigest2,
						Path:   testRepo,
					},
					testArtifact4: {
						Digest: testDigest4,
						Path:   testRepo,
					},
				},
			},
			verifier: &mockVerifier{
				verifyResult: map[string]VerifierResult{
					testDigest2: {
						IsSuccess: true,
						Message:   validMessage2,
					},
					testDigest3: {
						IsSuccess: true,
						Message:   validMessage3,
					},
					testDigest4: {
						IsSuccess: true,
						Message:   validMessage4,
					},
					testDigest5: {
						IsSuccess: true,
						Message:   validMessage5,
					},
				},
			},
			policyEnforcer: &mockPolicyEnforcer{},
			want: ValidationResult{
				IsSuccess: true,
				ArtifactReports: []*ArtifactValidationReport{
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage3,
							},
						},
					},
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage2,
							},
						},
						NestedArtifactReports: []*ArtifactValidationReport{{
							VerifierReports: []VerifierResult{
								{
									IsSuccess: true,
									Message:   validMessage4,
								},
							},
							NestedArtifactReports: []*ArtifactValidationReport{{
								VerifierReports: []VerifierResult{
									{
										IsSuccess: true,
										Message:   validMessage5,
									},
								}}},
						}},
					},
				}},
			wantErr: false,
		},
		{
			name: "3-layer nested artifacts are verified in single goroutine",
			opts: ValidateArtifactOptions{
				SubjectArtifact: testImage,
			},
			workerNumber: 1,
			stores: []ReferrerStore{&mockStore{
				referrers: map[string][]oci.Descriptor{
					testDigest1: {
						oci.Descriptor{
							Digest: testDigest2,
						},
						oci.Descriptor{
							Digest: testDigest3,
						},
						oci.Descriptor{
							Digest: testDigest6,
						},
					},
					testDigest2: {
						oci.Descriptor{
							Digest: testDigest4,
						},
					},
					testDigest4: {
						oci.Descriptor{
							Digest: testDigest5,
						},
					},
				},
			}},
			resolver: &mockResolver{
				tagToDigest: map[string]common.Reference{
					testImage: {
						Digest: testDigest1,
						Path:   testRepo,
					},
					testArtifact2: {
						Digest: testDigest2,
						Path:   testRepo,
					},
					testArtifact4: {
						Digest: testDigest4,
						Path:   testRepo,
					},
				},
			},
			verifier: &mockVerifier{
				verifyResult: map[string]VerifierResult{
					testDigest2: {
						IsSuccess: true,
						Message:   validMessage1,
					},
					testDigest3: {
						IsSuccess: true,
						Message:   validMessage3,
					},
					testDigest4: {
						IsSuccess: true,
						Message:   validMessage4,
					},
					testDigest5: {
						IsSuccess: true,
						Message:   validMessage5,
					},
					testDigest6: {
						IsSuccess: true,
						Message:   validMessage6,
					},
				},
			},
			policyEnforcer: &mockPolicyEnforcer{},
			want: ValidationResult{
				IsSuccess: true,
				ArtifactReports: []*ArtifactValidationReport{
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage3,
							},
						},
					},
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage6,
							},
						},
					},
					{
						VerifierReports: []VerifierResult{
							{
								IsSuccess: true,
								Message:   validMessage1,
							},
						},
						NestedArtifactReports: []*ArtifactValidationReport{{
							VerifierReports: []VerifierResult{
								{
									IsSuccess: true,
									Message:   validMessage4,
								},
							},
							NestedArtifactReports: []*ArtifactValidationReport{{
								VerifierReports: []VerifierResult{
									{
										IsSuccess: true,
										Message:   validMessage5,
									},
								}}},
						}},
					},
				}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workerNumber := defaultWorkerNumber
			if tt.workerNumber > 0 {
				workerNumber = tt.workerNumber
			}
			executor := &DefaultExecutor{
				Stores:         tt.stores,
				PolicyEnforcer: tt.policyEnforcer,
				verifier:       tt.verifier,
				tagResolver:    tt.resolver,
				config:         &NewExecutorOptions{WorkerNumber: workerNumber},
			}
			got, err := executor.ValidateArtifact(context.Background(), tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !sameValidationResult(&got, &tt.want) {
				t.Errorf("ValidateArtifact() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDefaultExecutor(t *testing.T) {
	executor := NewDefaultExecutor(NewExecutorOptions{}, []ReferrerStore{&mockStore{}}, []Verifier{}, &mockPolicyEnforcer{})

	defaultExecutor, ok := executor.(*DefaultExecutor)
	if !ok {
		t.Fatalf("NewDefaultExecutor() did not return a DefaultExecutor")
	}

	if defaultExecutor.config.WorkerNumber != defaultWorkerNumber {
		t.Errorf("NewDefaultExecutor() default worker number = %v, want %v", defaultExecutor.config.WorkerNumber, defaultWorkerNumber)
	}
}

func sameValidationResult(result1, result2 *ValidationResult) bool {
	if result1.IsSuccess != result2.IsSuccess {
		return false
	}
	if len(result1.ArtifactReports) != len(result2.ArtifactReports) {
		return false
	}
	for _, report := range result1.ArtifactReports {
		hasSameReport := false
		for _, report2 := range result2.ArtifactReports {
			if sameArtifactValidationReport(report, report2) {
				hasSameReport = true
				break
			}
		}
		if !hasSameReport {
			return false
		}
	}
	return true
}

func sameArtifactValidationReport(report1, report2 *ArtifactValidationReport) bool {
	if len(report1.VerifierReports) != len(report2.VerifierReports) {
		return false
	}
	for _, verifierReport := range report1.VerifierReports {
		hasSameReport := false
		for _, verifierReport2 := range report2.VerifierReports {
			if reflect.DeepEqual(verifierReport, verifierReport2) {
				hasSameReport = true
				break
			}
		}
		if !hasSameReport {
			return false
		}
	}
	if len(report1.NestedArtifactReports) != len(report2.NestedArtifactReports) {
		return false
	}
	for _, nestedReport := range report1.NestedArtifactReports {
		hasSameReport := false
		for _, nestedReport2 := range report2.NestedArtifactReports {
			if sameArtifactValidationReport(nestedReport, nestedReport2) {
				hasSameReport = true
				break
			}
		}
		if !hasSameReport {
			return false
		}
	}
	return true
}
