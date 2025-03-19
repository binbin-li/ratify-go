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

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ValidationReport describes the results of verifying an artifact and its
// nested artifacts by available verifiers.
type ValidationReport struct {
	// Subject is the subject reference of the artifact being verified.
	// Required.
	Subject string

	// Results are generated by verifiers while verifying the subject against
	// the referrer artifact. Required.
	// e.g. If the Subject is a container image, Artifact is a descriptor to
	// Notation signature. Results are generated by Notation verifiers verifying
	// the image against the signature.
	Results []*VerificationResult

	// Artifact is the descriptor of the referrer artifact being verified
	// against with. Required.
	Artifact ocispec.Descriptor

	// ArtifactReports is reports of verifying referrer artifacts. Optional.
	// e.g. If the Subject is a container image, Artifact is a descriptor to
	// SBOM which is signed by a Notation signature. ArtifactReports are
	// generated by the executor verifying the SBOM against the signature.
	ArtifactReports []*ValidationReport
}

// Evaluator is an interface that defines methods to aggregate and evaluate
// verification results generated for an artifact per validation request.
type Evaluator interface {
	// VerifyRequired checks if the provided verifier is required to perform
	// verification on the subject against the artifact. If the verifier is
	// required, it returns [ErrVerifyRequired].
	VerifyRequired(ctx context.Context, subjectDigest, artifactDigest string, verifier Verifier) error

	// AddResult adds the verification result of the subject against the
	// artifact to the evaluator for further evaluation.
	AddResult(ctx context.Context, subjectDigest, artifactDigest string, artifactResult *VerificationResult) error

	// Evaluate makes the final decision based on aggregated verification
	// results added so far.
	Evaluate(ctx context.Context) (bool, error)
}

// PolicyEnforcer is an interface that generates an evaluator upon a validation
// request.
type PolicyEnforcer interface {
	// Evaluator returns an [Evaluator] for the given subject digest.
	Evaluator(ctx context.Context, subjectDigest string) (Evaluator, error)
}
