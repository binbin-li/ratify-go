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
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// registeredPolicyEnforcers saves the registered policy enforcer factories.
var registeredPolicyEnforcers map[string]func(CreatePolicyEnforcerOptions) (PolicyEnforcer, error)

// ValidationReport describes the results of verifying an artifact and its
// nested artifacts by available verifiers.
type ValidationReport struct {
	// Subject is the subject reference of the artifact being verified.
	// Required.
	Subject string

	// Results is reports of verifying the subject against the referrer
	// artifacts by matching verifiers. Required.
	Results []*VerificationResult

	// Artifact is the descriptor of the referrer artifact being verified
	// against with. Required.
	Artifact ocispec.Descriptor

	// ArtifactReports is reports of verifying referrer artifacts. Optional.
	ArtifactReports []*ValidationReport
}

// PolicyEnforcer is an interface with methods that make policy decisions.
type PolicyEnforcer interface {
	// Evaluate determines the final outcome of validation that is constructed 
	// using the results from individual verifications.
	Evaluate(ctx context.Context, artifactReports []*ValidationReport) bool
}

// CreatePolicyEnforcerOptions represents the options to create a policy 
// enforcer plugin.
type CreatePolicyEnforcerOptions struct {
	// Name is unique identifier of a policy enforcer instance. Required.
	Name string

	// Type represents a specific implementation of policy enforcer. Required.
	// Note: there could be multiple policy enforcers of the same type with 
	//       different names.
	Type string

	// Parameters of the policy enforcer. Optional.
	Parameters any
}

// RegisterPolicyEnforcer registers a policy enforcer factory to the system.
func RegisterPolicyEnforcer(policyEnforcerType string, create func(CreatePolicyEnforcerOptions) (PolicyEnforcer, error)) {
	if policyEnforcerType == "" {
		panic("policy enforcer type cannot be empty")
	}
	if create == nil {
		panic("policy enforcer factory cannot be nil")
	}
	if registeredPolicyEnforcers == nil {
		registeredPolicyEnforcers = make(map[string]func(CreatePolicyEnforcerOptions) (PolicyEnforcer, error))
	}
	if _, registered := registeredPolicyEnforcers[policyEnforcerType]; registered {
		panic(fmt.Sprintf("policy enforcer factory type %s already registered", policyEnforcerType))
	}
	registeredPolicyEnforcers[policyEnforcerType] = create
}

// CreatePolicyEnforcer creates a policy enforcer instance if it belongs to a 
// registered type.
func CreatePolicyEnforcer(opts CreatePolicyEnforcerOptions) (PolicyEnforcer, error) {
	if opts.Name == "" || opts.Type == "" {
		return nil, fmt.Errorf("name or type is not provided in the policy enforcer options")
	}
	policyEnforcerFactory, ok := registeredPolicyEnforcers[opts.Type]
	if !ok {
		return nil, fmt.Errorf("policy enforcer factory of type %s is not registered", opts.Type)

	}
	return policyEnforcerFactory(opts)
}
