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

package common

import (
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Reference describes an image reference identifier that includes properties like digest, tag.
type Reference struct {
	// Path is the repository path of the artifact.
	Path string
	// Digest is the digest of the artifact.
	Digest digest.Digest
	// Tag is the tag of the artifact.
	Tag string
	// Original is the original string representation of the reference.
	Original string
	// Descriptor is the descriptor of the artifact.
	Descriptor v1.Descriptor
}

// String returns the original string representation of the reference.
func (ref Reference) String() string {
	return ref.Original
}
