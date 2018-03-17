// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remote

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/google/go-containerregistry/authn"
	"github.com/google/go-containerregistry/name"
	"github.com/google/go-containerregistry/v1"
	"github.com/google/go-containerregistry/v1/remote/transport"
	"github.com/google/go-containerregistry/v1/types"
)

// image accesses an image from a remote registry
type image struct {
	ref    name.Reference
	client *http.Client
}

var _ v1.Image = (*image)(nil)

// Image accesses a given image reference over the provided transport, with the provided authentication.
func Image(ref name.Reference, auth authn.Authenticator, t http.RoundTripper) (v1.Image, error) {
	tr, err := transport.New(ref, auth, t, transport.PullScope)
	if err != nil {
		return nil, err
	}
	return image{
		ref: ref,
		client: &http.Client{
			Transport: tr,
		},
	}, nil
}

func (i image) url(resource, identifier string) url.URL {
	return url.URL{
		Scheme: transport.Scheme(i.ref.Context().Registry),
		Host:   i.ref.Context().RegistryStr(),
		Path:   fmt.Sprintf("/v2/%s/%s/%s", i.ref.Context().RepositoryStr(), resource, identifier),
	}
}

// TODO: refactor http request creation
// TODO: cache config and manifest files
func (i image) Manifest() (*v1.Manifest, error) {
	u := i.url("manifests", i.ref.Identifier())
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", string(types.DockerManifestSchema2))
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return v1.ParseManifest(resp.Body)
}

func (i image) FSLayers() ([]v1.Hash, error) {
	manifest, err := i.Manifest()
	if err != nil {
		return nil, err
	}
	var layers []v1.Hash
	for _, l := range manifest.Layers {
		layers = append(layers, l.Digest)
	}
	return layers, nil
}

func (i image) DiffIDs() ([]v1.Hash, error) {
	config, err := i.ConfigFile()
	if err != nil {
		return nil, err
	}
	return config.RootFS.DiffIDs, nil
}

func (i image) ConfigName() (v1.Hash, error) {
	manifest, err := i.Manifest()
	if err != nil {
		return v1.Hash{}, err
	}
	return manifest.Config.Digest, nil
}

func (i image) BlobSet() (map[v1.Hash]struct{}, error) {
	set := make(map[v1.Hash]struct{})
	layers, err := i.FSLayers()
	if err != nil {
		return nil, err
	}
	for _, h := range layers {
		set[h] = struct{}{}
	}
	config, err := i.ConfigName()
	if err != nil {
		return nil, err
	}
	set[config] = struct{}{}
	return set, nil
}

func (i image) Digest() (v1.Hash, error) {
	// TODO: refactor this -- we can't just use i.Manifest() because of string formatting
	u := i.url("manifests", i.ref.Identifier())
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return v1.Hash{}, err
	}
	req.Header.Set("Accept", string(types.DockerManifestSchema2))
	resp, err := i.client.Do(req)
	if err != nil {
		return v1.Hash{}, err
	}
	defer resp.Body.Close()
	return v1.SHA256(resp.Body)
}

func (i image) MediaType() (types.MediaType, error) {
	// TODO: how to coerce string into types.MediaType in go?
	return types.OCIManifestSchema1, nil
}

func (i image) ConfigFile() (*v1.ConfigFile, error) {
	hash, err := i.ConfigName()
	if err != nil {
		return nil, err
	}
	body, err := i.Blob(hash)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return v1.ParseConfigFile(body)
}

func (i image) BlobSize(h v1.Hash) (int64, error) {
	u := i.url("blobs", h.String())
	resp, err := i.client.Head(u.String())
	if err != nil {
		return -1, err
	}
	return resp.ContentLength, nil
}

func (i image) Blob(h v1.Hash) (io.ReadCloser, error) {
	u := i.url("blobs", h.String())
	resp, err := i.client.Get(u.String())
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (i image) Layer(h v1.Hash) (io.ReadCloser, error) {
	// TODO: pull this out into diffid_to_digest
	layers, err := i.FSLayers()
	if err != nil {
		return nil, err
	}
	diffids, err := i.DiffIDs()
	if err != nil {
		return nil, err
	}
	for n, l := range layers {
		if l == h {
			return i.Blob(diffids[n])
		}
	}
	return nil, fmt.Errorf("could not find Layer by diffid (%v)", h)
}

// TODO(mattmoor): xyzpdq
func (i image) UncompressedBlob(h v1.Hash) (io.ReadCloser, error) {
	return nil, fmt.Errorf("NYI: remote.UncompressedBlob(%v)", h)
}

// TODO(mattmoor): xyzpdq
func (i image) UncompressedLayer(h v1.Hash) (io.ReadCloser, error) {
	return nil, fmt.Errorf("NYI: remote.UncompressedLayer(%v)", h)
}
