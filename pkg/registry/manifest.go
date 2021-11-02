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

package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ManifestHandler is the interface for the metadata storage layer underneath
// this registry.
type ManifestHandler interface {
	// ListRepositories enumerates up to some count of repositories starting at
	// a specified offset.  This is used to implement the "catalog" handler.
	ListRepositories(offset, count int) ([]name.Repository, error)

	// GetRepository fetches a handler for interacting with a collection of
	// manifests rooted under a particular repository.
	GetRepository(repo name.Repository) (RepositoryHandler, error)
}

// RepositoryHandler is the interface for accessing manifest data under a
// particular repository.
type RepositoryHandler interface {
	// GetDigest fetches the raw bytes of the manifest, and its media type,
	// or returns an error indicating why it cannot.
	GetDigest(v1.Hash) ([]byte, types.MediaType, error)
	// GetTag fetches the raw bytes of the manifest currently labeled by the
	// provided tag, and its media type, or returns an error indicating why
	// it cannot.
	GetTag(string) ([]byte, types.MediaType, error)

	// DeleteDigest removes the manifest with the given hash, it returns an
	// error when the digest does not exist.
	DeleteDigest(v1.Hash) error
	// DeleteTag removes the tag with the given name, the digest is left untouched,
	// it returns an error when the digest does not exist.
	DeleteTag(string) error

	// PutDigest adds the provided manifest content, with the associated media type
	// to the store under the provided hash name.  It returns an error if this cannot
	// be completed.
	PutDigest(v1.Hash, []byte, types.MediaType) error
	// PutTag applies the provided tag to the given hash.  It returns an error if
	// this is not possible.
	PutTag(string, v1.Hash) error

	// ListTags enumerates up to some count of tags starting at
	// a specified offset.  This is used to implement the "tags" handler.
	ListTags(offset, count int) ([]string, error)
}

type manifests struct {
	// maps repo -> manifest tag/digest -> manifest
	log *log.Logger

	mh ManifestHandler
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

func isTags(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "tags"
}

func isCatalog(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 2 {
		return false
	}

	return elems[len(elems)-1] == "_catalog"
}

// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-an-image-manifest
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-an-image
func (m *manifests) handle(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]

	repo, err := name.NewRepository(req.Host+"/"+path.Join(elem[1:len(elem)-2]...), name.StrictValidation)
	if err != nil {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "NAME_INVALID",
			Message: err.Error(),
		}
	}

	rh, err := m.mh.GetRepository(repo)
	if err != nil {
		// Not reachable with the default implementation
		return &regError{
			Status:  http.StatusInternalServerError,
			Code:    "NAME_INVALID",
			Message: err.Error(),
		}
	}

	switch req.Method {
	case http.MethodGet:
		var (
			content   []byte
			mediaType types.MediaType
		)
		h, err := v1.NewHash(target)
		if err == nil {
			content, mediaType, err = rh.GetDigest(h)
		} else {
			content, mediaType, err = rh.GetTag(target)
		}
		if err != nil {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "MANIFEST_UNKNOWN",
				Message: err.Error(),
			}
		}

		rd := sha256.Sum256(content)
		d := "sha256:" + hex.EncodeToString(rd[:])
		resp.Header().Set("Docker-Content-Digest", d)
		resp.Header().Set("Content-Type", string(mediaType))
		resp.Header().Set("Content-Length", fmt.Sprint(len(content)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader(content))
		return nil

	case http.MethodHead:
		var (
			content   []byte
			mediaType types.MediaType
		)
		h, err := v1.NewHash(target)
		if err == nil {
			content, mediaType, err = rh.GetDigest(h)
		} else {
			content, mediaType, err = rh.GetTag(target)
		}
		if err != nil {
			return &regError{
				Status:  http.StatusNotFound,
				Code:    "MANIFEST_UNKNOWN",
				Message: err.Error(),
			}
		}
		rd := sha256.Sum256(content)
		d := "sha256:" + hex.EncodeToString(rd[:])
		resp.Header().Set("Docker-Content-Digest", d)
		resp.Header().Set("Content-Type", string(mediaType))
		resp.Header().Set("Content-Length", fmt.Sprint(len(content)))
		resp.WriteHeader(http.StatusOK)
		return nil

	case http.MethodPut:
		b := &bytes.Buffer{}
		io.Copy(b, req.Body)
		h, _, err := v1.SHA256(bytes.NewBuffer(b.Bytes()))
		if err != nil {
			// This shouldn't be possible
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "MANIFEST_INVALID",
				Message: err.Error(),
			}
		}
		mediaType := types.MediaType(req.Header.Get("Content-Type"))

		// If the manifest is a manifest list, check that the manifest
		// list's constituent manifests are already uploaded.
		// This isn't strictly required by the registry API, but some
		// registries require this.
		if mediaType.IsIndex() {
			im, err := v1.ParseIndexManifest(b)
			if err != nil {
				return &regError{
					Status:  http.StatusBadRequest,
					Code:    "MANIFEST_INVALID",
					Message: err.Error(),
				}
			}
			for _, desc := range im.Manifests {
				if !desc.MediaType.IsDistributable() {
					continue
				}
				if desc.MediaType.IsIndex() || desc.MediaType.IsImage() {
					if _, _, err := rh.GetDigest(desc.Digest); err != nil {
						return &regError{
							Status:  http.StatusNotFound,
							Code:    "MANIFEST_UNKNOWN",
							Message: err.Error(),
						}
					}
				} else {
					// TODO: Probably want to do an existence check for blobs.
					m.log.Printf("TODO: Check blobs for %q", desc.Digest)
				}
			}
		}

		// Allow future references by target (tag) and immutable digest.
		// See https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier.
		if err := rh.PutDigest(h, b.Bytes(), mediaType); err != nil {
			// Not reachable with the default implementation
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "MANIFEST_INVALID",
				Message: err.Error(),
			}
		}
		if err := rh.PutTag(target, h); err != nil {
			// Not reachable with the default implementation
			return &regError{
				Status:  http.StatusInternalServerError,
				Code:    "MANIFEST_INVALID",
				Message: err.Error(),
			}
		}
		resp.Header().Set("Docker-Content-Digest", h.String())
		resp.WriteHeader(http.StatusCreated)
		return nil

	case http.MethodDelete:
		h, err := v1.NewHash(target)
		if err == nil {
			if err := rh.DeleteDigest(h); err != nil {
				return &regError{
					Status:  http.StatusNotFound,
					Code:    "MANIFEST_UNKNOWN",
					Message: err.Error(),
				}
			}
		} else {
			if err := rh.DeleteTag(target); err != nil {
				return &regError{
					Status:  http.StatusNotFound,
					Code:    "MANIFEST_UNKNOWN",
					Message: err.Error(),
				}
			}
		}
		resp.WriteHeader(http.StatusAccepted)
		return nil

	default:
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}
}

func (m *manifests) handleTags(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	query := req.URL.Query()
	nStr := query.Get("n")
	n := 1000
	if nStr != "" {
		n, _ = strconv.Atoi(nStr)
	}

	if req.Method != http.MethodGet {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}

	repo, err := name.NewRepository(req.Host+"/"+path.Join(elem[1:len(elem)-2]...), name.StrictValidation)
	if err != nil {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "NAME_INVALID",
			Message: err.Error(),
		}
	}

	rh, err := m.mh.GetRepository(repo)
	if err != nil {
		// Not reachable with the default implementation
		return &regError{
			Status:  http.StatusInternalServerError,
			Code:    "NAME_INVALID",
			Message: err.Error(),
		}
	}

	// TODO: implement pagination https://github.com/opencontainers/distribution-spec/blob/b505e9cc53ec499edbd9c1be32298388921bb705/detail.md#tags-paginated
	tags, err := rh.ListTags(0, n)
	if err != nil {
		// Not reachable with the default implementation
		return &regError{
			Status:  http.StatusInternalServerError,
			Code:    "NAME_INVALID",
			Message: err.Error(),
		}
	}

	if len(tags) == 0 {
		return &regError{
			Status:  http.StatusNotFound,
			Code:    "NAME_UNKNOWN",
			Message: "There are no tags in this repository.",
		}
	}

	msg, _ := json.Marshal(struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{
		Name: repo.RepositoryStr(),
		Tags: tags,
	})
	resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
	resp.WriteHeader(http.StatusOK)
	io.Copy(resp, bytes.NewReader([]byte(msg)))
	return nil
}

func (m *manifests) handleCatalog(resp http.ResponseWriter, req *http.Request) *regError {
	query := req.URL.Query()
	nStr := query.Get("n")
	n := 10000
	if nStr != "" {
		n, _ = strconv.Atoi(nStr)
	}

	if req.Method != http.MethodGet {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}

	// TODO: implement pagination
	rs, err := m.mh.ListRepositories(0, n)
	if err != nil {
		// Not reachable with the default implementation
		return &regError{
			Status:  http.StatusInternalServerError,
			Code:    "METHOD_UNKNOWN",
			Message: err.Error(),
		}
	}

	repos := make([]string, 0, len(rs))
	for _, repo := range rs {
		repos = append(repos, repo.String())
	}

	msg, _ := json.Marshal(struct {
		Repos []string `json:"repositories"`
	}{
		Repos: repos,
	})
	resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
	resp.WriteHeader(http.StatusOK)
	io.Copy(resp, bytes.NewReader([]byte(msg)))
	return nil
}

type defaultRepoStore struct {
	m        sync.Mutex
	contents map[name.Repository]RepositoryHandler
}

var _ ManifestHandler = (*defaultRepoStore)(nil)

// ListRepositories implements ManifestHandler
func (drs *defaultRepoStore) ListRepositories(offset, count int) ([]name.Repository, error) {
	repos := make([]name.Repository, 0, len(drs.contents))
	for key := range drs.contents {
		repos = append(repos, key)
	}

	// Map ordering is random, so stabilize the order for pagination.
	sort.Slice(repos, func(i, j int) bool {
		return repos[i].String() < repos[j].String()
	})

	upper := offset + count
	if upper > len(repos) {
		upper = len(repos)
	}
	return repos[offset:upper], nil
}

// GetRepository implements ManifestHandler
func (drs *defaultRepoStore) GetRepository(repo name.Repository) (RepositoryHandler, error) {
	drs.m.Lock()
	defer drs.m.Unlock()

	if drs.contents == nil {
		drs.contents = make(map[name.Repository]RepositoryHandler)
	}
	dms, ok := drs.contents[repo]
	if !ok {
		dms = &defaultManifestStore{
			tags:     make(map[string]v1.Hash),
			contents: make(map[v1.Hash]manifest),
		}
		drs.contents[repo] = dms
	}
	return dms, nil
}

type defaultManifestStore struct {
	m        sync.Mutex
	tags     map[string]v1.Hash
	contents map[v1.Hash]manifest
}

type manifest struct {
	contentType types.MediaType
	blob        []byte
}

var _ RepositoryHandler = (*defaultManifestStore)(nil)

// GetDigest implements RepositoryHandler
func (dms *defaultManifestStore) GetDigest(h v1.Hash) ([]byte, types.MediaType, error) {
	dms.m.Lock()
	defer dms.m.Unlock()

	m, ok := dms.contents[h]
	if !ok {
		return nil, "", fmt.Errorf("digest %s not found", h)
	}
	return m.blob, m.contentType, nil
}

// GetTag implements RepositoryHandler
func (dms *defaultManifestStore) GetTag(tag string) ([]byte, types.MediaType, error) {
	dms.m.Lock()
	defer dms.m.Unlock()

	h, ok := dms.tags[tag]
	if !ok {
		return nil, "", fmt.Errorf("tag %s not found", tag)
	}
	m, ok := dms.contents[h]
	if !ok {
		return nil, "", fmt.Errorf("digest %s not found", h)
	}
	return m.blob, m.contentType, nil
}

// DeleteDigest implements RepositoryHandler
func (dms *defaultManifestStore) DeleteDigest(h v1.Hash) error {
	dms.m.Lock()
	defer dms.m.Unlock()

	if _, ok := dms.contents[h]; !ok {
		return fmt.Errorf("digest %s not found", h)
	}

	// TODO(mattmoor): Check for dangling tag references.
	delete(dms.contents, h)
	return nil
}

// DeleteTag implements RepositoryHandler
func (dms *defaultManifestStore) DeleteTag(tag string) error {
	dms.m.Lock()
	defer dms.m.Unlock()

	if _, ok := dms.tags[tag]; !ok {
		return fmt.Errorf("tag %s not found", tag)
	}

	delete(dms.tags, tag)
	return nil
}

// PutDigest implements RepositoryHandler
func (dms *defaultManifestStore) PutDigest(h v1.Hash, content []byte, contentType types.MediaType) error {
	dms.m.Lock()
	defer dms.m.Unlock()

	dms.contents[h] = manifest{
		blob:        content,
		contentType: contentType,
	}
	return nil
}

// PutTag implements RepositoryHandler
func (dms *defaultManifestStore) PutTag(tag string, h v1.Hash) error {
	dms.m.Lock()
	defer dms.m.Unlock()

	// TODO(mattmoor): Check that the hash exists? (impossible given current usage)
	dms.tags[tag] = h
	return nil
}

// ListTags implements RepositoryHandler
func (dms *defaultManifestStore) ListTags(offset, count int) ([]string, error) {
	dms.m.Lock()
	defer dms.m.Unlock()

	tags := make([]string, 0, len(dms.tags))
	for tag := range dms.tags {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	upper := offset + count
	if upper > len(tags) {
		upper = len(tags)
	}
	return tags[offset:upper], nil
}
