package export

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lcleveland/network-mcp/internal/config"
)

// fakeS3 speaks path-style HeadObject and PutObject, keeping the sha256
// metadata and each request's headers.
type fakeS3 struct {
	mu   sync.Mutex
	meta map[string]string // path to sha256 metadata
	reqs []*http.Request
	fail string // path answered 403
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	io.Copy(io.Discard, r.Body)
	f.reqs = append(f.reqs, r)
	sha, ok := f.meta[r.URL.Path]
	switch {
	case r.URL.Path == f.fail:
		w.WriteHeader(403)
	case r.Method == http.MethodHead && !ok:
		w.WriteHeader(404)
	case r.Method == http.MethodHead:
		w.Header().Set("X-Amz-Meta-Sha256", sha)
		w.Header().Set("X-Amz-Version-Id", "v1")
	case r.Method == http.MethodPut:
		f.meta[r.URL.Path] = r.Header.Get("X-Amz-Meta-Sha256")
		w.Header().Set("X-Amz-Version-Id", "v2")
	default:
		w.WriteHeader(400)
	}
}

func TestS3(t *testing.T) {
	// ambient credentials that must never be used
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	os.WriteFile(filepath.Join(home, ".aws/credentials"), []byte("[default]\naws_access_key_id = AKIAAMBIENTFILE\naws_secret_access_key = ambient\n"), 0o600)
	t.Setenv("HOME", home)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENTENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient")

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "s3-key"), []byte(`{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"fake-s3-secret"}`), 0o400)
	f := &fakeS3{meta: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	ctx := context.Background()
	a := NewArtifact("dev1", "running", []byte("hostname dev1\n"), true)
	for _, checksum := range []string{"when_required", "when_supported"} {
		clear(f.meta)
		f.reqs = nil
		sk := must(New("bucket", config.Destination{Type: "s3", Endpoint: srv.URL, Region: "us-east-1", Bucket: "configs",
			Prefix: "net/", PathStyle: true, Credential: "s3-key", Checksum: checksum}, dir))

		rs, err := sk.Put(ctx, []Artifact{a}, "r")
		if err != nil || len(rs) != 1 || rs[0] != (Receipt{Destination: "bucket", Changed: true, Ref: "net/dev1/running.txt?versionId=v2"}) {
			t.Fatalf("%s first: %v %v", checksum, rs, err)
		}
		if f.meta["/configs/net/dev1/running.txt"] != a.SHA256 {
			t.Fatalf("metadata: %v", f.meta)
		}
		rs, err = sk.Put(ctx, []Artifact{a}, "r")
		if err != nil || rs[0] != (Receipt{Destination: "bucket", Changed: false, Ref: "net/dev1/running.txt?versionId=v1"}) {
			t.Fatalf("%s repeat: %v %v", checksum, rs, err)
		}
		if len(f.reqs) != 3 { // head, put, head
			t.Fatalf("%s: %d requests", checksum, len(f.reqs))
		}
		for _, r := range f.reqs {
			if auth := r.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKIAIOSFODNN7EXAMPLE/") {
				t.Fatalf("not signed with the ref's key: %q", auth)
			}
		}
		put := f.reqs[1].Header
		sum := put.Get("X-Amz-Checksum-Crc32") != "" || put.Get("X-Amz-Trailer") != "" || put.Get("X-Amz-Sdk-Checksum-Algorithm") != ""
		if sum != (checksum == "when_supported") {
			t.Errorf("%s: checksum sent %v: %v", checksum, sum, put)
		}
	}

	f.fail = "/configs/net/dev2/running.txt"
	sk := must(New("bucket", config.Destination{Type: "s3", Endpoint: srv.URL, Region: "us-east-1", Bucket: "configs",
		Prefix: "net", PathStyle: true, Credential: "s3-key"}, dir))
	rs, err := sk.Put(ctx, []Artifact{a, NewArtifact("dev2", "running", nil, true)}, "r")
	if err == nil || len(rs) != 1 || strings.Contains(fmt.Sprint(err, rs), "fake-s3-secret") {
		t.Fatalf("failure: %v %v", rs, err)
	}
}
