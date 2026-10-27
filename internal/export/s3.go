package export

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/lcleveland/network-mcp/internal/creds"
)

// S3 puts each artifact at Prefix/<device>/<kind>.<ext>, skipping one whose
// stored sha256 metadata already matches.
type S3 struct {
	Name, Bucket, Prefix, Credential, CredDir string
	// Options has no Credentials: Put adds them from the ref. Never built by
	// config.LoadDefaultConfig, which reads env and ~/.aws.
	Options s3.Options
}

func (d S3) Put(ctx context.Context, as []Artifact, _ string) ([]Receipt, error) {
	k, err := creds.S3(d.CredDir, d.Credential)
	if err != nil {
		return nil, err
	}
	o := d.Options
	o.Credentials = credentials.NewStaticCredentialsProvider(k.AccessKeyID, k.SecretAccessKey, k.SessionToken)
	c := s3.New(o)
	var rs []Receipt
	for _, a := range as {
		rel, err := a.Rel()
		if err != nil {
			return rs, err
		}
		key := path.Join(d.Prefix, rel)
		r := Receipt{Destination: d.Name, Changed: true}
		h, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &d.Bucket, Key: &key})
		var nf *types.NotFound
		switch {
		case err == nil && h.Metadata["sha256"] == a.SHA256:
			r.Changed, r.Ref = false, ref(key, h.VersionId)
		case err == nil, errors.As(err, &nf):
			p, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: &d.Bucket, Key: &key, Body: bytes.NewReader(a.Body),
				Metadata: map[string]string{"sha256": a.SHA256}})
			if err != nil {
				return rs, fmt.Errorf("%s: %w", key, err)
			}
			r.Ref = ref(key, p.VersionId)
		default:
			return rs, fmt.Errorf("%s: %w", key, err)
		}
		rs = append(rs, r)
	}
	return rs, nil
}

func ref(key string, version *string) string {
	if v := aws.ToString(version); v != "" {
		return key + "?versionId=" + v
	}
	return key
}
