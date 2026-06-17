package image

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Image struct {
	Ref    string
	Digest string
	img    v1.Image
}

func Pull(ref string) (*Image, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	img, err := remote.Image(parsed, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("pull image %q: %w", ref, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("resolve digest for %q: %w", ref, err)
	}

	return &Image{
		Ref:    parsed.String(),
		Digest: digest.String(),
		img:    img,
	}, nil
}
