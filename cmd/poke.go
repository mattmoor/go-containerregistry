package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/authn"
	"github.com/google/go-containerregistry/name"
	"github.com/google/go-containerregistry/v1/remote"
)

func parseReference(ref string) (name.Reference, error) {
	tag, err := name.NewTag(ref, name.WeakValidation)
	if err == nil {
		return tag, nil
	}
	return name.NewDigest(ref, name.WeakValidation)
}

func printConfig(arg string) {
	ref, err := parseReference(arg)
	if err != nil {
		log.Fatalln(err)
	}
	auth, err := authn.DefaultKeychain.Resolve(ref.Context().Registry)
	if err != nil {
		log.Fatalln(err)
	}
	i, err := remote.Image(ref, auth, http.DefaultTransport)
	if err != nil {
		log.Fatalln(err)
	}
	config, err := i.ConfigFile()
	if err != nil {
		log.Fatalln(err)
	}
	out, _ := json.Marshal(config)
	fmt.Println(string(out))
}

func printManifest(arg string) {
	ref, err := parseReference(arg)
	if err != nil {
		log.Fatalln(err)
	}
	auth, err := authn.DefaultKeychain.Resolve(ref.Context().Registry)
	if err != nil {
		log.Fatalln(err)
	}
	i, err := remote.Image(ref, auth, http.DefaultTransport)
	if err != nil {
		log.Fatalln(err)
	}
	manifest, err := i.Manifest()
	if err != nil {
		log.Fatalln(err)
	}
	out, _ := json.Marshal(manifest)
	fmt.Println(string(out))
}

func main() {
	switch os.Args[1] {
	case "config":
		if os.Args[2] != "" {
			printConfig(os.Args[2])
		}
	case "manifest":
		if os.Args[2] != "" {
			printManifest(os.Args[2])
		}
	default:
		log.Fatalf("unexpected subcommand: %s", os.Args[1])
	}
}
