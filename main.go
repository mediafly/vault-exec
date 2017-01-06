package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"

	yaml "gopkg.in/yaml.v2"
)

////////////////////////////////////////////////////////////////////////////////
// SecretInputType
////////////////////////////////////////////////////////////////////////////////
type SecretInputType string

const (
	SecretInputTypeBinary SecretInputType = "binary"
	SecretInputTypeString SecretInputType = "string"
)

func (t SecretInputType) WithDefault() SecretInputType {
	if t == "" {
		return SecretInputTypeString
	}
	return t
}

////////////////////////////////////////////////////////////////////////////////
// SecretInput
////////////////////////////////////////////////////////////////////////////////
type SecretInput struct {
	Key  string          `yaml:"key,omitempty"`
	Path string          `yaml:"path,omitempty"`
	Type SecretInputType `yaml:"type,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// SecretOutputType
////////////////////////////////////////////////////////////////////////////////
type SecretOutputType string

const (
	SecretOutputTypeFile     SecretOutputType = "file"
	SecretOutputTypeVariable SecretOutputType = "variable"
)

func (t SecretOutputType) WithDefault() SecretOutputType {
	if t == "" {
		return SecretOutputTypeFile
	}
	return t
}

////////////////////////////////////////////////////////////////////////////////
// SecretOutput
////////////////////////////////////////////////////////////////////////////////
type SecretOutput struct {
	Name string           `yaml:"name,omitempty"`
	Path string           `yaml:"path,omitempty"`
	Type SecretOutputType `yaml:"type,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// Secret
////////////////////////////////////////////////////////////////////////////////
type Secret struct {
	Input  SecretInput  `yaml:"input"`
	Output SecretOutput `yaml:"output"`
}

////////////////////////////////////////////////////////////////////////////////
// Manifest
////////////////////////////////////////////////////////////////////////////////
type Manifest struct {
	Authority   string   `yaml:"authority,omitempty"`
	Certificate string   `yaml:"certificate,omitempty"`
	Command     string   `yaml:"command"`
	Key         string   `yaml:"key,omitempty"`
	Secrets     []Secret `yaml:"secrets,omitempty"`
	Vault       string   `yaml:"vault,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// SecretCache
////////////////////////////////////////////////////////////////////////////////
type SecretCache map[string]*api.Secret

func (s *SecretCache) Get(client *api.Client, path string) (*api.Secret, error) {
	if secret, ok := (*s)[path]; ok {
		return secret, nil
	}

	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, errors.Wrap(err, "read failed")
	}

	(*s)[path] = secret

	return secret, nil
}

////////////////////////////////////////////////////////////////////////////////
// LoadManifest
////////////////////////////////////////////////////////////////////////////////
func LoadManifest(path string) (*Manifest, error) {
	var manifest Manifest
	var input []byte
	var err error

	if path == "-" {
		input, err = ioutil.ReadAll(os.Stdin)
	} else {
		input, err = ioutil.ReadFile(path)
	}

	if err != nil {
		return nil, errors.Wrap(err, "read manifest failed")
	}

	if err := yaml.Unmarshal(input, &manifest); err != nil {
		return nil, errors.Wrap(err, "parse manifest failed")
	}

	return &manifest, nil
}

////////////////////////////////////////////////////////////////////////////////
// CreateTempFile
////////////////////////////////////////////////////////////////////////////////
func CreateTempFile(name string, content string) (string, error) {
	file, err := ioutil.TempFile("", name)
	if err != nil {
		return "", errors.Wrap(err, "create temp file failed")
	}

	f := func() error {
		if _, err := file.WriteString(content); err != nil {
			return errors.Wrap(err, "write temp file failed")
		}

		if err := file.Close(); err != nil {
			return errors.Wrap(err, "close temp file failed")
		}

		return nil
	}

	if err := f(); err != nil {
		file.Close()
		os.Remove(file.Name())
		return "", err
	}

	return file.Name(), nil
}

////////////////////////////////////////////////////////////////////////////////
// Authorize
////////////////////////////////////////////////////////////////////////////////
func Authorize(manifest *Manifest) (*api.Client, error) {
	config := api.DefaultConfig()
	tls := api.TLSConfig{}

	if manifest.Vault != "" {
		config.Address = manifest.Vault
	}

	if manifest.Authority != "" {
		file, err := CreateTempFile("cacert.pem", manifest.Authority)
		if err != nil {
			return nil, errors.Wrap(err, "create ca cert failed")
		}
		defer os.Remove(file)

		tls.CACert = file
	}

	if tls.CACert == "" {
		tls.CACert = os.Getenv(api.EnvVaultCACert)
	}

	if manifest.Certificate != "" {
		file, err := CreateTempFile("cert.pem", manifest.Certificate)
		if err != nil {
			return nil, errors.Wrap(err, "create client cert failed")
		}
		defer os.Remove(file)

		tls.ClientCert = file
	}

	if tls.ClientKey == "" {
		tls.ClientKey = os.Getenv(api.EnvVaultClientCert)
	}

	if manifest.Key != "" {
		file, err := CreateTempFile("cert.key", manifest.Key)
		if err != nil {
			return nil, errors.Wrap(err, "create clietn key failed")
		}
		defer os.Remove(file)

		tls.ClientKey = file
	}

	if tls.ClientKey == "" {
		tls.ClientKey = os.Getenv(api.EnvVaultClientKey)
	}

	if err := config.ConfigureTLS(&tls); err != nil {
		return nil, errors.Wrap(err, "configure tls failed")
	}

	if tls.CACert == "" {
		return nil, errors.Errorf("missing ca certificate")
	}

	if tls.ClientKey == "" {
		return nil, errors.Errorf("missing client certificate")
	}

	if tls.ClientKey == "" {
		return nil, errors.Errorf("missing client key")
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "create client failed")
	}

	secret, err := client.Logical().Write("auth/cert/login", nil)
	if err != nil {
		return nil, errors.Wrap(err, "login failed")
	}

	client.SetToken(secret.Auth.ClientToken)

	return client, nil
}

////////////////////////////////////////////////////////////////////////////////
// GetSecrets
////////////////////////////////////////////////////////////////////////////////
func GetSecrets(manifest *Manifest, client *api.Client) ([]string, error) {
	cache := SecretCache{}
	env := os.Environ()

	for i, secret := range manifest.Secrets {
		f := func() error {
			secretInputType := secret.Input.Type.WithDefault()
			secretOutputType := secret.Output.Type.WithDefault()

			if secret.Input.Path == "" {
				return errors.New("missing input path")
			}

			if secret.Input.Key == "" {
				return errors.New("missing input key")
			}

			values, err := cache.Get(client, secret.Input.Path)
			if err != nil {
				return errors.Wrap(err, "get failed")
			}

			value, ok := values.Data[secret.Input.Key]
			if !ok {
				return errors.New("key not found")
			}

			switch secretOutputType {
			case SecretOutputTypeFile:
				if secret.Output.Path == "" {
					return errors.New("secret output path")
				}

				f := func() error {
					output, err := os.OpenFile(secret.Output.Path, os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						return errors.Wrap(err, "open file failed")
					}
					defer output.Close()

					switch secretInputType {
					case SecretInputTypeBinary:
						if _, err := output.Write(value.([]byte)); err != nil {
							return errors.Wrap(err, "write binary failed")
						}

					case SecretInputTypeString:
						if _, err := output.WriteString(value.(string)); err != nil {
							return errors.Wrap(err, "write string failed")
						}

					default:
						return errors.Errorf("invalid input type: %v", secretInputType)
					}
					return nil
				}

				if err := f(); err != nil {
					return err
				}

			case SecretOutputTypeVariable:
				if secretInputType != SecretInputTypeString {
					return errors.New("secret must be of type string to output to an environment variable")
				}

				env = append(env, fmt.Sprintf("%v=%v", secret.Output.Name, value.(string)))

			default:
				return errors.Errorf("secret invalid output type: %v", secretOutputType)
			}

			return nil
		}

		if err := f(); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("get secret at index %v failed", i))
		}
	}

	return env, nil
}

////////////////////////////////////////////////////////////////////////////////
// main
////////////////////////////////////////////////////////////////////////////////
func main() {
	if len(os.Args) != 2 {
		log.Fatalln("vault-exec [manifest]")
	}

	check := func(err error) {
		if err != nil {
			log.Fatalf("%+v", err)
		}
	}

	manifest, err := LoadManifest(os.Args[1])
	check(err)

	client, err := Authorize(manifest)
	check(err)

	env, err := GetSecrets(manifest, client)
	check(err)

	cmd := exec.Command("sh", "-c", manifest.Command)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	check(cmd.Run())
}
