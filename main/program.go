package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

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
	Group string           `yaml:"group,omitempty"`
	Mode  *uint32          `yaml:"mode,omitempty"`
	Name  string           `yaml:"name,omitempty"`
	Path  string           `yaml:"path,omitempty"`
	Type  SecretOutputType `yaml:"type,omitempty"`
	User  string           `yaml:"user,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// Secret
////////////////////////////////////////////////////////////////////////////////
type Secret struct {
	Input  SecretInput  `yaml:"input"`
	Output SecretOutput `yaml:"output"`
}

////////////////////////////////////////////////////////////////////////////////
// Auth
////////////////////////////////////////////////////////////////////////////////
type Auth struct {
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"pass,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// Manifest
////////////////////////////////////////////////////////////////////////////////
type Manifest struct {
	Auth        *Auth    `yaml:"auth,omitempty"`
	Authority   string   `yaml:"authority,omitempty"`
	Certificate string   `yaml:"certificate,omitempty"`
	Command     string   `yaml:"command"`
	Dir         string   `yaml:"dir,omitempty"`
	User        string   `yaml:"user,omitempty"`
	Key         string   `yaml:"key,omitempty"`
	Secrets     []Secret `yaml:"secrets,omitempty"`
	Token       string   `yaml:"token,omitempty"`
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
// LookupUser
////////////////////////////////////////////////////////////////////////////////
func LookupUser(username string) (uint32, uint32, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "lookup user %v failed", username)
	}

	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}

	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}

	return uint32(uid), uint32(gid), nil
}

////////////////////////////////////////////////////////////////////////////////
// LookupUid
////////////////////////////////////////////////////////////////////////////////
func LookupUid(username string) (int, error) {
	uid, _, err := LookupUser(username)
	return int(uid), err
}

////////////////////////////////////////////////////////////////////////////////
// LookupGid
////////////////////////////////////////////////////////////////////////////////
func LookupGid(groupname string) (int, error) {
	g, err := user.LookupGroup(groupname)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	gid64, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, errors.WithStack(err)
	}

	return int(gid64), nil
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
	tls := api.TLSConfig{
		CACert:     os.Getenv(api.EnvVaultCACert),
		ClientCert: os.Getenv(api.EnvVaultClientCert),
		ClientKey:  os.Getenv(api.EnvVaultClientKey),
	}

	if manifest.Vault != "" {
		config.Address = manifest.Vault
	}

	if config.Address == "" {
		return nil, errors.New("missing vault address")
	}

	if manifest.Authority != "" {
		file, err := CreateTempFile("cacert.pem", manifest.Authority)
		if err != nil {
			return nil, errors.Wrap(err, "create ca cert failed")
		}
		defer os.Remove(file)

		tls.CACert = file
	}

	if manifest.Certificate != "" {
		file, err := CreateTempFile("cert.pem", manifest.Certificate)
		if err != nil {
			return nil, errors.Wrap(err, "create client cert failed")
		}
		defer os.Remove(file)

		tls.ClientCert = file
	}

	if manifest.Key != "" {
		file, err := CreateTempFile("cert.key", manifest.Key)
		if err != nil {
			return nil, errors.Wrap(err, "create client key failed")
		}
		defer os.Remove(file)

		tls.ClientKey = file
	}

	if tls.CACert == "" {
		return nil, errors.New("missing ca certificate")
	}

	if tls.ClientCert == "" {
		return nil, errors.New("missing client certificate")
	}

	if tls.ClientKey == "" {
		return nil, errors.New("missing client key")
	}

	if err := config.ConfigureTLS(&tls); err != nil {
		return nil, errors.Wrap(err, "configure tls failed")
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "create client failed")
	}

	if manifest.Auth == nil {
		return nil, errors.New("missing auth")
	}

	if manifest.Auth.User == "" {
		return nil, errors.New("missing auth user")
	}

	if manifest.Auth.Password == "" {
		return nil, errors.New("missing auth password")
	}

	auth := map[string]interface{}{
		"password": manifest.Auth.Password,
	}

	secret, err := client.Logical().Write("auth/userpass/login/"+manifest.Auth.User, auth)
	if err != nil {
		return nil, errors.Wrap(err, "auth failed")
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

			if values == nil {
				return errors.Errorf("path not found: %v", secret.Input.Path)
			}

			value, ok := values.Data[secret.Input.Key]
			if !ok {
				return errors.Errorf("key not found: %v/%v", secret.Input.Path, secret.Input.Key)
			}

			switch secretOutputType {
			case SecretOutputTypeFile:
				if secret.Output.Path == "" {
					return errors.New("secret output path")
				}

				f := func() error {
					mode := os.FileMode(0600)

					if stat, err := os.Stat(secret.Output.Path); os.IsExist(err) {
						mode = stat.Mode()
					}

					if secret.Output.Mode != nil {
						mode = os.FileMode(*secret.Output.Mode)
					}

					abspath, err := filepath.Abs(secret.Output.Path)
					if err != nil {
						return errors.WithStack(err)
					}

					if err = os.MkdirAll(filepath.Dir(abspath), 0700); err != nil {
						return errors.WithStack(err)
					}

					output, err := os.OpenFile(secret.Output.Path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
					if err != nil {
						return errors.Wrap(err, "open file failed")
					}
					defer output.Close()

					// force the mode in case we are overwrting and existing file
					os.Chmod(secret.Output.Path, mode)

					uid := os.Getuid()

					if secret.Output.User != "" {
						uid, err = LookupUid(secret.Output.User)
						if err != nil {
							return errors.Errorf("invalid user: %v", secret.Output.User)
						}
					}

					gid := os.Getgid()

					if secret.Output.Group != "" {
						gid, err = LookupGid(secret.Output.Group)
						if err != nil {
							return errors.Errorf("invalid user: %v", secret.Output.User)
						}
					}

					os.Chown(secret.Output.Path, uid, gid)

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
					return errors.Errorf("expected input type string was %v", secretInputType)
				}

				env = append(env, fmt.Sprintf("%v=%v", secret.Output.Name, value.(string)))

			default:
				return errors.Errorf("invalid output type: %v", secretOutputType)
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
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "vault-exec [manifest] <command> <arg> <arg>...")
		os.Exit(1)
	}

	check := func(err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
			os.Exit(2)
		}
	}

	manifest, err := LoadManifest(os.Args[1])
	check(err)

	client, err := Authorize(manifest)
	check(err)

	env, err := GetSecrets(manifest, client)
	check(err)

	args := []string{"sh", "-c", manifest.Command}

	if len(os.Args) > 2 {
		args = os.Args[2:]
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = manifest.Dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if manifest.User != "" {
		uid, gid, err := LookupUser(manifest.User)
		check(err)

		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uid,
				Gid: gid,
			},
		}
	}

	check(cmd.Run())
}
