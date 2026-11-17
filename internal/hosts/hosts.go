// Package hosts loads hosts.toml, the per-repo .ostiary.toml and imports
// ~/.ssh/config. None of these files contain secrets.
package hosts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ASromancer/ostiary/internal/policy"
)

type Host struct {
	Host        string   `toml:"host" json:"host"`
	User        string   `toml:"user" json:"user"`
	Port        int      `toml:"port,omitempty" json:"port,omitempty"`
	Key         string   `toml:"key,omitempty" json:"key,omitempty"` // name of a key or password in the vault
	Profile     string   `toml:"profile,omitempty" json:"profile,omitempty"`
	Agent       bool     `toml:"agent" json:"agent"`
	Description string   `toml:"description,omitempty" json:"description,omitempty"`
	Allow       []string `toml:"allow,omitempty" json:"allow,omitempty"`
	Deny        []string `toml:"deny,omitempty" json:"deny,omitempty"`
	// Tunnels is the allow-list of host:port targets, as seen from the SSH server, an agent may ask to forward.
	Tunnels []string `toml:"tunnels,omitempty" json:"tunnels,omitempty"`
}

func (h *Host) Addr() string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(h.Host, strconv.Itoa(port))
}

func (h *Host) EffectiveProfile() string {
	if h.Profile == "" {
		return policy.ProfileStandard
	}
	return h.Profile
}

type Config struct {
	Hosts map[string]*Host `toml:"hosts"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return LoadBytes(b, path)
}

// LoadBytes parses hosts.toml content already read (name is for errors); nil is an empty config.
func LoadBytes(b []byte, path string) (*Config, error) {
	c := &Config{}
	if _, err := toml.Decode(string(b), c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Hosts == nil {
		c.Hosts = map[string]*Host{}
	}
	for name, h := range c.Hosts {
		if err := h.Validate(); err != nil {
			return nil, fmt.Errorf("%s: host %s: %w", path, name, err)
		}
	}
	return c, nil
}

func (h *Host) Validate() error {
	if h.Host == "" {
		return errors.New("missing host")
	}
	if h.Profile != "" && !policy.ValidProfile(h.Profile) {
		return fmt.Errorf("unknown profile %q (readonly|strict|standard|full)", h.Profile)
	}
	for i, t := range h.Tunnels {
		n, err := NormalizeTarget(t)
		if err != nil {
			return err
		}
		h.Tunnels[i] = n
	}
	return nil
}

// NormalizeTarget trims a tunnel target and lowercases its host. It must be host:port, port 1-65535, no spaces.
func NormalizeTarget(t string) (string, error) {
	t = strings.TrimSpace(t)
	host, port, err := net.SplitHostPort(t)
	n, perr := strconv.Atoi(port)
	if err != nil || host == "" || perr != nil || n < 1 || n > 65535 || strings.ContainsAny(t, " \t\r\n") {
		return "", fmt.Errorf("bad tunnel target %q (want host:port, port 1-65535)", t)
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(n)), nil
}

func (c *Config) Save(path string) error {
	var b bytes.Buffer
	b.WriteString("# ostiary hosts. Edit, then run 'ostiary reload' to apply.\n\n")
	if err := toml.NewEncoder(&b).Encode(c); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Repo is a .ostiary.toml found in the working directory or above.
// It can only narrow what agents see, never widen it.
type Repo struct {
	Hosts      []string `toml:"hosts"`
	MaxProfile string   `toml:"max_profile"`
	Dir        string   `toml:"-"`
}

const RepoFile = ".ostiary.toml"

// FindRepo walks up from cwd looking for .ostiary.toml. nil means none.
func FindRepo(cwd string) (*Repo, error) {
	if cwd == "" {
		return nil, nil
	}
	for dir := filepath.Clean(cwd); ; dir = filepath.Dir(dir) {
		p := filepath.Join(dir, RepoFile)
		r := &Repo{Dir: dir}
		_, err := toml.DecodeFile(p, r)
		if err == nil {
			if r.MaxProfile != "" && !policy.ValidProfile(r.MaxProfile) {
				return nil, fmt.Errorf("%s: unknown max_profile %q", p, r.MaxProfile)
			}
			return r, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if dir == filepath.Dir(dir) {
			return nil, nil
		}
	}
}

// Visible returns the hosts an agent may use, with their effective profile.
func (c *Config) Visible(r *Repo) map[string]string {
	out := map[string]string{}
	for name, h := range c.Hosts {
		if !h.Agent {
			continue
		}
		p := h.EffectiveProfile()
		if r != nil {
			listed := false
			for _, n := range r.Hosts {
				listed = listed || n == name
			}
			if !listed {
				continue
			}
			p = policy.Stricter(p, r.MaxProfile)
		}
		out[name] = p
	}
	return out
}

// Resolve maps the name an agent typed to a configured host name: an exact
// match, else the one host that differs only in case. Two such hosts are ambiguous, so no match.
func (c *Config) Resolve(name string) (string, bool) {
	if _, ok := c.Hosts[name]; ok {
		return name, true
	}
	found := ""
	for n := range c.Hosts {
		if strings.EqualFold(n, name) {
			if found != "" {
				return "", false
			}
			found = n
		}
	}
	return found, found != ""
}

// Pick resolves name among the hosts an agent may use. It returns the
// configured name and effective profile, or the message to show the agent.
func (c *Config) Pick(r *Repo, name string) (canon, profile, msg string) {
	vis := c.Visible(r)
	if canon, ok := c.Resolve(name); ok {
		if profile, ok := vis[canon]; ok {
			return canon, profile, ""
		}
	}
	names := make([]string, 0, len(vis))
	for n := range vis {
		names = append(names, n)
	}
	sort.Strings(names)
	msg = fmt.Sprintf("host %q is not available to agents here", name)
	if len(names) > 0 {
		msg += "; available: " + strings.Join(names, ", ")
	}
	return "", "", msg
}

// ImportSSHConfig reads concrete Host entries from an OpenSSH client config.
// Wildcard patterns, Match blocks and Include are skipped. Imported hosts
// are never visible to agents (agent = false) until the user enables them.
func ImportSSHConfig(path string) (map[string]*Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]*Host{}
	var cur []*Host
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, _ := strings.Cut(strings.Replace(line, "=", " ", 1), " ")
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch strings.ToLower(key) {
		case "host":
			cur = nil
			for _, n := range strings.Fields(val) {
				if strings.ContainsAny(n, "*?!") {
					continue
				}
				h := &Host{Host: n, Profile: policy.ProfileStandard}
				out[n], cur = h, append(cur, h)
			}
		case "match":
			cur = nil
		case "hostname":
			for _, h := range cur {
				h.Host = val
			}
		case "user":
			for _, h := range cur {
				h.User = val
			}
		case "port":
			p, _ := strconv.Atoi(val)
			for _, h := range cur {
				h.Port = p
			}
		}
	}
	return out, sc.Err()
}
