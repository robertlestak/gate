package gate

import (
	"encoding/json"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Config struct {
	KeyFile  string            `json:"keyFile" yaml:"keyFile"`
	Upstream *Upstream         `json:"upstream" yaml:"upstream"`
	Server   *GateServerConfig `json:"gate" yaml:"gate"`
}

func (c *Config) LoadFile(f string) error {
	l := log.WithFields(log.Fields{
		"fn": "LoadFile",
	})
	l.Debug("Loading config file")
	fd, err := os.ReadFile(f)
	if err != nil {
		l.WithError(err).Error("Failed to read config file")
		return err
	}
	if err := yaml.Unmarshal(fd, c); err != nil {
		l.WithError(err).Debug("Failed to unmarshal yaml config")
		if err := json.Unmarshal(fd, c); err != nil {
			l.WithError(err).Error("Failed to unmarshal json config")
			return err
		}
	}
	return nil
}
