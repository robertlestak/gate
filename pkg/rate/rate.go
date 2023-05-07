package rate

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/robertlestak/memory/pkg/memory"
	log "github.com/sirupsen/logrus"
)

type Origin struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func (o *Origin) nameHash() string {
	// sha256 hash of name
	h := sha256.New()
	h.Write([]byte(o.Name))
	return string(h.Sum(nil))
}

func (o *Origin) Get() error {
	return memory.Get("rate:origin:"+o.nameHash(), o)
}

func (o *Origin) Set() error {
	return memory.Set("rate:origin:"+o.nameHash(), o)
}

func (o *Origin) Delete() error {
	return memory.Delete("rate:origin:" + o.nameHash())
}

func (o *Origin) Incr() error {
	o.Count++
	return o.Set()
}

func (o *Origin) Decr() error {
	o.Count--
	return o.Set()
}

func (o *Origin) Reset() error {
	o.Count = 0
	return o.Set()
}

func (o *Origin) IsOverLimit(limit int) bool {
	return o.Count > limit
}

func HandleOriginRequest(host string, limit int) error {
	origin := &Origin{Name: host}
	err := origin.Get()
	if err != nil {
		return err
	}
	if origin.IsOverLimit(limit) {
		return errors.New("rate limit exceeded")
	}
	err = origin.Incr()
	if err != nil {
		return err
	}
	// decrease count after 1 second
	go func() {
		time.Sleep(1 * time.Second)
		err := origin.Decr()
		if err != nil {
			log.WithFields(log.Fields{
				"fn":    "HandleOriginRequest",
				"error": err,
			}).Error("Failed to decrease origin count")
		}
	}()
	return nil
}
