/*
Copyright 2018-2019 The Doctl Authors All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/digitalocean/doctl"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// LiveConfig is an implementation of Config for live values.
type Config struct {
	V *viper.Viper
}

// NewConfig returns a config with a new viper instance
func NewConfig() *Config {
	v := viper.New()
	v.SetEnvPrefix("DIGITALOCEAN")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.SetConfigType("yaml")

	v.SetDefault(doctl.ArgOutput, "text")
	v.SetDefault(doctl.ArgContext, doctl.ArgDefaultContext)

	return &Config{V: v}
}

func (c *Config) Load(cmd *cobra.Command, cfgFile string) {
	c.V.SetConfigFile(cfgFile)
	if err := c.V.ReadInConfig(); err != nil {
		log.Fatalln("reading initialization failed:", err)
	}

	c.V.BindPFlags(cmd.Flags())
}

// Set sets a config key.
func (c *Config) Set(ns, key string, val interface{}) {
	c.V.Set(NsKey(ns, key), val)
}

// IsSet checks whether flag is set.
func (c *Config) IsSet(ns, key string) bool {
	return c.V.IsSet(NsKey(ns, key))
}

// GetString returns a config value as a string.
func (c *Config) GetString(ns, key string) (string, error) {
	nskey := NsKey(ns, key)
	str := c.V.GetString(nskey)

	if c.isRequired(nskey) && strings.TrimSpace(str) == "" {
		return "", doctl.NewMissingArgsErr(nskey)
	}
	return str, nil
}

// GetBool returns a config value as a bool.
func (c *Config) GetBool(ns, key string) (bool, error) {
	return c.V.GetBool(NsKey(ns, key)), nil
}

// GetBoolPtr returns a config value as a bool pointer.
func (c *Config) GetBoolPtr(ns, key string) (*bool, error) {
	if !c.IsSet(ns, key) {
		return nil, nil
	}
	val := c.V.GetBool(NsKey(ns, key))
	return &val, nil
}

// GetInt returns a config value as an int.
func (c *Config) GetInt(ns, key string) (int, error) {
	nskey := NsKey(ns, key)
	val := c.V.GetInt(nskey)

	if c.isRequired(nskey) && val == 0 {
		return 0, doctl.NewMissingArgsErr(nskey)
	}
	return val, nil
}

// GetIntPtr returns a config value as an int pointer.
func (c *Config) GetIntPtr(ns, key string) (*int, error) {
	nskey := NsKey(ns, key)

	if !c.IsSet(ns, key) {
		if c.isRequired(nskey) {
			return nil, doctl.NewMissingArgsErr(nskey)
		}
		return nil, nil
	}
	val := c.V.GetInt(nskey)
	return &val, nil
}

// GetStringSlice returns a config value as a string slice.
func (c *Config) GetStringSlice(ns, key string) ([]string, error) {
	nskey := NsKey(ns, key)
	val := c.V.GetStringSlice(nskey)

	if c.isRequired(nskey) && emptyStringSlice(val) {
		return nil, doctl.NewMissingArgsErr(nskey)
	}

	// TODO: TestConfig version did not unpack the string slice
	// Why do we?
	out := []string{}
	for _, item := range val {
		item = strings.TrimPrefix(item, "[")
		item = strings.TrimSuffix(item, "]")

		list := strings.Split(item, ",")
		for _, str := range list {
			if str == "" {
				continue
			}
			out = append(out, str)
		}
	}
	return out, nil
}

func (c *Config) isRequired(key string) bool {
	return c.V.GetBool(fmt.Sprintf("required.%s", key))
}

func NsKey(ns, key string) string {
	return fmt.Sprintf("%s.%s", ns, key)
}

// This is needed because an empty StringSlice flag returns `["[]"]`
func emptyStringSlice(s []string) bool {
	return len(s) == 1 && s[0] == "[]"
}

