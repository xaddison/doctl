/*
Copyright 2018 The Doctl Authors All rights reserved.
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

package commands

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/digitalocean/doctl"
	"github.com/digitalocean/doctl/config"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

const (
	defaultConfigName = "config.yaml" // default name of config file
)

var (
	//DoitCmd is the root level doctl command that all other commands attach to
	DoitCmd = &Command{ // base command
		Command: &cobra.Command{
			Use:   "doctl",
			Short: "doctl is a command line interface for the DigitalOcean API.",
		},
		CmdConfigConfig: config.NewConfig(),
	}

	//Writer wires up stdout for all commands to write to
	Writer = os.Stdout
	//APIURL customize API base URL
	APIURL string
	//Context current auth context
	Context string
	//Output global output format
	Output string
	//Token global authorization token
	Token string
	//Trace toggles http tracing output
	Trace bool
	//Verbose toggle verbose output on and off
	Verbose bool

	cfgFileWriter = defaultConfigFileWriter // create default cfgFileWriter
	requiredColor = color.New(color.Bold).SprintfFunc()
)

func init() {
	var cfgFile string

	initConfig()

	rootPFlagSet := DoitCmd.PersistentFlags()
	rootPFlagSet.StringVarP(&cfgFile, "config", "c",
		filepath.Join(configHome(), defaultConfigName), "config file")
	DoitCmd.CmdConfigConfig.V.BindPFlag("config", rootPFlagSet.Lookup("config"))

	rootPFlagSet.StringVarP(&APIURL, "api-url", "u", "", "Override default API V2 endpoint")
	DoitCmd.CmdConfigConfig.V.BindPFlag("api-url", rootPFlagSet.Lookup("api-url"))

	rootPFlagSet.StringVarP(&Token, doctl.ArgAccessToken, "t", "", "API V2 Access Token")
	DoitCmd.CmdConfigConfig.V.BindPFlag(doctl.ArgAccessToken, rootPFlagSet.Lookup("access-token"))

	rootPFlagSet.StringVarP(&Output, "output", "o", "text", "output format [text|json]")
	DoitCmd.CmdConfigConfig.V.BindPFlag("output", rootPFlagSet.Lookup("output"))

	rootPFlagSet.StringVarP(&Context, doctl.ArgContext, "", defaultContext, "authentication context")
	rootPFlagSet.BoolVarP(&Trace, "trace", "", false, "trace api access")
	rootPFlagSet.BoolVarP(&Verbose, doctl.ArgVerbose, "v", false, "verbose output")

	addCommands()

	cobra.OnInitialize(initConfig)
}

func initConfig() {
	DoitCmd.CmdConfigConfig.V.SetEnvPrefix("DIGITALOCEAN")
	DoitCmd.CmdConfigConfig.V.AutomaticEnv()
	DoitCmd.CmdConfigConfig.V.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	DoitCmd.CmdConfigConfig.V.SetConfigType("yaml")

	cfgFile := DoitCmd.CmdConfigConfig.V.GetString("config")
	DoitCmd.CmdConfigConfig.V.SetConfigFile(cfgFile)

	DoitCmd.CmdConfigConfig.V.SetDefault("output", "text")
	DoitCmd.CmdConfigConfig.V.SetDefault("context", defaultContext)

	if _, err := os.Stat(cfgFile); err == nil {
		if err := DoitCmd.CmdConfigConfig.V.ReadInConfig(); err != nil {
			log.Fatalln("reading initialization failed:", err)
		}
	}
}

// in case we ever want to change this, or let folks configure it...
func configHome() string {
	cfgDir, err := os.UserConfigDir()
	checkErr(err)

	ch := filepath.Join(cfgDir, "doctl")
	err = os.MkdirAll(ch, 0755)
	checkErr(err)

	return ch
}

// Execute executes the current command using DoitCmd.
func Execute() {
	if err := DoitCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

// AddCommands adds sub commands to the base command.
func addCommands() {
	DoitCmd.AddCommand(Account())
	DoitCmd.AddCommand(Auth())
	DoitCmd.AddCommand(Completion())
	DoitCmd.AddCommand(computeCmd())
	DoitCmd.AddCommand(Kubernetes())
	DoitCmd.AddCommand(Databases())
	DoitCmd.AddCommand(Projects())
	DoitCmd.AddCommand(Version())
}

func computeCmd() *Command {
	cmd := &Command{
		Command: &cobra.Command{
			Use:   "compute",
			Short: "compute commands",
			Long:  "compute commands are for controlling and managing infrastructure",
		},
	}

	cmd.AddCommand(Actions())
	cmd.AddCommand(CDN())
	cmd.AddCommand(Certificate())
	cmd.AddCommand(DropletAction())
	cmd.AddCommand(Droplet())
	cmd.AddCommand(Domain())
	cmd.AddCommand(Firewall())
	cmd.AddCommand(FloatingIP())
	cmd.AddCommand(FloatingIPAction())
	cmd.AddCommand(Images())
	cmd.AddCommand(ImageAction())
	cmd.AddCommand(LoadBalancer())
	cmd.AddCommand(Plugin())
	cmd.AddCommand(Region())
	cmd.AddCommand(Size())
	cmd.AddCommand(Snapshot())
	cmd.AddCommand(SSHKeys())
	cmd.AddCommand(Tags())
	cmd.AddCommand(Volume())
	cmd.AddCommand(VolumeAction())

	// SSH is different since it doesn't have any subcommands. In this case, let's
	// give it a parent at init time.
	SSH(cmd)

	return cmd
}

type flagOpt func(c *Command, name, key string)

// key is already manually namespaced when requiredOpt is called
// this flow is totally borked and will be cleaned up in a subsequent changeset
func requiredOpt() flagOpt {
	return func(c *Command, name, key string) {
		c.MarkFlagRequired(key)
		DoitCmd.CmdConfigConfig.V.Set(fmt.Sprintf("required.%s", key), true)
		c.Flag(name).Usage = fmt.Sprintf("%s %s", c.Flag(name).Usage, requiredColor("(required)"))
	}
}

// All of these AddXXXFlags work by binding the flag to the root viper instance, then
// manually managing the namespaces, relationships, etc. It's extremely brittle, high touch
// and flaky. We're unwinding it in a series of changesets.
//
// Hold on to your hats!

// AddStringFlag adds a string flag to a command.
func AddStringFlag(cmd *Command, name, shorthand, dflt, desc string, opts ...flagOpt) {
	fn := flagName(cmd, name)
	cmd.Flags().StringP(name, shorthand, dflt, desc)

	for _, o := range opts {
		o(cmd, name, fn)
	}

	DoitCmd.CmdConfigConfig.V.BindPFlag(fn, cmd.Flags().Lookup(name))
}

// AddIntFlag adds an integr flag to a command.
func AddIntFlag(cmd *Command, name, shorthand string, def int, desc string, opts ...flagOpt) {
	fn := flagName(cmd, name)
	cmd.Flags().IntP(name, shorthand, def, desc)
	DoitCmd.CmdConfigConfig.V.BindPFlag(fn, cmd.Flags().Lookup(name))

	for _, o := range opts {
		o(cmd, name, fn)
	}
}

// AddBoolFlag adds a boolean flag to a command.
func AddBoolFlag(cmd *Command, name, shorthand string, def bool, desc string, opts ...flagOpt) {
	fn := flagName(cmd, name)
	cmd.Flags().BoolP(name, shorthand, def, desc)
	DoitCmd.CmdConfigConfig.V.BindPFlag(fn, cmd.Flags().Lookup(name))

	for _, o := range opts {
		o(cmd, name, fn)
	}
}

// AddStringSliceFlag adds a string slice flag to a command.
func AddStringSliceFlag(cmd *Command, name, shorthand string, def []string, desc string, opts ...flagOpt) {
	fn := flagName(cmd, name)
	cmd.Flags().StringSliceP(name, shorthand, def, desc)
	DoitCmd.CmdConfigConfig.V.BindPFlag(fn, cmd.Flags().Lookup(name))

	for _, o := range opts {
		o(cmd, name, fn)
	}
}

func flagName(cmd *Command, name string) string {
	if cmd.Parent() != nil {
		return fmt.Sprintf("%s.%s.%s", cmd.Parent().Name(), cmd.Name(), name)
	}
	return fmt.Sprintf("%s.%s", cmd.Name(), name)
}

func cmdNS(cmd *cobra.Command) string {
	if cmd.Parent() != nil {
		return fmt.Sprintf("%s.%s", cmd.Parent().Name(), cmd.Name())
	}
	return fmt.Sprintf("%s", cmd.Name())
}

func writeConfig() error {
	f, err := cfgFileWriter()
	if err != nil {
		return err
	}

	defer f.Close()

	b, err := yaml.Marshal(DoitCmd.CmdConfigConfig.V.AllSettings())
	if err != nil {
		return errors.New("unable to encode configuration to YAML format")
	}

	_, err = f.Write(b)
	if err != nil {
		return errors.New("unable to write configuration")
	}

	return nil
}

func defaultConfigFileWriter() (io.WriteCloser, error) {
	cfgFile := DoitCmd.CmdConfigConfig.V.GetString("config")
	f, err := os.Create(cfgFile)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(cfgFile, 0600); err != nil {
		return nil, err
	}

	return f, nil
}
