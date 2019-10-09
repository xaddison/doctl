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
	"github.com/digitalocean/doctl/commands/displayers"
	"github.com/digitalocean/doctl/config"
	"github.com/digitalocean/doctl/do"
	"github.com/digitalocean/doctl/pkg/ssh"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

const (
	defaultConfigName = "config.yaml" // default name of config file
	defaultContext    = "default"     // default authentication context
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

var getCurrentAuthContextFn = defaultGetCurrentAuthContextFn

func defaultGetCurrentAuthContextFn() string {
	if Context != "" {
		return Context
	}
	if authContext := DoitCmd.CmdConfigConfig.V.GetString("context"); authContext != "" {
		return authContext
	}
	return defaultContext
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

// CmdRunner runs a command and passes in a cmdConfig.
type CmdRunner func(*CmdConfig) error

// CmdConfig is a command configuration.
type CmdConfig struct {
	NS   string
	Out  io.Writer
	Args []string

	// Config wraps a viper instance
	Config *config.Config
	// SSH wraps an ssh connection
	SSH func(user, host, keyPath string, port int, opts ssh.Options) *ssh.Runner

	initServices          func(*CmdConfig) error
	getContextAccessToken func() string
	setContextAccessToken func(string)

	// services
	Keys              func() do.KeysService
	Sizes             func() do.SizesService
	Regions           func() do.RegionsService
	Images            func() do.ImagesService
	ImageActions      func() do.ImageActionsService
	LoadBalancers     func() do.LoadBalancersService
	FloatingIPs       func() do.FloatingIPsService
	FloatingIPActions func() do.FloatingIPActionsService
	Droplets          func() do.DropletsService
	DropletActions    func() do.DropletActionsService
	Domains           func() do.DomainsService
	Actions           func() do.ActionsService
	Account           func() do.AccountService
	Tags              func() do.TagsService
	Volumes           func() do.VolumesService
	VolumeActions     func() do.VolumeActionsService
	Snapshots         func() do.SnapshotsService
	Certificates      func() do.CertificatesService
	Firewalls         func() do.FirewallsService
	CDNs              func() do.CDNsService
	Projects          func() do.ProjectsService
	Kubernetes        func() do.KubernetesService
	Databases         func() do.DatabasesService
}

// NewCmdConfig creates an instance of a CmdConfig.
func NewCmdConfig(ns string, viper *config.Config, out io.Writer, args []string, initGodo bool) (*CmdConfig, error) {

	cmdConfig := &CmdConfig{
		NS:     ns,
		Out:    out,
		Config: viper,
		SSH:    ssh.SSH,
		Args:   args,

		initServices: func(c *CmdConfig) error {
			accessToken := c.getContextAccessToken()
			apiURL := DoitCmd.CmdConfigConfig.V.GetString("api-url")
			godoClient, err := config.GetGodoClient(Trace, apiURL, accessToken)
			if err != nil {
				return fmt.Errorf("unable to initialize DigitalOcean api client: %s", err)
			}

			c.Keys = func() do.KeysService { return do.NewKeysService(godoClient) }
			c.Sizes = func() do.SizesService { return do.NewSizesService(godoClient) }
			c.Regions = func() do.RegionsService { return do.NewRegionsService(godoClient) }
			c.Images = func() do.ImagesService { return do.NewImagesService(godoClient) }
			c.ImageActions = func() do.ImageActionsService { return do.NewImageActionsService(godoClient) }
			c.FloatingIPs = func() do.FloatingIPsService { return do.NewFloatingIPsService(godoClient) }
			c.FloatingIPActions = func() do.FloatingIPActionsService { return do.NewFloatingIPActionsService(godoClient) }
			c.Droplets = func() do.DropletsService { return do.NewDropletsService(godoClient) }
			c.DropletActions = func() do.DropletActionsService { return do.NewDropletActionsService(godoClient) }
			c.Domains = func() do.DomainsService { return do.NewDomainsService(godoClient) }
			c.Actions = func() do.ActionsService { return do.NewActionsService(godoClient) }
			c.Account = func() do.AccountService { return do.NewAccountService(godoClient) }
			c.Tags = func() do.TagsService { return do.NewTagsService(godoClient) }
			c.Volumes = func() do.VolumesService { return do.NewVolumesService(godoClient) }
			c.VolumeActions = func() do.VolumeActionsService { return do.NewVolumeActionsService(godoClient) }
			c.Snapshots = func() do.SnapshotsService { return do.NewSnapshotsService(godoClient) }
			c.Certificates = func() do.CertificatesService { return do.NewCertificatesService(godoClient) }
			c.LoadBalancers = func() do.LoadBalancersService { return do.NewLoadBalancersService(godoClient) }
			c.Firewalls = func() do.FirewallsService { return do.NewFirewallsService(godoClient) }
			c.CDNs = func() do.CDNsService { return do.NewCDNsService(godoClient) }
			c.Projects = func() do.ProjectsService { return do.NewProjectsService(godoClient) }
			c.Kubernetes = func() do.KubernetesService { return do.NewKubernetesService(godoClient) }
			c.Databases = func() do.DatabasesService { return do.NewDatabasesService(godoClient) }

			return nil
		},

		// these details should get moved into config
		getContextAccessToken: func() string {
			context := Context
			if context == "" {
				context = DoitCmd.CmdConfigConfig.V.GetString("context")
			}
			token := ""

			switch context {
			case defaultContext:
				token = DoitCmd.CmdConfigConfig.V.GetString(doctl.ArgAccessToken)
			default:
				contexts := DoitCmd.CmdConfigConfig.V.GetStringMapString("auth-contexts")

				token = contexts[context]
			}

			return token
		},

		// these details should get moved into config
		setContextAccessToken: func(token string) {
			context := Context
			if context == "" {
				context = DoitCmd.CmdConfigConfig.V.GetString("context")
			}

			switch context {
			case defaultContext:
				DoitCmd.CmdConfigConfig.V.Set(doctl.ArgAccessToken, token)
			default:
				contexts := DoitCmd.CmdConfigConfig.V.GetStringMapString("auth-contexts")
				contexts[context] = token

				DoitCmd.CmdConfigConfig.V.Set("auth-contexts", contexts)
			}
		},
	}

	if initGodo {
		if err := cmdConfig.initServices(cmdConfig); err != nil {
			return nil, err
		}
	}

	return cmdConfig, nil
}

// Display displays the output from a command.
func (c *CmdConfig) Display(d displayers.Displayable) error {
	dc := &displayers.Displayer{
		Item: d,
		Out:  c.Out,
	}

	columnList, err := c.Config.GetString(c.NS, doctl.ArgFormat)
	if err != nil {
		return err
	}

	withHeaders, err := c.Config.GetBool(c.NS, doctl.ArgNoHeader)
	if err != nil {
		return err
	}

	dc.NoHeaders = withHeaders
	dc.ColumnList = columnList
	dc.OutputType = Output

	return dc.Display()
}

// CmdBuilder builds a new command.
func CmdBuilder(parent *Command, cr CmdRunner, cliText, desc string, out io.Writer, options ...cmdOption) *Command {
	return cmdBuilderWithInit(parent, cr, cliText, desc, out, true, options...)
}

func cmdBuilderWithInit(parent *Command, cr CmdRunner, cliText, desc string, out io.Writer, initCmd bool, options ...cmdOption) *Command {

	viperInstance := config.NewConfig()

	cobraCommand := &cobra.Command{
		Use:   cliText,
		Short: desc,
		Long:  desc,
		Run: func(cmd *cobra.Command, args []string) {
			c, err := NewCmdConfig(
				cmdNS(cmd),
				viperInstance,
				out,
				args,
				initCmd,
			)
			checkErr(err)

			err = cr(c)
			checkErr(err)
		},
	}

	c := &Command{
		Command:         cobraCommand,
		CmdConfigConfig: viperInstance,
	}

	if parent != nil {
		parent.AddCommand(c)
	}

	for _, co := range options {
		co(c)
	}

	if cols := c.fmtCols; cols != nil {
		formatHelp := fmt.Sprintf("Columns for output in a comma separated list. Possible values: %s",
			strings.Join(cols, ","))
		AddStringFlag(c, doctl.ArgFormat, "", "", formatHelp)
		AddBoolFlag(c, doctl.ArgNoHeader, "", false, "hide headers")
	}

	return c

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
