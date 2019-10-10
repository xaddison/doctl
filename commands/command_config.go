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
	"fmt"
	"io"
	"strings"

	"github.com/digitalocean/doctl"
	"github.com/digitalocean/doctl/commands/displayers"
	"github.com/digitalocean/doctl/config"
	"github.com/digitalocean/doctl/do"
	"github.com/digitalocean/doctl/pkg/ssh"

	"github.com/spf13/cobra"
)

// CmdConfig is a command configuration.
type CmdConfig struct {
	NS           string
	CobraCommand *cobra.Command
	Out          io.Writer
	Args         []string

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
func NewCmdConfig(ns string, cobraCommand *cobra.Command, out io.Writer, args []string, viper *config.Config, initGodo bool) (*CmdConfig, error) {

	cmdConfig := &CmdConfig{
		NS:           ns,
		CobraCommand: cobraCommand,
		Out:          out,
		Args:         args,
		Config:       viper,
		SSH:          ssh.SSH,

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
			case doctl.ArgDefaultContext:
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
			case doctl.ArgDefaultContext:
				DoitCmd.CmdConfigConfig.V.Set(doctl.ArgAccessToken, token)
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

// CmdRunner runs a command and passes in a cmdConfig.
type CmdRunner func(*CmdConfig) error

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
				cmd,
				out,
				args,
				viperInstance,
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
