// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package utils

import (
	"io"

	"github.com/urfave/cli"
)

var CliDefaultHelpTemplate string

// AppHelpTemplate is the template for the default, global app help topic.
var AppHelpTemplate = `Name:
   {{.App.Name}} - {{.App.Usage}}

   Copyright 2018-2020 YOUCHAIN FOUNDATION LTD.

Usage:
   {{.App.HelpName}} [options]{{if .App.Commands}} [command [command options]]{{end}} {{if .App.ArgsUsage}}{{.App.ArgsUsage}}{{else}}[arguments...]{{end}}
   {{if .App.Version}}
Version:
   {{.App.Version}}
   {{end}}{{if .App.Description}}
Description:
   {{.App.Description}}
   {{end}}{{if len .App.Authors}}
Author(S):
   {{range .App.Authors}}{{ . }}{{end}}
   {{end}}{{if .App.VisibleCommands}}
Commands:
   {{range .App.VisibleCategories}}{{if .Name}}

   {{.Name}}:{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{else}}{{range .VisibleCommands}}
   {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{if .FlagGroups}}

Global options:
  {{range .FlagGroups}}{{.Name}} options:
    {{if .Description}}{{.Description}}
  {{end}}
    {{range .Flags}}{{.}}
    {{end}}
  {{end}}{{end}}{{if .App.Copyright }}
Copyright:
   {{.App.Copyright}}
   {{end}}
Use "{{.App.Name}} help [COMMAND]" or "{{.App.Name}} [COMMAND] --help" for more information on a command. 
`

type flagGroup struct {
	Name        string
	Description string
	Flags       []cli.Flag
}

var AppHelpFlagGroups = []flagGroup{
	{
		Name:        "Basic",
		Description: "",
		Flags:       BasicFlags,
	},
	{
		Name:        "Miner",
		Description: "Options for miner, be cautious about the validator key options, see corresponding document for detail.",
		Flags:       MinerFlags,
	},
	{
		Name:        "Consensus",
		Description: "These options are mainly for testing or running a new chain.",
		Flags:       ConsFlags,
	},
	{
		Name:        "RPC",
		Description: "Options for providing rpc services.",
		Flags:       RPCFlags,
	},
	{
		Name:        "P2P",
		Description: "These options are mainly for P2P.",
		Flags:       P2PFlags,
	},
	{
		Name:        "Metrics",
		Description: "These options are mainly for debugging.",
		Flags:       MetricsFlags,
	},
	{
		Name:        "TxPool",
		Description: "These options are mainly for TxPool.",
		Flags:       TxPoolFlags,
	},
	{
		Name:        "DevOp",
		Description: "These options are mainly for DevOp.",
		Flags:       DevOpFlags,
	},
}

func init() {
	CliDefaultHelpTemplate = cli.AppHelpTemplate
	// Define a one shot struct to pass to the usage template
	type helpData struct {
		App        interface{}
		FlagGroups []flagGroup
	}
	cli.AppHelpTemplate = AppHelpTemplate

	originalHelpPrinter := cli.HelpPrinter
	cli.HelpPrinter = func(w io.Writer, tmpl string, data interface{}) {
		if tmpl == AppHelpTemplate {
			// Iterate over all the flags and add any uncategorized ones
			categorized := make(map[string]struct{})
			for _, group := range AppHelpFlagGroups {
				for _, flag := range group.Flags {
					categorized[flag.String()] = struct{}{}
				}
			}
			var uncategorized []cli.Flag
			for _, flag := range data.(*cli.App).Flags {
				if _, ok := categorized[flag.String()]; !ok {
					uncategorized = append(uncategorized, flag)
				}
			}
			if len(uncategorized) > 0 {
				// Append all ungategorized options to the misc group
				miscs := len(AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags)
				AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags = append(AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags, uncategorized...)

				// Make sure they are removed afterwards
				defer func() {
					AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags = AppHelpFlagGroups[len(AppHelpFlagGroups)-1].Flags[:miscs]
				}()
			}
			// Render out custom usage screen
			originalHelpPrinter(w, tmpl, helpData{data, AppHelpFlagGroups})
		} else {
			originalHelpPrinter(w, tmpl, data)
		}
	}

}
