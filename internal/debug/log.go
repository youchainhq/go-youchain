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

package debug

import (
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/youchainhq/go-youchain/logging"
	"io"
	"os"
)

func SetupLogger(printOrigin bool, level int, vmodule string, logDir string) error {
	logging.PrintOrigins(printOrigin)

	verbosity := logging.Lvl(level)
	logging.Verbosity(verbosity)
	err := logging.Vmodule(vmodule)
	if err != nil {
		return err
	}

	if logDir != "" {
		//terminal handler
		usecolor := (isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())) && os.Getenv("TERM") != "dumb"
		output := io.Writer(os.Stdout)
		if usecolor {
			output = colorable.NewColorableStderr()
		}

		//setup file rotate handler
		config := logging.NewRotateConfig()
		config.LogDir = logDir
		rfh := logging.NewFileRotateHandler(config, logging.TerminalFormat(usecolor))

		ostream := logging.StreamHandler(output, logging.TerminalFormat(usecolor))
		logging.GRoot().SetHandler(logging.MultiHandler(ostream, rfh))
	}

	return nil
}

func PrintOrigin(yesOrNot bool) {
	logging.PrintOrigins(yesOrNot)
}

func Verbosity(level int) {
	logging.Verbosity(logging.Lvl(level))
}

func Vmodule(pattern string) error {
	return logging.Vmodule(pattern)
}
