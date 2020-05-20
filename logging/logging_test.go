// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// This file is part of the go-youchain library.
//
// The go-youchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-youchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.

package logging

import (
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

var (
	ostream Handler
	glogger *GlogHandler
)

func TestMain(m *testing.M) {
	PrintOrigins(true)

	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	output := io.Writer(os.Stderr)
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream = StreamHandler(output, TerminalFormat(usecolor))

	glogger = NewGlogHandler(ostream)
	glogger.Verbosity(LvlInfo)

	Root().SetHandler(glogger)

	os.Exit(m.Run())
}

func TestUsage(t *testing.T) {
	//simple usage, lv ignore
	Debug("simple usage")

	//new logger context
	newLogger := New("contextKey", "contextValue")
	newLogger.Info("msg", "key", "value")
}

func TestVmodule(t *testing.T) {
	//new logger
	newLogger := New()

	//set verbosity to 3
	glogger.Verbosity(LvlInfo)

	//specifically set logging/* package to 5(less Severity)
	err := glogger.Vmodule("logging/*=5")
	if err != nil {
		t.Fatal(err)
	}

	//try to print debug level
	newLogger.Debug("output", "should seen", "logging/*=5")
}

func TestFileRotate(t *testing.T) {
	config := defaultConfig
	config.MaxSize = 1

	//clean
	_ = os.RemoveAll(config.LogDir)

	//setup file
	rfh := NewFileRotateHandler(defaultConfig, TerminalFormat(false))

	glogger.SetHandler(MultiHandler(DiscardHandler(), rfh))

	//simple usage
	newLogger := New("contextKey", "contextvalue")

	buf := make([]byte, 0x1000)
	for i := 0; i < 200; i++ {
		newLogger.Info("context info", "value", buf)
	}

	files, _ := ioutil.ReadDir(config.LogDir)

	//two file: newfile, oldfile compress
	assert.Equal(t, len(files), 2)

	//clean
	_ = os.RemoveAll(config.LogDir)
}
