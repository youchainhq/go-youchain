package logging

import (
	"fmt"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"io"
	"os"
)

var (
	root        = &logger{[]interface{}{}, new(swapHandler)}
	rootStream  Handler
	rootGlogger *GlogHandler
)

func init() {
	setupDefault()
}

func setupDefault() {
	usecolor := (isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())) && os.Getenv("TERM") != "dumb"
	output := io.Writer(os.Stdout)
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	rootStream = StreamHandler(output, TerminalFormat(usecolor))

	//rootGlogger as root
	rootGlogger = NewGlogHandler(rootStream)
	rootGlogger.Verbosity(LvlInfo)
	PrintOrigins(true)

	root.SetHandler(rootGlogger)
}

// New returns a new logger with the given context.
// New is a convenient alias for Root().New
func New(ctx ...interface{}) Logger {
	return root.New(ctx...)
}

// Root returns the root logger
func Root() Logger {
	return root
}

func Verbosity(lvl Lvl) {
	rootGlogger.Verbosity(lvl)
}

// Root returns the root logger
func GRoot() *GlogHandler {
	return rootGlogger
}

func Vmodule(ruleset string) error {
	return rootGlogger.Vmodule(ruleset)
}

// The following functions bypass the exported logger methods (logger.Debug,
// etc.) to keep the call depth the same for all paths to logger.write so
// runtime.Caller(2) always refers to the call site in client code.

// Trace is a convenient alias for Root().Trace
func Trace(msg string, ctx ...interface{}) {
	root.write(msg, LvlTrace, ctx, skipLevel)
}

func Tracef(format string, v ...interface{}) {
	root.write(fmt.Sprintf(format, v...), LvlTrace, nil, skipLevel)
}

// Debug is a convenient alias for Root().Debug
func Debug(msg string, ctx ...interface{}) {
	root.write(msg, LvlDebug, ctx, skipLevel)
}

func Debugf(format string, v ...interface{}) {
	root.write(fmt.Sprintf(format, v...), LvlDebug, nil, skipLevel)
}

// Info is a convenient alias for Root().Info
func Info(msg string, ctx ...interface{}) {
	root.write(msg, LvlInfo, ctx, skipLevel)
}

func Infof(format string, v ...interface{}) {
	root.write(fmt.Sprintf(format, v...), LvlInfo, nil, skipLevel)
}

// Warn is a convenient alias for Root().Warn
func Warn(msg string, ctx ...interface{}) {
	root.write(msg, LvlWarn, ctx, skipLevel)
}

func Warnf(format string, v ...interface{}) {
	root.write(fmt.Sprintf(format, v...), LvlWarn, nil, skipLevel)
}

// Error is a convenient alias for Root().Error
func Error(msg string, ctx ...interface{}) {
	root.write(msg, LvlError, ctx, skipLevel)
}

func Errorf(format string, v ...interface{}) {
	root.write(fmt.Sprintf(format, v...), LvlError, nil, skipLevel)
}

// Crit is a convenient alias for Root().Crit
func Crit(msg string, ctx ...interface{}) {
	root.write(msg, LvlCrit, ctx, skipLevel)
	os.Exit(1)
}

func Critf(format string, v ...interface{}) {
	root.write(fmt.Sprintf(format, v...), LvlCrit, nil, skipLevel)
}

// Output is a convenient alias for write, allowing for the modification of
// the calldepth (number of stack frames to skip).
// calldepth influences the reported line number of the log message.
// A calldepth of zero reports the immediate caller of Output.
// Non-zero calldepth skips as many stack frames.
func Output(msg string, lvl Lvl, calldepth int, ctx ...interface{}) {
	root.write(msg, lvl, ctx, calldepth+skipLevel)
}
