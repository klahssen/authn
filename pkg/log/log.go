package log

import (
	"go.uber.org/zap"
)

var (
	logger Logger
)

//Logger interface
type Logger interface {
	//SetLevel(level string) error
	Infof(template string, args ...interface{})
	Info(args ...interface{})
	Warnf(template string, args ...interface{})
	Warn(args ...interface{})
	Fatalf(template string, args ...interface{})
	Fatal(args ...interface{})
	Errorf(template string, args ...interface{})
	Error(args ...interface{})
	Debugf(template string, args ...interface{})
	Debug(args ...interface{})
}

func newZapConfig() zap.Config {
	return zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:       true,
		Encoding:          "console",
		EncoderConfig:     zap.NewDevelopmentEncoderConfig(),
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
		DisableStacktrace: true,
	}
}

func init() {
	//l := zap.NewExample(zap.Development())
	//l, _ := zap.NewDevelopment()
	l, _ := newZapConfig().Build()
	logger = l.Sugar()
}

//SetLogger replaces default zap Sugar logger
func SetLogger(l Logger) {
	if l != nil {
		logger = l
	}
}

//Infof method
func Infof(template string, args ...interface{}) {
	logger.Infof(template, args...)
}

//Info method
func Info(args ...interface{}) {
	logger.Info(args...)
}

//Warnf method
func Warnf(template string, args ...interface{}) {
	logger.Warnf(template, args...)
}

//Warn method
func Warn(args ...interface{}) {
	logger.Warn(args...)
}

//Fatalf method
func Fatalf(template string, args ...interface{}) {
	logger.Fatalf(template, args...)
}

//Fatal method
func Fatal(args ...interface{}) {
	logger.Fatal(args...)
}

//Errorf method
func Errorf(template string, args ...interface{}) {
	logger.Errorf(template, args...)
}

//Error method
func Error(args ...interface{}) {
	logger.Error(args...)
}

//Debugf method
func Debugf(template string, args ...interface{}) {
	logger.Debugf(template, args...)
}

//Debug method
func Debug(args ...interface{}) {
	logger.Debug(args...)
}
