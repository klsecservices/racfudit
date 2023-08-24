package common

import (
    "flag"
    "fmt"
    "log"
    "os"
)

type Logger struct {
    info    *log.Logger
    debug   *log.Logger
    warning *log.Logger
    error   *log.Logger
    f       *os.File
}

func (l *Logger) Info(format string, a ...any) {
    l.info.Printf(format, a...)
}

func (l *Logger) Debug(format string, a ...any) {
    l.debug.Printf(format, a...)
}

func (l *Logger) Warning(format string, a ...any) {
    l.warning.Printf(format, a...)
}

func (l *Logger) Error(format string, a ...any) {
    l.error.Printf(format, a...)
}

func (l *Logger) Fatal(v ...any) {
    l.error.Fatal(v...)
}

func (l *Logger) Close() {
    if l.f != nil {
        l.f.Close()
    }
}

func Fatal(v ...any) {
    if Log == nil {
        fmt.Println(v...)
        flag.Usage()
        os.Exit(1)
    }
    Log.Fatal(v...)
}
