package common

import (
    "flag"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "strings"
    "time"
)

type Options struct {
    RACFFile   string
    logFile    string
    DumpFile   string
    SqlFile    string
    UseFieldDB bool
}

func (o *Options) Check() error {
    if len(o.RACFFile) == 0 {
        return fmt.Errorf("RACF DB file must be set")
    } else if len(o.DumpFile) == 0 && len(o.SqlFile) == 0 {
        return fmt.Errorf("Need to set output format and filename (-dump|-sql)")
    }
    return nil
}

func (o *Options) Logger() error {
    var w io.Writer
    var f *os.File

    // Create log file if it has been set. Otherwise use io.Discard
    if len(o.logFile) > 0 {
        var err error
        ext := filepath.Ext(o.logFile)
        if len(ext) == 0 {
            ext = ".log"
        }
        hour, min, sec := time.Now().Clock()
        fileName := fmt.Sprintf("%s_%v-%v-%v%s", strings.TrimSuffix(o.logFile, ext), hour, min, sec, ext)
        f, err = os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            return err
        }
        w = f
    } else {
        w = io.Discard
    }

    // Logging INFO and ERROR message both into console and log file
    mw := io.MultiWriter(os.Stdout, w)

    Log = &Logger{
        log.New(mw, "INFO: ", 0),
        log.New(w, "DEBUG: ", 0),
        log.New(w, "WARNING: ", 0),
        log.New(mw, "ERROR: ", 0),
        f,
    }

    return nil
}

func ParseFlags() {
    Opt = &Options{}

    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "RACF DB extracting tool (%s)\n", os.Args[0])
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "Examples:\n")
        fmt.Fprintf(os.Stderr, "  %s -f <RACF_DB> -sql <sqlite3.db>\n\textract RACF DB content to sqlite3 DB\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "  %s -f <RACF_DB> -log <logfile> -dump <dump.txt> \n\textract RACF DB content to plain text file and save warning and debug info to log file\n", os.Args[0])
    }

    flag.StringVar(&Opt.RACFFile, "f", "", "input RACF DB file")
    flag.StringVar(&Opt.logFile, "log", "", "save debug and warning info to log file")
    flag.StringVar(&Opt.DumpFile, "dump", "", "dump RACF DB as plain text")
    flag.StringVar(&Opt.SqlFile, "sql", "", "convert RACF DB to sqlite3 DB")
    flag.BoolVar(&Opt.UseFieldDB, "use-field-db", true, "use template field DB from IBM official site (https://www.ibm.com/docs/en/zos/2.4.0?topic=definitions-group-template-racf-database)")

    flag.Parse()
}
