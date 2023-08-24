package main

import (
    "racfudit/common"
    "racfudit/db"
)

func main() {

    // Parse options and configure log file
    common.ParseFlags()
    if err := common.Opt.Check(); err != nil {
        common.Fatal(err)
    }
    if err := common.Opt.Logger(); err != nil {
        common.Fatal(err)
    }
    defer common.Log.Close()

    // Parse RACF DB and extract profiles (init runtime DB)
    // profileStructs contains map of dinamic structure for RACF profiles
    profileStructs, profiles, err := db.ParseRACF(common.Opt.RACFFile)
    if err != nil {
        common.Fatal(err)
    }

    // Save runtime DB as plaint text
    if len(common.Opt.DumpFile) > 0 {
        db.ToPlainText(profiles, common.Opt.DumpFile)
    }

    // Save runtime DB as sqlite3 DB
    if len(common.Opt.SqlFile) > 0 {
        db.ToSQLite(profiles, common.Opt.SqlFile, profileStructs)
    }

    common.Log.Info("Done")

}
