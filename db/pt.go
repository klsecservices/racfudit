package db

import (
    "fmt"
    "os"

    "racfudit/common"
)

// Save runtime DB as plaint text
func ToPlainText(profiles []*Profile, fileName string) {
    f, err := os.Create(fileName)
    if err != nil {
        common.Fatal("Can not create dump file: %v", err)
    }

    common.Log.Info("Saving RACF profiles as plain text file %s", fileName)
    for _, p := range profiles {
        common.Log.Debug("Saving profile: %q (%v)\n", p.Name, &p.Type)
        fmt.Fprintln(f, p)
    }
}
