package db

import (
    "fmt"
    "reflect"
    "strings"

    "racfudit/common"
    "racfudit/decode"

    "database/sql"

    _ "github.com/mattn/go-sqlite3"
)

type DBSQLite struct {
    db       *sql.DB
    fileName string
}

// Create new SQLite3 DB
func NewDBSQLite(dbname string) (*DBSQLite, error) {
    db, err := sql.Open("sqlite3", dbname)
    if err != nil {
        return nil, err
    }
    return &DBSQLite{db, dbname}, nil
}

// Create tables in SQLite3 DB according to runtime DB
func (d *DBSQLite) Init(profileStructs map[string]map[string]reflect.Type) error {
    for profileType, segments := range profileStructs {
        for segmentName, segmentStruct := range segments {
            fields := []string{`"ProfileName" TEXT`, `"Offset" TEXT`, `"RawData" TEXT`}
            tableName := fmt.Sprintf("%s_%s", profileType, segmentName)
            common.Log.Debug("Creating table %s", tableName)

            for i := 0; i < segmentStruct.NumField(); i++ {
                sField := segmentStruct.Field(i)

                if sField.Type.Kind() == reflect.Slice &&
                    sField.Type.Elem().Kind() == reflect.Struct &&
                    strings.HasSuffix(sField.Name, "_RG") {

                    // Expand and put RepeatGroup fields
                    rpStruct := sField.Type.Elem()
                    for i := 0; i < rpStruct.NumField(); i++ {
                        rgField := rpStruct.Field(i)
                        dbType := GetDBFieldType(&rgField.Type)
                        fields = append(fields, fmt.Sprintf("%q %s", rgField.Name, dbType))
                    }

                } else {
                    // put non-RepeatGroup fields
                    dbType := GetDBFieldType(&sField.Type)
                    fields = append(fields, fmt.Sprintf("%q %s", sField.Name, dbType))
                }
            }
            q := PrepareCreateQuery(tableName, fields)
            common.Log.Debug("Executing SQL query: %s", q)
            query, err := d.db.Prepare(q)
            if err != nil {
                return fmt.Errorf("Can not prepare SQL query %q: %v", q, err)
            }
            defer query.Close()
            _, err = query.Exec()
            if err != nil {
                return fmt.Errorf("Can not execute SQL query %q: %v", q, err)
            }
        }
    }
    return nil
}

// ToDO: Define SQLite field types or leave TEXT for everyone
func GetDBFieldType(t *reflect.Type) (s string) {
    switch *t {
    case reflect.TypeOf(uint8(0)), reflect.TypeOf(uint16(0)), reflect.TypeOf(uint32(0)), reflect.TypeOf(uint64(0)):
        //s = "INTEGER"
        s = "TEXT"
    case reflect.TypeOf(decode.HexStr{}), reflect.TypeOf(decode.Date{}), reflect.TypeOf(decode.EBCDICStr{}), reflect.TypeOf(decode.Time{}), reflect.TypeOf(decode.Flag{}):
        s = "TEXT"
    default:
        s = "TEXT"
    }
    return
}

// Fill tables in SQLite3 DB
func (d *DBSQLite) Fill(profiles []*Profile) (err error) {
    for _, profile := range profiles {
        if err = d.writeProfile(profile); err != nil {
            common.Log.Error("Error %v", err)
        }
    }
    return
}

func (d *DBSQLite) writeProfile(p *Profile) error {
    for _, s := range p.Segments {
        keys := []string{"ProfileName", "Offset", "RawData"}
        values := []string{
            fmt.Sprintf("'%s'", p.Name),
            fmt.Sprintf("'%s'", s.Address.String()),
            fmt.Sprintf("'%s'", s.Raw),
        }
        tableName := fmt.Sprintf("%s_%s", p.Type.Name, s.Name)
        common.Log.Debug("Inserting profile data %s in table %s", p.Name, tableName)

        sV := reflect.Indirect(s.Data)
        sT := reflect.TypeOf(sV.Interface())
        for i := 0; i < sV.NumField(); i++ {
            sFieldV := sV.Field(i)
            sField := sT.Field(i)

            // Check if field is a RepeatGroup field
            if sField.Type.Kind() == reflect.Slice &&
                sField.Type.Elem().Kind() == reflect.Struct &&
                strings.HasSuffix(sField.Name, "_RG") {

                // Expand and put RepeatGroup fields
                rpT := sField.Type.Elem()
                for i := 0; i < rpT.NumField(); i++ {
                    rgField := rpT.Field(i)
                    rgValues := make([]string, sFieldV.Len())
                    for j := 0; j < sFieldV.Len(); j++ {
                        rpV := sFieldV.Index(j)
                        rgValues[j] = DumpField(rpV.Field(i))
                    }
                    keys = append(keys, rgField.Name)
                    values = append(values, fmt.Sprintf("'%s'", strings.Join(rgValues, "; ")))
                }
            } else {
                keys = append(keys, sField.Name)
                values = append(values, fmt.Sprintf("'%s'", DumpField(sFieldV)))
            }
        }

        q := PrepareInsertQuery(tableName, keys, values)
        common.Log.Debug("Executing SQL query: %s", q)
        query, err := d.db.Prepare(q)
        if err != nil {
            return fmt.Errorf("Can not prepare SQL query %q: %v", q, err)
        }
        defer query.Close()
        _, err = query.Exec()
        if err != nil {
            return fmt.Errorf("Can not execute SQL query %q: %v", q, err)
        }
    }
    return nil
}

// Close SQLite3 DB handler
func (d *DBSQLite) Close() {
    d.db.Close()
}

// Create SQL query for creating a table
func PrepareCreateQuery(name string, fields []string) string {
    query := fmt.Sprintf("CREATE TABLE %s ", name)
    query += fmt.Sprintf("(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT")
    for _, v := range fields {
        query += fmt.Sprintf(", %s", v)
    }
    query += fmt.Sprintf(");")
    return query
}

// Create SQL query for inserting data into a table
func PrepareInsertQuery(name string, keys []string, values []string) string {
    query := fmt.Sprintf("INSERT INTO %s", name)
    query += fmt.Sprintf(`(%s) values(%s)`, strings.Join(keys, ", "), strings.Join(values, ", "))
    return query
}

// Save runtime DB as SQLite3 DB
func ToSQLite(profiles []*Profile, fileName string, profileStructs map[string]map[string]reflect.Type) {
    dbSQLite, err := NewDBSQLite(fileName)
    if err != nil {
        common.Fatal(fmt.Errorf("Can not create SQLite3 DB: %v", err))
    }
    defer dbSQLite.Close()

    common.Log.Info("Creating tables in SQLite3 DB %s for RACF profiles", fileName)
    err = dbSQLite.Init(profileStructs)
    if err != nil {
        common.Fatal(fmt.Errorf("Can not initialize SQLite3 DB: %v", err))
    }

    common.Log.Info("Saving RACF profiles in SQLite3 DB %s", fileName)
    err = dbSQLite.Fill(profiles)
    if err != nil {
        common.Fatal(fmt.Errorf("Can not fill SQLite3 DB completely: %v", err))
    }

}
