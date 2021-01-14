package util

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

type Sqlite3 struct {
	DbConn *sql.DB
}

func NewSqlite3Connection(DBFile string) (*Sqlite3, error) {
	sl := &Sqlite3{}
	db, err := sql.Open("sqlite3", DBFile)
	if err != nil {
		return nil, fmt.Errorf("Sqlite3 %s open error:%v ", DBFile, err)
	}
	sl.DbConn = db
	return sl, nil
}

func (s *Sqlite3) Close() {
	s.DbConn.Close()
}
