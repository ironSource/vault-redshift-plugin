package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
    "crypto/md5"
    "encoding/hex"

	"github.com/hashicorp/vault/builtin/logical/database/dbplugin"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/plugins/helper/database/connutil"
	"github.com/hashicorp/vault/plugins/helper/database/credsutil"
	"github.com/hashicorp/vault/plugins/helper/database/dbutil"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

const (
	redshiftTypeName      string = "redshift"
	defaultRedshiftRenewSQL        = `
ALTER USER {{name}} VALID UNTIL '{{expiration}}';
`
)

// New implements builtinplugins.BuiltinFactory
func New() (interface{}) {
	connProducer := &connutil.SQLConnectionProducer{}
	connProducer.Type = "postgres"

	credsProducer := &credsutil.SQLCredentialsProducer{
		DisplayNameLen: 8,
		RoleNameLen:    8,
		UsernameLen:    63,
		Separator:      "_",
	}

	dbType := &RedShift{
		ConnectionProducer:  connProducer,
		CredentialsProducer: credsProducer,
	}

	return dbType
}

type RedShift struct {
	connutil.ConnectionProducer
	credsutil.CredentialsProducer
}

func (p *RedShift) Type() (string, error) {
	return redshiftTypeName, nil
}

func (p *RedShift) getConnection() (*sql.DB, error) {
	db, err := p.Connection()
	if err != nil {
		return nil, err
	}

	return db.(*sql.DB), nil
}

func (p *RedShift) CreateUser(statements dbplugin.Statements, usernameConfig dbplugin.UsernameConfig, expiration time.Time) (username string, password string, err error) {
	if statements.CreationStatements == "" {
		return "", "", dbutil.ErrEmptyCreationStatement
	}

	// Grab the lock
	p.Lock()
	defer p.Unlock()

	username, err = p.GenerateUsername(usernameConfig)
	if err != nil {
		return "", "", err
	}
    
    username = strings.ToLower(username)
	username = strings.Replace(username, "-", "_", -1)

	password, err = p.GeneratePassword()
	if err != nil {
		return "", "", err
	}
    
    pwdMD5 := md5.New()
    pwdMD5.Write([]byte(password));
    pwdMD5.Write([]byte(username));
    passwordMD5  := "md5" + hex.EncodeToString(pwdMD5.Sum(nil))
	expirationStr, err := p.GenerateExpiration(expiration)
	if err != nil {
		return "", "", err
	}

	// Get the connection
	db, err := p.getConnection()
	if err != nil {
		return "", "", err

	}

	// Start a transaction
	tx, err := db.Begin()
	if err != nil {
		return "", "", err

	}
	defer func() {
		tx.Rollback()
	}()

	// Execute each query
	for _, query := range strutil.ParseArbitraryStringSlice(statements.CreationStatements, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		stmt, err := tx.Prepare(dbutil.QueryHelper(query, map[string]string{
			"name":       username,
			"password":   passwordMD5,
			"expiration": expirationStr,
		}))
		if err != nil {
			return "", "", err

		}
		defer stmt.Close()
		if _, err := stmt.Exec(); err != nil {
			return "", "", err

		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return "", "", err

	}
    
	return username, password, nil
}

func (p *RedShift) RenewUser(statements dbplugin.Statements, username string, expiration time.Time) error {
	p.Lock()
	defer p.Unlock()

	renewStmts := statements.RenewStatements
	if renewStmts == "" {
		renewStmts = defaultRedshiftRenewSQL
	}

	db, err := p.getConnection()
	if err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		tx.Rollback()
	}()

	expirationStr, err := p.GenerateExpiration(expiration)
	if err != nil {
		return err
	}

	for _, query := range strutil.ParseArbitraryStringSlice(renewStmts, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}
		stmt, err := tx.Prepare(dbutil.QueryHelper(query, map[string]string{
			"name":       username,
			"expiration": expirationStr,
		}))
		if err != nil {
			return err
		}

		defer stmt.Close()
		if _, err := stmt.Exec(); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (p *RedShift) RevokeUser(statements dbplugin.Statements, username string) error {
	// Grab the lock
	p.Lock()
	defer p.Unlock()

	if statements.RevocationStatements == "" {
		return p.defaultRevokeUser(username)
	}

	return p.customRevokeUser(username, statements.RevocationStatements)
}

func (p *RedShift) customRevokeUser(username, revocationStmts string) error {
	db, err := p.getConnection()
	if err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		tx.Rollback()
	}()

	for _, query := range strutil.ParseArbitraryStringSlice(revocationStmts, ";") {
		query = strings.TrimSpace(query)
		if len(query) == 0 {
			continue
		}

		stmt, err := tx.Prepare(dbutil.QueryHelper(query, map[string]string{
			"name": username,
		}))
		if err != nil {
			return err
		}
		defer stmt.Close()

		if _, err := stmt.Exec(); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

const (
    rs_revoke_sql string = `
select distinct schemaname from (
  select QUOTE_IDENT(schemaname) as schemaname FROM pg_tables WHERE schemaname not in ('pg_internal') 
  union 
  select QUOTE_IDENT(schemaname) as schemaname FROM pg_views WHERE schemaname not in ('pg_internal') 
)
`
)

func (p *RedShift) defaultRevokeUser(username string) error {
	db, err := p.getConnection()
	if err != nil {
		return err
	}

	// Check if the user exists
	var exists bool
	err = db.QueryRow("SELECT exists (SELECT usename FROM pg_user WHERE usename=$1);", username).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if exists == false {
		return nil
	}

	// Query for permissions; we need to revoke permissions before we can drop
	// the role
	// This isn't done in a transaction because even if we fail along the way,
	// we want to remove as much access as possible
	stmt, err := db.Prepare("select 'alter table '+schemaname+'.'+tablename+' owner to rdsdb;' as sql from pg_tables where tableowner like $1;")
	if err != nil {
		return err
	}
	defer stmt.Close()

	rows, err := stmt.Query(username)
	if err != nil {
		return err
	}
	defer rows.Close()

	const initialNumRevocations = 16
	revocationStmts := make([]string, 0, initialNumRevocations)
	for rows.Next() {
		var sql string
		err = rows.Scan(&sql)
		if err != nil {
			// keep going; remove as many permissions as possible right now
			continue
		}
		revocationStmts = append(revocationStmts, sql)
	}
	
	stmt, err = db.Prepare(fmt.Sprintf(`select 'revoke all on schema '+schemaname+' from %s;' as sql from (%s);`,
									   username,
									   rs_revoke_sql))
	if err != nil {
		return err
	}

	rows, err = stmt.Query()
	if err != nil {
		return err
	}

	for rows.Next() {
		var sql string
		err = rows.Scan(&sql)
		if err != nil {
			// keep going; remove as many permissions as possible right now
			continue
		}
		revocationStmts = append(revocationStmts, sql)
	}

	stmt, err = db.Prepare(fmt.Sprintf(`select 'revoke all on all tables in schema '+schemaname+' from %s;' as sql from (%s);`,
									   username,
									   rs_revoke_sql))
	if err != nil {
		return err
	}

	rows, err = stmt.Query()
	if err != nil {
		return err
	}

	for rows.Next() {
		var sql string
		err = rows.Scan(&sql)
		if err != nil {
			// keep going; remove as many permissions as possible right now
			continue
		}
		revocationStmts = append(revocationStmts, sql)
	}
	
	// again, here, we do not stop on error, as we want to remove as
	// many permissions as possible right now
	var lastStmtError error
	for _, query := range revocationStmts {
		stmt, err := db.Prepare(query)
		if err != nil {
			lastStmtError = err
			continue
		}
		defer stmt.Close()
		_, err = stmt.Exec()
		if err != nil {
			lastStmtError = err
		}
	}

	// can't drop if not all privileges are revoked
	if rows.Err() != nil {
		return fmt.Errorf("could not generate revocation statements for all rows: %s", rows.Err())
	}
	if lastStmtError != nil {
		return fmt.Errorf("could not perform all revocation statements: %s", lastStmtError)
	}

	// Drop this user
	stmt, err = db.Prepare(fmt.Sprintf(
		`DROP USER %s;`, pq.QuoteIdentifier(username)))
	if err != nil {
		return err
	}
	defer stmt.Close()
	if _, err := stmt.Exec(); err != nil {
		return err
	}

	return nil
}