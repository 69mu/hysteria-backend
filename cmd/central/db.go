package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
)

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE IF NOT EXISTS server_users (
			server_id TEXT NOT NULL,
			user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			PRIMARY KEY (server_id, user_id)
		);
		CREATE TABLE IF NOT EXISTS traffic (
			user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			tx      INTEGER NOT NULL DEFAULT 0,
			rx      INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS servers (
			id TEXT PRIMARY KEY,
			acme_domain TEXT NOT NULL DEFAULT '',
			acme_email TEXT NOT NULL DEFAULT '',
			auth_url TEXT NOT NULL DEFAULT '',
			traffic_url TEXT NOT NULL DEFAULT '',
			interval_auth TEXT NOT NULL DEFAULT '10s',
			interval_kick TEXT NOT NULL DEFAULT '10s',
			interval_traffic_from_proxy TEXT NOT NULL DEFAULT '10s',
			interval_traffic_to_central TEXT NOT NULL DEFAULT '10s'
		);
		CREATE TABLE IF NOT EXISTS server_status (
			server_id TEXT PRIMARY KEY,
			status TEXT NOT NULL DEFAULT '',
			hysteria_version TEXT NOT NULL DEFAULT '',
			backend_version TEXT NOT NULL DEFAULT '',
			last_config_update TEXT NOT NULL DEFAULT '',
			uptime_seconds INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS server_groups (
			server_id TEXT NOT NULL,
			group_name TEXT NOT NULL,
			PRIMARY KEY (server_id, group_name)
		);
		CREATE TABLE IF NOT EXISTS group_users (
			group_name TEXT NOT NULL,
			user_id TEXT NOT NULL,
			PRIMARY KEY (group_name, user_id)
		);
	`)
	if err != nil {
		return err
	}

	// Migrate: add quota column if it doesn't exist.
	// Default 0 = no access; admin must set a positive quota for each user.
	_, err = db.Exec(`ALTER TABLE users ADD COLUMN quota INTEGER NOT NULL DEFAULT 0`)
	if err != nil {
		// "duplicate column name" means migration already applied; ignore it.
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate quota column: %w", err)
		}
	}

	// Migrate: add last_seen column for user auth tracking.
	_, err = db.Exec(`ALTER TABLE users ADD COLUMN last_seen TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate last_seen column: %w", err)
		}
	}

	// Migrate: add ip column to server_status.
	_, err = db.Exec(`ALTER TABLE server_status ADD COLUMN ip TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate ip column: %w", err)
		}
	}

	// Migrate: add region and size columns to servers.
	for _, col := range []string{
		"ALTER TABLE servers ADD COLUMN region TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE servers ADD COLUMN size TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE server_status ADD COLUMN droplet_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE server_status ADD COLUMN provision_status TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE users ADD COLUMN token TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE servers ADD COLUMN token TEXT NOT NULL DEFAULT ''",
	} {
		_, err = db.Exec(col)
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	// Backfill empty tokens.
	backfillToken := func(table string) error {
		rows, err := db.Query(fmt.Sprintf("SELECT id FROM %s WHERE token = ''", table))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			rows.Scan(&id)
			db.Exec(fmt.Sprintf("UPDATE %s SET token = ? WHERE id = ?", table), generateToken(db), id)
		}
		return nil
	}
	if err := backfillToken("users"); err != nil {
		return fmt.Errorf("backfill user tokens: %w", err)
	}
	if err := backfillToken("servers"); err != nil {
		return fmt.Errorf("backfill server tokens: %w", err)
	}

	// Migrate: create server_traffic table for per-server traffic tracking.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS server_traffic (
			server_id TEXT NOT NULL,
			user_id   TEXT NOT NULL,
			tx        INTEGER NOT NULL DEFAULT 0,
			rx        INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (server_id, user_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("create server_traffic: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Random server ID generation (adjective-noun style)
// ---------------------------------------------------------------------------

var idAdjectives = []string{
	"alpine", "amber", "ancient", "arctic", "autumn", "blazing", "bold", "brave", "bright", "calm",
	"cedar", "clever", "cobalt", "coral", "cosmic", "crimson", "crystal", "dancing", "dark", "dawn",
	"deep", "dusty", "eager", "echo", "electric", "emerald", "fading", "fern", "fierce", "floral",
	"foggy", "frozen", "gentle", "gilded", "glacial", "golden", "granite", "hollow", "humble", "icy",
	"iron", "ivory", "jade", "jasper", "keen", "lemon", "light", "lime", "lofty", "lunar",
	"marble", "meadow", "misty", "mossy", "noble", "oak", "obsidian", "olive", "opal", "pale",
	"pearl", "pine", "polar", "proud", "quiet", "rapid", "raven", "rocky", "rosy", "royal",
	"ruby", "rustic", "sage", "sandy", "scarlet", "shadow", "sharp", "silent", "silver", "slate",
	"snowy", "solar", "spicy", "steady", "stone", "stormy", "sunny", "swift", "teal", "thorn",
	"timber", "topaz", "twin", "velvet", "violet", "vivid", "warm", "wild", "windy", "winter",
}

var idNouns = []string{
	"badger", "bear", "bison", "brook", "canyon", "cedar", "cliff", "cloud", "condor", "coral",
	"crane", "creek", "crow", "dawn", "deer", "delta", "dove", "dusk", "eagle", "elk",
	"falcon", "fern", "finch", "flame", "flora", "forge", "fox", "frost", "grove", "hawk",
	"haze", "heron", "hill", "horse", "island", "jade", "jay", "lake", "lark", "leaf",
	"lion", "lotus", "lynx", "maple", "marsh", "mesa", "mist", "moon", "moose", "nest",
	"oak", "ocean", "orchid", "osprey", "otter", "owl", "palm", "panther", "peak", "pebble",
	"pine", "pond", "quail", "rain", "raven", "reef", "ridge", "river", "robin", "sage",
	"seal", "shore", "sky", "snow", "sparrow", "spring", "spruce", "star", "stone", "storm",
	"stream", "summit", "swan", "thorn", "tide", "trail", "trout", "tulip", "vale", "wave",
	"whale", "willow", "wolf", "wren",
}

func generateServerID(db *sql.DB) string {
	for {
		ai, err := rand.Int(rand.Reader, big.NewInt(int64(len(idAdjectives))))
		if err != nil {
			continue
		}
		ni, err := rand.Int(rand.Reader, big.NewInt(int64(len(idNouns))))
		if err != nil {
			continue
		}
		id := idAdjectives[ai.Int64()] + "-" + idNouns[ni.Int64()]
		var exists int
		db.QueryRow("SELECT COUNT(*) FROM servers WHERE id = ?", id).Scan(&exists)
		if exists == 0 {
			return id
		}
	}
}

func generateToken(db *sql.DB) string {
	for {
		tok, err := randomHex(16)
		if err != nil {
			continue
		}
		var exists int
		db.QueryRow("SELECT COUNT(*) FROM users WHERE token = ?", tok).Scan(&exists)
		if exists > 0 {
			continue
		}
		db.QueryRow("SELECT COUNT(*) FROM servers WHERE token = ?", tok).Scan(&exists)
		if exists == 0 {
			return tok
		}
	}
}
