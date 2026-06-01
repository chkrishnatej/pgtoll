package config

// Database connection configuration
const (
	PgAddr     = "127.0.0.1:5432"
	PgUser     = "postgres"
	PgDatabase = "postgres"
	PgPassword = "SecureP@ssw0rd123" // change this
	CaCertPath = "postgres-setup/certs/ca.crt"
)

// Protocol constants
const (
	SSLRequestCode    = 80877103 // magic: "version 1234.5679" signals SSL probe
	ProtocolVersion30 = 196608   // Postgres protocol 3.0
)
