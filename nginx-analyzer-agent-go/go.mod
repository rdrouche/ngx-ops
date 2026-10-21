module nginx-analyzer-go

go 1.24.7

replace golang.org/x/sys => github.com/golang/sys v0.30.0

replace golang.org/x/text => github.com/golang/text v0.21.0

require (
	github.com/corazawaf/coraza/v3 v3.3.3
	github.com/ncruces/go-sqlite3 v0.23.0
)

require (
	github.com/corazawaf/libinjection-go v0.2.2 // indirect
	github.com/magefile/mage v1.15.1-0.20241126214340-bdc92f694516 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20240411101913-e07a1f0e8eb4 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	golang.org/x/net v0.37.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

require (
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.8.2
	golang.org/x/sys v0.31.0 // indirect
)

// Dependances de Coraza (binaire cmd/waf uniquement) : memes remplacements GitHub que ci-dessus
// pour les modules hors github.com, afin que le build ne depende que de github.com.
replace golang.org/x/net => github.com/golang/net v0.33.0

replace golang.org/x/sync => github.com/golang/sync v0.10.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20241217172543-b2144cdd0a67

replace google.golang.org/protobuf => github.com/protocolbuffers/protobuf-go v1.36.1

replace rsc.io/binaryregexp => github.com/rsc/binaryregexp v0.2.0
