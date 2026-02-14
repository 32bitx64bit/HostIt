module hostit/client

go 1.24.0

require (
	golang.org/x/sys v0.39.0
	hostit/shared v0.0.0
)

require (
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.2 // indirect
	golang.org/x/crypto v0.46.0 // indirect
)

replace hostit/shared => ../shared
