package constants

// Version is the current version of git-crypt
const Version = "v0.0.1"

// FileHeader is a predefined marker to identify encrypted files
var FileHeader = []byte("GITCRYPT")

// KeyFileName is the name of the key file
const KeyFileName = ".git-crypt.key"
