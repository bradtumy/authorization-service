package oauth

import "os"

// EnvClientStore validates a single client from environment variables.
type EnvClientStore struct{}

func (EnvClientStore) Validate(clientID, clientSecret string) bool {
	expectedID := os.Getenv("CLIENT_ID")
	expectedSecret := os.Getenv("CLIENT_SECRET")
	return expectedID != "" && expectedSecret != "" && clientID == expectedID && clientSecret == expectedSecret
}
