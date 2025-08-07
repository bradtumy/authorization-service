package integration

import (
	"context"
	"os"
	"testing"

	"github.com/bradtumy/authorization-service/pkg/oidc"
)

func TestMain(m *testing.M) {
	oidc.LoadConfig(context.Background())
	os.Exit(m.Run())
}
