package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Table-driven tests let us define multiple scenarios cleanly
	tests := map[string]struct {
		headers       http.Header
		wantAPIKey    string
		wantErrExpect error
	}{
		"Valid Authorization Header": {
			headers: http.Header{
				"Authorization": []string{"ApiKey secret_token_123"},
			},
			wantAPIKey:    "secret_token_123",
			wantErrExpect: nil,
		},
		"No Authorization Header": {
			headers:       http.Header{},
			wantAPIKey:    "",
			wantErrExpect: ErrNoAuthHeaderIncluded, // Matches the error defined in auth.go
		},
		"Malformed Authorization Header (Missing ApiKey prefix)": {
			headers: http.Header{
				"Authorization": []string{"Bearer secret_token_123"},
			},
			wantAPIKey:    "",
			wantErrExpect: errors.New("malformed authorization header"),
		},
		"Malformed Authorization Header (Too short)": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantAPIKey:    "",
			wantErrExpect: errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Construct a mock request with the test case headers
			req, _ := http.NewRequest("GET", "/", nil)
			req.Header = tc.headers

			gotAPIKey, err := GetAPIKey(req.Header)

			// Check if the returned error matches expected behavior
			if tc.wantErrExpect != nil {
				if err == nil || err.Error() != tc.wantErrExpect.Error() {
					t.Fatalf("expected error: %v, got: %v", tc.wantErrExpect, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error occurred: %v", err)
			}

			// Check if the returned API Key is correct
			if gotAPIKey != tc.wantAPIKey {
				t.Errorf("expected API Key: %q, got: %q", tc.wantAPIKey, gotAPIKey)
			}
		})
	}
}
