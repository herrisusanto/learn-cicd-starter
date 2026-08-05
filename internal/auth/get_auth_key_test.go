package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		header   http.Header
		want     string
		wantErr  bool
		wantKind error
	}{
		{
			name:     "no auth header",
			header:   http.Header{},
			want:     "",
			wantErr:  true,
			wantKind: ErrNoAuthHeaderIncluded,
		},
		{
			name:     "malformed - scheme only",
			header:   http.Header{"Authorization": []string{"ApiKey"}},
			want:     "",
			wantErr:  true,
			wantKind: nil,
		},
		{
			name:     "malformed - wrong scheme",
			header:   http.Header{"Authorization": []string{"Bearer abc123"}},
			want:     "",
			wantErr:  true,
			wantKind: nil,
		},
		{
			name:     "valid key",
			header:   http.Header{"Authorization": []string{"ApiKey abc123"}},
			want:     "abc123",
			wantErr:  false,
			wantKind: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.header)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.wantKind != nil && !errors.Is(err, tt.wantKind) {
					t.Fatalf("expected error kind %v, got %v", tt.wantKind, err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if got != tt.want {
				t.Fatalf("expected key %q, got %q", tt.want, got)
			}
		})
	}
}
