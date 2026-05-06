package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name:          "Hiányzó Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name:          "Helyes ApiKey header",
			headers:       http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey:   "my-secret-key",
			expectedError: "",
		},
		{
			name:          "Rossz prefix (Bearer helyett ApiKey)",
			headers:       http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "Csak prefix, kulcs nélkül",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "Üres Authorization header érték",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("várt kulcs: %q, kapott: %q", tt.expectedKey, key)
			}

			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("nem várt hiba: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("várt hiba %q, de nem jött hiba", tt.expectedError)
				} else if err.Error() != tt.expectedError {
					t.Errorf("várt hibaüzenet: %q, kapott: %q", tt.expectedError, err.Error())
				}
			}
		})
	}
}
