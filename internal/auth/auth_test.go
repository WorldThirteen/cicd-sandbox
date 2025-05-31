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
			name: "valid API key",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey test-api-key-123")
				return h
			}(),
			expectedKey:   "test-api-key-123",
			expectedError: "",
		},
		{
			name: "valid API key with complex key value",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey super_test_51234567890abcdef")
				return h
			}(),
			expectedKey:   "super_test_51234567890abcdef",
			expectedError: "",
		},
		{
			name: "missing authorization header",
			headers: func() http.Header {
				return make(http.Header)
			}(),
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "empty authorization header",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "")
				return h
			}(),
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "malformed header - wrong prefix",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "Bearer test-api-key-123")
				return h
			}(),
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - case sensitive prefix",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "apikey test-api-key-123")
				return h
			}(),
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - missing API key value",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey")
				return h
			}(),
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - only spaces",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "   ")
				return h
			}(),
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "malformed header - ApiKey with empty value",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey ")
				return h
			}(),
			expectedKey:   "",
			expectedError: "",
		},
		{
			name: "valid API key with extra spaces",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey  test-api-key-with-spaces")
				return h
			}(),
			expectedKey:   "",
			expectedError: "",
		},
		{
			name: "API key with multiple parts (should take first part after ApiKey)",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey test-key extra-data")
				return h
			}(),
			expectedKey:   "test-key",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check the returned key
			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}

			// Check the error
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, want %v", tt.expectedError)
				} else if err.Error() != tt.expectedError {
					t.Errorf("GetAPIKey() error = %v, want %v", err.Error(), tt.expectedError)
				}
			}
		})
	}
}

func TestGetAPIKey_NoAuthHeaderIncludedError(t *testing.T) {
	headers := make(http.Header)
	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("GetAPIKey() should return ErrNoAuthHeaderIncluded for missing header, got %v", err)
	}
}

func TestGetAPIKey_EmptyHeaderReturnsNoAuthError(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "")
	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("GetAPIKey() should return ErrNoAuthHeaderIncluded for empty header, got %v", err)
	}
}

func TestGetAPIKey_ValidKeyExtractionFromComplexHeader(t *testing.T) {
	testCases := []struct {
		authHeader  string
		expectedKey string
	}{
		{"ApiKey simple-key", "simple-key"},
		{"ApiKey key-with-dashes", "key-with-dashes"},
		{"ApiKey key_with_underscores", "key_with_underscores"},
		{"ApiKey 1234567890", "1234567890"},
		{"ApiKey super_test_4eC39HqLyjWDarjtT1zdp7dc", "super_test_4eC39HqLyjWDarjtT1zdp7dc"},
	}

	for _, tc := range testCases {
		t.Run("key_"+tc.expectedKey, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Authorization", tc.authHeader)

			key, err := GetAPIKey(headers)

			if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
			}

			if key != tc.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tc.expectedKey)
			}
		})
	}
}
