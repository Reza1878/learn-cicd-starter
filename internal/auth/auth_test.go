package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	type result struct {
		apiKey string
		err    error
	}

	tests := map[string]struct {
		input http.Header
		want  result
	}{
		"no token provided": {
			input: map[string][]string{"Authorization": {""}},
			want:  result{apiKey: "", err: errors.New("no authorization header included")},
		},
		"malformed authorization header": {
			input: map[string][]string{"Authorization": {"Bearer invalidapikey"}},
			want:  result{apiKey: "", err: errors.New("malformed authorization header")},
		},
		"valid authorization header": {
			input: map[string][]string{"Authorization": {"ApiKey FakeApiKey"}},
			want:  result{apiKey: "ApiKey", err: nil},
		},
	}

	for name, tc := range tests {
		res, err := GetAPIKey(tc.input)
		if res != tc.want.apiKey || !errors.Is(err, tc.want.err) {
			t.Fatalf("%s: expected %#v, got %#v", name, tc.want, result{apiKey: res, err: err})
		}
	}
}
