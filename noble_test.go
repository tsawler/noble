package noble

import (
	"reflect"
	"testing"
)

func TestArgon_ComparePasswordAndHash(t *testing.T) {
	tests := []struct {
		name     string
		password string
		hash     string
		wantErr  bool
		wantGot  bool
	}{
		{
			name:     "valid",
			password: "verysecret",
			hash:     "$argon2id$v=19$m=61440,t=1,p=4$oW7b7qw+6jiZSeiuEuF9Aw$zXHSJUld/AN2xfWEedPJZU+MnGAUzEX9QOK6cpPZzLU",
			wantErr:  false,
			wantGot:  true,
		},
		{
			name:     "invalid",
			password: "password",
			hash:     "$argon2id$v=19$m=61440,t=1,p=4$oW7b7qw+6jiZSeiuEuF9Aw$zXHSJUld/AN2xfWEedPJZU+MnGAUzEX9QOK6cpPZzLU",
			wantErr:  false,
			wantGot:  false,
		},
		{
			name:     "only 5 parts",
			password: "password",
			hash:     "$argon2id$v=19$m=61440,t=1,p=4$oW7b7qw+6jiZSeiuEuF9Aw",
			wantErr:  true,
			wantGot:  false,
		},
	}
	for _, e := range tests {
		t.Run(e.name, func(t *testing.T) {
			a := New()

			got, err := a.ComparePasswordAndHash(e.password, e.hash)
			if (err != nil) != e.wantErr {
				t.Errorf("%s, ComparePasswordAndHash() error = %v, wantErr %v", e.name, err, e.wantErr)
				return
			}

			if got != e.wantGot {
				t.Errorf("%s, ComparePasswordAndHash() got = %v, wantGot %v", e.name, got, e.wantGot)
				return
			}
		})
	}
}

func TestArgon_GeneratePasswordKey(t *testing.T) {

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid",
			password: "verysecret",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
		},
		{
			name:     "short password",
			password: "a",
			wantErr:  false,
		},
	}
	for _, e := range tests {
		t.Run(e.name, func(t *testing.T) {
			a := New()

			_, err := a.GeneratePasswordKey(e.password)
			if (err != nil) != e.wantErr {
				t.Errorf("GeneratePasswordKey() error = %v, wantErr %v", err, e.wantErr)
				return
			}

		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		want Argon
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}
