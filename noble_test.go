package noble

import (
	"errors"
	"testing"
)

type TestRandomSourceReader struct{}

func (tr *TestRandomSourceReader) generateBytes(length int) ([]byte, error) {
	return nil, errors.New("some error")
}

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
		{
			name:     "invalid info part",
			password: "password",
			hash:     "$argon2id$v=19$m=61440 t=1 p=4$oW7b7qw+6jiZSeiuEuF9Aw$zXHSJUld/AN2xfWEedPJZU+MnGAUzEX9QOK6cpPZzLU",
			wantErr:  true,
			wantGot:  false,
		},
		{
			name:     "bad encoding part four",
			password: "password",
			hash:     "$argon2id$v=19$m=61440,t=1,p=4$ oW7b7qw+6jiZSeiuEuF9Aw$zXHSJUld/AN2xfWEedPJZU+MnGAUzEX9QOK6cpPZzLU",
			wantErr:  true,
			wantGot:  false,
		},
		{
			name:     "bad encoding part five",
			password: "verysecret",
			hash:     "$argon2id$v=19$m=61440,t=1,p=4$oW7b7qw+6jiZSeiuEuF9Aw$ zXHSJUld/AN2xfWEedPJZU+MnGAUzEX9QOK6cpPZzLU",
			wantErr:  true,
			wantGot:  false,
		},
	}
	for _, e := range tests {
		t.Run(e.name, func(t *testing.T) {
			a := New()

			got, err := a.ComparePasswordAndKey(e.password, e.hash)
			if (err != nil) != e.wantErr {
				t.Errorf("%s, ComparePasswordAndKey() error = %v, wantErr %v", e.name, err, e.wantErr)
				return
			}

			if got != e.wantGot {
				t.Errorf("%s, ComparePasswordAndKey() got = %v, wantGot %v", e.name, got, e.wantGot)
				return
			}
		})
	}
}

func TestArgon_GeneratePasswordKey(t *testing.T) {

	tests := []struct {
		name          string
		password      string
		wantErr       bool
		useTestReader bool
	}{
		{
			name:          "valid",
			password:      "verysecret",
			wantErr:       false,
			useTestReader: false,
		},
		{
			name:          "invalid reader",
			password:      "verysecret",
			wantErr:       true,
			useTestReader: true,
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
			var a Argon

			if e.useTestReader {
				a = Argon{
					Time:              1,
					Memory:            60 * 1024,
					Threads:           4,
					KeyLen:            32,
					MinPasswordLength: 6,
					Reader:            &TestRandomSourceReader{},
				}
			} else {
				a = New()
			}

			_, err := a.GeneratePasswordKey(e.password)
			if (err != nil) != e.wantErr {
				t.Errorf("GeneratePasswordKey() error = %v, wantErr %v", err, e.wantErr)
				return
			}

		})
	}
}
