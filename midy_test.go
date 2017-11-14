package midy

import (
	"reflect"
	"testing"
)

func TestDetectHashType(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name  string
		args  args
		wantH HashType
	}{
		{
			name: "case1: valid md5 lower",
			args: args{
				s: "d41d8cd98f00b204e9800998ecf8427e",
			},
			wantH: Md5,
		},
		{
			name: "case2: valid sha1 lower",
			args: args{
				s: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			},
			wantH: Sha1,
		},
		{
			name: "case3: valid sha256 lower",
			args: args{
				s: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			wantH: Sha256,
		},
		{
			name: "case4: valid md5 upper",
			args: args{
				s: "D41D8CD98F00B204E9800998ECF8427E",
			},
			wantH: Md5,
		},
		{
			name: "case5: valid sha1 upper",
			args: args{
				s: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
			},
			wantH: Sha1,
		},
		{
			name: "case6: valid sha256 upper",
			args: args{
				s: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			},
			wantH: Sha256,
		},
		{
			name: "case7: valid sha256 mix",
			args: args{
				s: "e3b0c44298fc1c149afbf4c8996fb92427aE41E4649B934CA495991B7852B855",
			},
			wantH: Sha256,
		},
		{
			name: "case8: invalid sha256 (lack 1 letter)",
			args: args{
				s: "3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			wantH: Invalid,
		},
		{
			name: "case9: invalid character (replace 1 letter)",
			args: args{
				s: "<3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			wantH: Invalid,
		},
		{
			name: "case10: invalid character (replace 1 letter)",
			args: args{
				s: "z3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			wantH: Invalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotH := DetectHashType(tt.args.s); !reflect.DeepEqual(gotH, tt.wantH) {
				t.Errorf("DetectHashType() = %v, want %v", gotH, tt.wantH)
			}
		})
	}
}

func TestScrapeHashStrings(t *testing.T) {
	target:=`
	d41d8cd98f00b204e9800998ecf8427e
	z3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
	<sha256>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</sha256>
	`

	scraped := ScrapeHashStrings(target)

	if len(scraped) != 3 {
		t.Errorf("expected 3 items. but got %d", len(scraped))
	}

	for _, s := range scraped {

		if "d41d8cd98f00b204e9800998ecf8427e" == s {
			continue
		}

		if "da39a3ee5e6b4b0d3255bfef95601890afd80709" == s {
			continue
		}

		if "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" == s {
			continue
		}

		t.Errorf("not expected %s", s)
	}
}
