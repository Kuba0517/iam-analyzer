package graph

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"s3:GetObject", "s3:GetObject", true},
		{"s3:GetObject", "s3:PutObject", false},

		{"s3:*", "s3:GetObject", true},
		{"s3:*", "s3:PutObject", true},
		{"s3:*", "ec2:DescribeInstances", false},
		{"*", "s3:GetObject", true},
		{"*", "", true},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:GetBucketPolicy", true},
		{"s3:Get*", "s3:PutObject", false},

		{"s3:Get?bject", "s3:GetObject", true},
		{"s3:Get?bject", "s3:Getobject", true},
		{"s3:Get?bject", "s3:GetXbject", true},
		{"s3:Get?bject", "s3:GetOOject", false},

		// Combined wildcards.
		{"s3:*Object", "s3:GetObject", true},
		{"s3:*Object", "s3:PutObject", true},
		{"s3:*Object", "s3:GetBucket", false},

		// Case insensitive.
		{"S3:GetObject", "s3:getobject", true},

		{"arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/key.txt", true},
		{"arn:aws:s3:::my-bucket/*", "arn:aws:s3:::other-bucket/key.txt", false},
		{"arn:aws:s3:::*", "arn:aws:s3:::any-bucket", true},

		{"", "", true},
		{"", "something", false},
		{"*", "", true},
	}

	for _, tt := range tests {
		got := Match(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestOverlaps(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"*", "s3:GetObject", true},
		{"s3:GetObject", "*", true},
		{"*", "*", true},

		{"s3:GetObject", "s3:GetObject", true},

		{"s3:GetObject", "s3:PutObject", false},
		{"s3:Get*", "ec2:*", false},

		{"s3:*", "s3:GetObject", true},
		{"s3:GetObject", "s3:*", true},

		{"s3:Get*", "s3:*Object", true},
	}

	for _, tt := range tests {
		got := Overlaps(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("Overlaps(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
