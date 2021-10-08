package oidc

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNumericDate_MarshalJSON(t *testing.T) {
	testCases := []struct {
		output string
		date   time.Time
	}{
		{
			output: "1234567890",
			date:   time.Unix(1234567890, 0),
		},
		{
			output: "1234567890.123456789",
			date:   time.Unix(1234567890, 123_456_789),
		},
		{
			output: "1234567890.123456",
			date:   time.Unix(1234567890, 123_456_000),
		},
		{
			output: "1234567890.1",
			date:   time.Unix(1234567890, 100_000_000),
		},
		{
			// the maximum time.Time that Go can marshal to JSON.
			output: "253402300799.999999999",
			date:   time.Date(9999, time.December, 31, 23, 59, 59, 999_999_999, time.UTC),
		},
		{
			// the maximum time.Time that in Go
			// https://stackoverflow.com/questions/25065055/what-is-the-maximum-time-time-in-go
			output: "9223371974719179007.999999999",
			date:   time.Unix(1<<63-62135596801, 999999999),
		},
	}

	for _, tc := range testCases {
		got, err := json.Marshal(NumericDate{tc.date})
		if err != nil {
			t.Errorf("failed to marshal %s", tc.date)
			continue
		}
		if string(got) != tc.output {
			t.Errorf("mashal %s not match: want %s, got %s", tc.date, tc.output, string(got))
		}
	}
}

func BenchmarkNumericDate_MarshalJSON(b *testing.B) {
	date := NumericDate{
		time.Date(9999, time.December, 31, 23, 59, 59, 999_999_999, time.UTC),
	}
	for i := 0; i < b.N; i++ {
		date.MarshalJSON()
	}
}

func TestNumericDate_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		input string
		date  time.Time
	}{
		{
			input: "1234567890",
			date:  time.Unix(1234567890, 0),
		},
		{
			input: "1234567890.123456789",
			date:  time.Unix(1234567890, 123456789),
		},
		{
			// the maximum time.Time that Go can marshal to JSON.
			input: "253402300799.999999999",
			date:  time.Date(9999, time.December, 31, 23, 59, 59, 999_999_999, time.UTC),
		},
		{
			// the maximum time.Time that in Go
			// https://stackoverflow.com/questions/25065055/what-is-the-maximum-time-time-in-go
			input: "9223371974719179007.999999999",
			date:  time.Unix(1<<63-62135596801, 999999999),
		},
	}

	for _, tc := range testCases {
		var got NumericDate
		if err := json.Unmarshal([]byte(tc.input), &got); err != nil {
			t.Errorf("failed parse %q: %v", tc.input, err)
		}
		if !got.Equal(tc.date) {
			t.Errorf("the result of %q is unexpected: want %s, got %s", tc.input, tc.date, got)
		}
	}
}

func BenchmarkNumericDate_UnmarshalJSON(b *testing.B) {
	input := []byte("253402300799.999999999")
	for i := 0; i < b.N; i++ {
		var date NumericDate
		date.UnmarshalJSON(input)
	}
}
