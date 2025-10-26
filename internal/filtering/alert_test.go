package filtering

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSFilter_IsAlertFilter(t *testing.T) {
	filtersDir := t.TempDir()

	testCases := []struct {
		name      string
		filterID  rules.ListID
		filters   []FilterYAML
		whitelist []FilterYAML
		want      bool
	}{{
		name:     "alert_blocklist",
		filterID: 1,
		filters: []FilterYAML{{
			Enabled: true,
			URL:     "https://example.com/filter1.txt",
			Name:    "alert_filter",
			White:   false,
			Alert:   true,
			Filter: Filter{
				ID: 1,
			},
		}},
		whitelist: nil,
		want:      true,
	}, {
		name:     "alert_allowlist",
		filterID: 2,
		filters:  nil,
		whitelist: []FilterYAML{{
			Enabled: true,
			URL:     "https://example.com/filter2.txt",
			Name:    "alert_allowlist",
			White:   true,
			Alert:   true,
			Filter: Filter{
				ID: 2,
			},
		}},
		want: true,
	}, {
		name:     "non_alert_filter",
		filterID: 3,
		filters: []FilterYAML{{
			Enabled: true,
			URL:     "https://example.com/filter3.txt",
			Name:    "regular_filter",
			White:   false,
			Alert:   false,
			Filter: Filter{
				ID: 3,
			},
		}},
		whitelist: nil,
		want:      false,
	}, {
		name:      "non_existent_filter",
		filterID:  999,
		filters:   nil,
		whitelist: nil,
		want:      false,
	}, {
		name:     "mixed_filters",
		filterID: 5,
		filters: []FilterYAML{{
			Enabled: true,
			URL:     "https://example.com/filter4.txt",
			Name:    "regular_filter",
			White:   false,
			Alert:   false,
			Filter: Filter{
				ID: 4,
			},
		}, {
			Enabled: true,
			URL:     "https://example.com/filter5.txt",
			Name:    "alert_filter",
			White:   false,
			Alert:   true,
			Filter: Filter{
				ID: 5,
			},
		}},
		whitelist: nil,
		want:      true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(&Config{
				Logger:           testLogger,
				FilteringEnabled: true,
				Filters:          tc.filters,
				WhitelistFilters: tc.whitelist,
				DataDir:          filtersDir,
			}, nil)
			require.NoError(t, err)
			t.Cleanup(d.Close)

			got := d.IsAlertFilter(tc.filterID)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFilterYAML_AlertFlag(t *testing.T) {
	testCases := []struct {
		name      string
		filter    FilterYAML
		wantAlert bool
	}{{
		name: "alert_enabled",
		filter: FilterYAML{
			Enabled: true,
			URL:     "https://example.com/filter.txt",
			Name:    "test_filter",
			White:   false,
			Alert:   true,
			Filter: Filter{
				ID: 1,
			},
		},
		wantAlert: true,
	}, {
		name: "alert_disabled",
		filter: FilterYAML{
			Enabled: true,
			URL:     "https://example.com/filter.txt",
			Name:    "test_filter",
			White:   false,
			Alert:   false,
			Filter: Filter{
				ID: 2,
			},
		},
		wantAlert: false,
	}, {
		name: "alert_with_allowlist",
		filter: FilterYAML{
			Enabled: true,
			URL:     "https://example.com/filter.txt",
			Name:    "test_filter",
			White:   true,
			Alert:   true,
			Filter: Filter{
				ID: 3,
			},
		},
		wantAlert: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantAlert, tc.filter.Alert)
		})
	}
}
