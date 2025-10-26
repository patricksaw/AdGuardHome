package querylog

import (
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/stretchr/testify/assert"
)

// TestSearchCriterion_matchFilteringStatus_Alerts tests the search criterion
// matching for all alert-only filtering statuses.
func TestSearchCriterion_matchFilteringStatus_Alerts(t *testing.T) {
	testCases := []struct {
		name          string
		criterionType criterionType
		value         string
		reason        filtering.Reason
		isFiltered    bool
		wantMatch     bool
	}{{
		name:          "blocklist_alert_matches",
		criterionType: ctFilteringStatus,
		value:         filteringStatusAlerts,
		reason:        filtering.FilteredAlert,
		isFiltered:    false,
		wantMatch:     true,
	}, {
		name:          "blocklist_alert_no_match_on_block",
		criterionType: ctFilteringStatus,
		value:         filteringStatusAlerts,
		reason:        filtering.FilteredBlockList,
		isFiltered:    true,
		wantMatch:     false,
	}, {
		name:          "safebrowsing_alert_matches",
		criterionType: ctFilteringStatus,
		value:         filteringStatusSafebrowsingAlerts,
		reason:        filtering.FilteredSafeBrowsingAlert,
		isFiltered:    false,
		wantMatch:     true,
	}, {
		name:          "safebrowsing_alert_no_match_on_block",
		criterionType: ctFilteringStatus,
		value:         filteringStatusSafebrowsingAlerts,
		reason:        filtering.FilteredSafeBrowsing,
		isFiltered:    true,
		wantMatch:     false,
	}, {
		name:          "parental_alert_matches",
		criterionType: ctFilteringStatus,
		value:         filteringStatusParentalAlerts,
		reason:        filtering.FilteredParentalAlert,
		isFiltered:    false,
		wantMatch:     true,
	}, {
		name:          "parental_alert_no_match_on_block",
		criterionType: ctFilteringStatus,
		value:         filteringStatusParentalAlerts,
		reason:        filtering.FilteredParental,
		isFiltered:    true,
		wantMatch:     false,
	}, {
		name:          "safebrowsing_alert_no_match_parental_alert",
		criterionType: ctFilteringStatus,
		value:         filteringStatusSafebrowsingAlerts,
		reason:        filtering.FilteredParentalAlert,
		isFiltered:    false,
		wantMatch:     false,
	}, {
		name:          "parental_alert_no_match_safebrowsing_alert",
		criterionType: ctFilteringStatus,
		value:         filteringStatusParentalAlerts,
		reason:        filtering.FilteredSafeBrowsingAlert,
		isFiltered:    false,
		wantMatch:     false,
	}, {
		name:          "blocklist_alert_no_match_safebrowsing_alert",
		criterionType: ctFilteringStatus,
		value:         filteringStatusAlerts,
		reason:        filtering.FilteredSafeBrowsingAlert,
		isFiltered:    false,
		wantMatch:     false,
	}, {
		name:          "blocklist_alert_no_match_parental_alert",
		criterionType: ctFilteringStatus,
		value:         filteringStatusAlerts,
		reason:        filtering.FilteredParentalAlert,
		isFiltered:    false,
		wantMatch:     false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &searchCriterion{
				criterionType: tc.criterionType,
				value:         tc.value,
			}

			entry := &logEntry{
				Result: filtering.Result{
					Reason:     tc.reason,
					IsFiltered: tc.isFiltered,
				},
			}

			matched := c.match(entry)
			assert.Equal(t, tc.wantMatch, matched,
				"criterion %s with reason %s should match=%v",
				tc.value, tc.reason, tc.wantMatch)
		})
	}
}

// TestSearchCriterion_AlertsExclusivity tests that alert filters are mutually
// exclusive with blocking filters.
func TestSearchCriterion_AlertsExclusivity(t *testing.T) {
	testCases := []struct {
		name       string
		value      string
		reason     filtering.Reason
		isFiltered bool
		wantMatch  bool
	}{{
		name:       "blocked_status_no_match_safebrowsing_alert",
		value:      filteringStatusBlocked,
		reason:     filtering.FilteredSafeBrowsingAlert,
		isFiltered: false,
		wantMatch:  false,
	}, {
		name:       "blocked_safebrowsing_no_match_alert",
		value:      filteringStatusBlockedSafebrowsing,
		reason:     filtering.FilteredSafeBrowsingAlert,
		isFiltered: false,
		wantMatch:  false,
	}, {
		name:       "blocked_parental_no_match_alert",
		value:      filteringStatusBlockedParental,
		reason:     filtering.FilteredParentalAlert,
		isFiltered: false,
		wantMatch:  false,
	}, {
		name:       "safebrowsing_alert_no_match_blocked",
		value:      filteringStatusSafebrowsingAlerts,
		reason:     filtering.FilteredSafeBrowsing,
		isFiltered: true,
		wantMatch:  false,
	}, {
		name:       "parental_alert_no_match_blocked",
		value:      filteringStatusParentalAlerts,
		reason:     filtering.FilteredParental,
		isFiltered: true,
		wantMatch:  false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &searchCriterion{
				criterionType: ctFilteringStatus,
				value:         tc.value,
			}

			entry := &logEntry{
				Result: filtering.Result{
					Reason:     tc.reason,
					IsFiltered: tc.isFiltered,
				},
			}

			matched := c.match(entry)
			assert.Equal(t, tc.wantMatch, matched,
				"alerts and blocking should be mutually exclusive")
		})
	}
}

// TestSearchCriterion_AllAlerts tests searching for all alert types combined.
func TestSearchCriterion_AllAlerts(t *testing.T) {
	testCases := []struct {
		name   string
		reason filtering.Reason
	}{{
		name:   "blocklist_alert",
		reason: filtering.FilteredAlert,
	}, {
		name:   "safebrowsing_alert",
		reason: filtering.FilteredSafeBrowsingAlert,
	}, {
		name:   "parental_alert",
		reason: filtering.FilteredParentalAlert,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &searchCriterion{
				criterionType: ctFilteringStatus,
				value:         filteringStatusAlerts,
			}

			entry := &logEntry{
				Result: filtering.Result{
					Reason:     tc.reason,
					IsFiltered: false,
				},
			}

			// FilteredAlert should match, but specific alert types should not
			// match the generic "alerts" filter (they have their own filters).
			if tc.reason == filtering.FilteredAlert {
				assert.True(t, c.match(entry))
			} else {
				assert.False(t, c.match(entry))
			}
		})
	}
}
