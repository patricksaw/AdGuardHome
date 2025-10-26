package filtering

import (
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDNSFilter_checkSafeBrowsing_AlertMode tests the safe browsing alert-only
// mode functionality.
func TestDNSFilter_checkSafeBrowsing_AlertMode(t *testing.T) {
	sbChecker := newChecker(sbBlocked)

	testCases := []struct {
		name           string
		host           string
		enabled        bool
		alertOnly      bool
		wantReason     Reason
		wantIsFiltered bool
		wantMatch      bool
	}{{
		name:           "blocking_mode",
		host:           sbBlocked,
		enabled:        true,
		alertOnly:      false,
		wantReason:     FilteredSafeBrowsing,
		wantIsFiltered: true,
		wantMatch:      true,
	}, {
		name:           "alert_only_mode",
		host:           sbBlocked,
		enabled:        false,
		alertOnly:      true,
		wantReason:     FilteredSafeBrowsingAlert,
		wantIsFiltered: false,
		wantMatch:      true,
	}, {
		name:           "both_disabled",
		host:           sbBlocked,
		enabled:        false,
		alertOnly:      false,
		wantReason:     NotFilteredNotFound,
		wantIsFiltered: false,
		wantMatch:      false,
	}, {
		name:           "clean_host_blocking_mode",
		host:           "example.com",
		enabled:        true,
		alertOnly:      false,
		wantReason:     NotFilteredNotFound,
		wantIsFiltered: false,
		wantMatch:      false,
	}, {
		name:           "clean_host_alert_mode",
		host:           "example.com",
		enabled:        false,
		alertOnly:      true,
		wantReason:     NotFilteredNotFound,
		wantIsFiltered: false,
		wantMatch:      false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(&Config{
				Logger:                testLogger,
				SafeBrowsingEnabled:   tc.enabled,
				SafeBrowsingAlertOnly: tc.alertOnly,
				SafeBrowsingChecker:   sbChecker,
			}, nil)
			require.NoError(t, err)
			t.Cleanup(d.Close)

			setts := &Settings{
				ProtectionEnabled:     true,
				SafeBrowsingEnabled:   tc.enabled,
				SafeBrowsingAlertOnly: tc.alertOnly,
			}

			res, err := d.CheckHost(tc.host, dns.TypeA, setts)
			require.NoError(t, err)

			assert.Equal(t, tc.wantReason, res.Reason, "reason mismatch")
			assert.Equal(t, tc.wantIsFiltered, res.IsFiltered, "isFiltered mismatch")

			if tc.wantMatch {
				require.NotEmpty(t, res.Rules, "expected rules to be present")
				assert.Equal(t, rulelist.APIIDSafeBrowsing, res.Rules[0].FilterListID)
				assert.Equal(t, "adguard-malware-shavar", res.Rules[0].Text)
			} else {
				assert.Empty(t, res.Rules, "expected no rules")
			}
		})
	}
}

// TestDNSFilter_checkParental_AlertMode tests the parental control alert-only
// mode functionality.
func TestDNSFilter_checkParental_AlertMode(t *testing.T) {
	pcChecker := newChecker(pcBlocked)

	testCases := []struct {
		name           string
		host           string
		enabled        bool
		alertOnly      bool
		wantReason     Reason
		wantIsFiltered bool
		wantMatch      bool
	}{{
		name:           "blocking_mode",
		host:           pcBlocked,
		enabled:        true,
		alertOnly:      false,
		wantReason:     FilteredParental,
		wantIsFiltered: true,
		wantMatch:      true,
	}, {
		name:           "alert_only_mode",
		host:           pcBlocked,
		enabled:        false,
		alertOnly:      true,
		wantReason:     FilteredParentalAlert,
		wantIsFiltered: false,
		wantMatch:      true,
	}, {
		name:           "both_disabled",
		host:           pcBlocked,
		enabled:        false,
		alertOnly:      false,
		wantReason:     NotFilteredNotFound,
		wantIsFiltered: false,
		wantMatch:      false,
	}, {
		name:           "clean_host_blocking_mode",
		host:           "example.com",
		enabled:        true,
		alertOnly:      false,
		wantReason:     NotFilteredNotFound,
		wantIsFiltered: false,
		wantMatch:      false,
	}, {
		name:           "clean_host_alert_mode",
		host:           "example.com",
		enabled:        false,
		alertOnly:      true,
		wantReason:     NotFilteredNotFound,
		wantIsFiltered: false,
		wantMatch:      false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(&Config{
				Logger:                 testLogger,
				ParentalEnabled:        tc.enabled,
				ParentalAlertOnly:      tc.alertOnly,
				ParentalControlChecker: pcChecker,
			}, nil)
			require.NoError(t, err)
			t.Cleanup(d.Close)

			setts := &Settings{
				ProtectionEnabled: true,
				ParentalEnabled:   tc.enabled,
				ParentalAlertOnly: tc.alertOnly,
			}

			res, err := d.CheckHost(tc.host, dns.TypeA, setts)
			require.NoError(t, err)

			assert.Equal(t, tc.wantReason, res.Reason, "reason mismatch")
			assert.Equal(t, tc.wantIsFiltered, res.IsFiltered, "isFiltered mismatch")

			if tc.wantMatch {
				require.NotEmpty(t, res.Rules, "expected rules to be present")
				assert.Equal(t, rulelist.APIIDParentalControl, res.Rules[0].FilterListID)
				assert.Equal(t, "parental CATEGORY_BLACKLISTED", res.Rules[0].Text)
			} else {
				assert.Empty(t, res.Rules, "expected no rules")
			}
		})
	}
}

// TestDNSFilter_MutualExclusivity_SafeBrowsing tests that safe browsing
// blocking and alert modes cannot be active simultaneously.
func TestDNSFilter_MutualExclusivity_SafeBrowsing(t *testing.T) {
	sbChecker := newChecker(sbBlocked)

	d, err := New(&Config{
		Logger:                testLogger,
		SafeBrowsingEnabled:   true,
		SafeBrowsingAlertOnly: true, // Both set to true
		SafeBrowsingChecker:   sbChecker,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(d.Close)

	// When both are true, enabled should take precedence (blocking mode).
	setts := &Settings{
		ProtectionEnabled:     true,
		SafeBrowsingEnabled:   true,
		SafeBrowsingAlertOnly: true,
	}

	res, err := d.CheckHost(sbBlocked, dns.TypeA, setts)
	require.NoError(t, err)

	// Should block, not alert, because enabled=true takes precedence.
	assert.Equal(t, FilteredSafeBrowsing, res.Reason)
	assert.True(t, res.IsFiltered)
}

// TestDNSFilter_MutualExclusivity_Parental tests that parental control
// blocking and alert modes cannot be active simultaneously.
func TestDNSFilter_MutualExclusivity_Parental(t *testing.T) {
	pcChecker := newChecker(pcBlocked)

	d, err := New(&Config{
		Logger:                 testLogger,
		ParentalEnabled:        true,
		ParentalAlertOnly:      true, // Both set to true
		ParentalControlChecker: pcChecker,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(d.Close)

	// When both are true, enabled should take precedence (blocking mode).
	setts := &Settings{
		ProtectionEnabled: true,
		ParentalEnabled:   true,
		ParentalAlertOnly: true,
	}

	res, err := d.CheckHost(pcBlocked, dns.TypeA, setts)
	require.NoError(t, err)

	// Should block, not alert, because enabled=true takes precedence.
	assert.Equal(t, FilteredParental, res.Reason)
	assert.True(t, res.IsFiltered)
}

// TestDNSFilter_ProtectionDisabled tests that alert mode respects the global
// protection enabled flag.
func TestDNSFilter_ProtectionDisabled(t *testing.T) {
	sbChecker := newChecker(sbBlocked)
	pcChecker := newChecker(pcBlocked)

	d, err := New(&Config{
		Logger:                 testLogger,
		SafeBrowsingEnabled:    false,
		SafeBrowsingAlertOnly:  true,
		ParentalEnabled:        false,
		ParentalAlertOnly:      true,
		SafeBrowsingChecker:    sbChecker,
		ParentalControlChecker: pcChecker,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(d.Close)

	// Protection is disabled globally.
	setts := &Settings{
		ProtectionEnabled:     false, // Disabled
		SafeBrowsingAlertOnly: true,
		ParentalAlertOnly:     true,
	}

	// Safe browsing should not match.
	res, err := d.CheckHost(sbBlocked, dns.TypeA, setts)
	require.NoError(t, err)
	assert.Equal(t, NotFilteredNotFound, res.Reason)
	assert.False(t, res.IsFiltered)

	// Parental should not match.
	res, err = d.CheckHost(pcBlocked, dns.TypeA, setts)
	require.NoError(t, err)
	assert.Equal(t, NotFilteredNotFound, res.Reason)
	assert.False(t, res.IsFiltered)
}

// TestDNSFilter_ReasonString tests that the new reason enum values have
// correct string representations.
func TestDNSFilter_ReasonString(t *testing.T) {
	testCases := []struct {
		reason Reason
		want   string
	}{{
		reason: FilteredSafeBrowsing,
		want:   "FilteredSafeBrowsing",
	}, {
		reason: FilteredSafeBrowsingAlert,
		want:   "FilteredSafeBrowsingAlert",
	}, {
		reason: FilteredParental,
		want:   "FilteredParental",
	}, {
		reason: FilteredParentalAlert,
		want:   "FilteredParentalAlert",
	}}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.reason.String())
		})
	}
}
