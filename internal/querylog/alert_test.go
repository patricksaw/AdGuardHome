package querylog

import (
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryLog_IsAlert(t *testing.T) {
	l, err := newQueryLog(Config{
		Logger:      slogutil.NewDiscardLogger(),
		Enabled:     true,
		FileEnabled: true,
		RotationIvl: timeutil.Day,
		MemSize:     100,
		BaseDir:     t.TempDir(),
	})
	require.NoError(t, err)

	testCases := []struct {
		name      string
		isAlert   bool
		wantAlert bool
	}{{
		name:      "alert_entry",
		isAlert:   true,
		wantAlert: true,
	}, {
		name:      "non_alert_entry",
		isAlert:   false,
		wantAlert: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			q := dns.Msg{
				Question: []dns.Question{{
					Name:   "example.org.",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}},
			}

			a := dns.Msg{
				Question: q.Question,
				Answer: []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(1, 2, 3, 4),
				}},
			}

			res := filtering.Result{
				Rules: []*filtering.ResultRule{{
					FilterListID: 1,
					Text:         "||example.org^",
				}},
				Reason:     filtering.FilteredBlockList,
				IsFiltered: true,
			}

			params := &AddParams{
				Question:   &q,
				Answer:     &a,
				OrigAnswer: &a,
				Result:     &res,
				Upstream:   "upstream",
				ClientIP:   net.IPv4(192, 168, 1, 1),
				IsAlert:    tc.isAlert,
			}

			l.Add(params)

			entries := []*logEntry{}
			l.buffer.Range(func(entry *logEntry) (cont bool) {
				entries = append(entries, entry)
				return true
			})

			require.Len(t, entries, 1)
			assert.Equal(t, tc.wantAlert, entries[0].IsAlert)
		})

		l.buffer.Clear()
	}
}

func TestAddParams_IsAlert(t *testing.T) {
	testCases := []struct {
		name      string
		isAlert   bool
		wantAlert bool
	}{{
		name:      "alert_true",
		isAlert:   true,
		wantAlert: true,
	}, {
		name:      "alert_false",
		isAlert:   false,
		wantAlert: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := &AddParams{
				Question: &dns.Msg{
					Question: []dns.Question{{
						Name:   "example.org.",
						Qtype:  dns.TypeA,
						Qclass: dns.ClassINET,
					}},
				},
				ClientIP: net.IPv4(192, 168, 1, 1),
				Result: &filtering.Result{
					Reason: filtering.FilteredBlockList,
				},
				IsAlert: tc.isAlert,
			}

			assert.Equal(t, tc.wantAlert, params.IsAlert)
		})
	}
}
