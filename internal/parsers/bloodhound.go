package parsers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// A legacy BloodHound collector writes one JSON document per collected class —
// users.json, computers.json, groups.json, domains.json — each an object keyed
// by that class, holding an array of records:
//
//	{"computers": [{"Properties": {"name": "DC01.ACME.LOCAL", "operatingsystem": "Windows Server 2019"},
//	                "ObjectIdentifier": "S-1-5-21-…-1001",
//	                "Sessions": [{"UserName": "ACME\\jdoe", "UserSID": "S-1-5-21-…-1105"}],
//	                "LocalAdmins": [{"ObjectIdentifier": "S-1-5-21-…-500"}]}]}
//
// Later collectors wrap the same lists in an object carrying `Results`, so both
// shapes are read.
type bloodhoundRecord struct {
	Properties struct {
		Name            string `json:"name"`
		SAMAccountName  string `json:"samaccountname"`
		Domain          string `json:"domain"`
		OperatingSystem string `json:"operatingsystem"`
	} `json:"Properties"`
	// ObjectIdentifier is the record's SID; newer collectors spell it
	// `objectid`.
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectID         string `json:"objectid"`
	// Sessions and LocalAdmins hold the computer's footholds, in either the
	// direct array shape or one wrapped in `Results`.
	Sessions    json.RawMessage `json:"Sessions"`
	LocalAdmins json.RawMessage `json:"LocalAdmins"`
}

// bloodhoundPrincipal is one account a computer's record names.
type bloodhoundPrincipal struct {
	// Name is the account's name, when the collector recorded one.
	Name string
	// SID is the security identifier it recorded instead.
	SID string
}

// extractBloodHound reads legacy BloodHound collector JSON through the identity
// subset the store can express (docs/parser-tool-contracts.md §6): computers
// become hosts, a session becomes a user-level foothold on the computer it was
// seen on, and a local administrator becomes an admin-level one. Both carry
// ADMIN_OF and PIVOT_TO edges.
//
// Recognized: an object with one or more of the collector's class keys
// (`users`, `computers`, `groups`, `domains`, `ous`, `gpos`), whose records
// carry `Properties` and, for computers, `Sessions` and `LocalAdmins`.
//
// Deliberately not recorded, and said so in the receipt: AD user, group, and
// domain entities are deferred (docs/engagement-state.md §3), so a user with no
// captured secret and a group's memberships have nothing to name them by, and
// ACL (`Aces`) entries are not in v1's closed edge set. A collector carries no
// secrets, so this parse writes no credentials, no findings, and therefore no
// EXPLOITED_VIA edge, whose source is a finding.
func extractBloodHound(in input) (Records, error) {
	decoder := json.NewDecoder(in.file)
	token, err := decoder.Token()
	if err != nil {
		return Records{}, in.unrecognized("legacy BloodHound collector JSON", err.Error())
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return Records{}, in.unrecognized("legacy BloodHound collector JSON",
			"the document's first token is not a JSON object")
	}

	var (
		records  Records
		hosts    []bloodhoundRecord
		classes  int
		users    int
		groups   int
		domains  int
		otherKey int
	)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return Records{}, in.unrecognized("legacy BloodHound collector JSON", err.Error())
		}
		key, _ := keyToken.(string)
		switch strings.ToLower(key) {
		case "computers":
			classes++
			members, err := decodeBloodHoundArray(decoder)
			if err != nil {
				return Records{}, in.unrecognized("legacy BloodHound collector JSON",
					fmt.Sprintf("the computers array is malformed: %v", err))
			}
			hosts = append(hosts, members...)
		case "users":
			classes++
			count, err := skipJSONArray(decoder)
			if err != nil {
				return Records{}, in.unrecognized("legacy BloodHound collector JSON",
					fmt.Sprintf("the users array is malformed: %v", err))
			}
			users = count
		case "groups":
			classes++
			count, err := skipJSONArray(decoder)
			if err != nil {
				return Records{}, in.unrecognized("legacy BloodHound collector JSON",
					fmt.Sprintf("the groups array is malformed: %v", err))
			}
			groups = count
		case "domains":
			classes++
			count, err := skipJSONArray(decoder)
			if err != nil {
				return Records{}, in.unrecognized("legacy BloodHound collector JSON",
					fmt.Sprintf("the domains array is malformed: %v", err))
			}
			domains = count
		case "ous", "gpos":
			classes++
			if _, err := skipJSONArray(decoder); err != nil {
				return Records{}, in.unrecognized("legacy BloodHound collector JSON", err.Error())
			}
		case "meta":
			// The collector's own bookkeeping: a count, a type, a version.
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return Records{}, in.unrecognized("legacy BloodHound collector JSON", err.Error())
			}
		default:
			otherKey++
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				return Records{}, in.unrecognized("legacy BloodHound collector JSON", err.Error())
			}
		}
	}
	if classes == 0 {
		return Records{}, in.unrecognized("legacy BloodHound collector JSON",
			"the document carries none of the collector's classes (users, computers, groups, domains)")
	}

	for _, computer := range hosts {
		host := bloodhoundHostName(computer)
		if host == "" {
			records.Skipped = append(records.Skipped, Skipped{
				Record: fmt.Sprintf("computer %q", computer.Properties.SAMAccountName),
				Reason: "no name: a host is recorded under its address or name",
			})
			continue
		}
		records.Hosts = append(records.Hosts, HostRecord{
			Addresses: []string{host},
			Hostname:  host,
			OS:        strings.TrimSpace(computer.Properties.OperatingSystem),
		})
		for _, session := range bloodhoundPrincipals(computer.Sessions) {
			principal := bloodhoundPrincipalName(session)
			if principal == "" {
				continue
			}
			records.Accesses = append(records.Accesses, AccessRecord{
				Principal: accountRef(principal),
				Target:    hostRef(host),
				Level:     engagementstate.LevelUser,
			})
			records.Edges = append(records.Edges, EdgeRecord{
				Type:       engagementstate.EdgePivotTo,
				From:       accessRef(accountRef(principal), hostRef(host)),
				To:         hostRef(host),
				Confidence: engagementstate.ConfidenceMedium,
			})
		}
		for _, admin := range bloodhoundPrincipals(computer.LocalAdmins) {
			principal := bloodhoundPrincipalName(admin)
			if principal == "" {
				continue
			}
			records.Accesses = append(records.Accesses, AccessRecord{
				Principal: accountRef(principal),
				Target:    hostRef(host),
				Level:     engagementstate.LevelAdmin,
			})
			records.Edges = append(records.Edges,
				EdgeRecord{
					Type:       engagementstate.EdgeAdminOf,
					From:       accessRef(accountRef(principal), hostRef(host)),
					To:         hostRef(host),
					Confidence: engagementstate.ConfidenceMedium,
				},
				EdgeRecord{
					Type:       engagementstate.EdgePivotTo,
					From:       accessRef(accountRef(principal), hostRef(host)),
					To:         hostRef(host),
					Confidence: engagementstate.ConfidenceMedium,
				},
			)
		}
	}

	if users > 0 || groups > 0 || domains > 0 {
		records.Warnings = append(records.Warnings, fmt.Sprintf(
			"AD users (%d), groups (%d), and domains (%d) were not recorded: the store's AD entities are deferred, so only computers, sessions, and local administrators become records",
			users, groups, domains))
	}
	if otherKey > 0 {
		records.Warnings = append(records.Warnings, fmt.Sprintf(
			"%d unrecognized collector key(s) were skipped", otherKey))
	}
	if len(records.Accesses) == 0 {
		records.Warnings = append(records.Warnings,
			"no session or local administrator is listed: the computers were recorded without footholds")
	}
	return records, nil
}

// decodeBloodHoundArray streams one class's array, one record at a time, so a
// large collection does not have to fit in memory at once.
func decodeBloodHoundArray(decoder *json.Decoder) ([]bloodhoundRecord, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return nil, fmt.Errorf("want an array")
	}
	var out []bloodhoundRecord
	for decoder.More() {
		var record bloodhoundRecord
		if err := decoder.Decode(&record); err != nil {
			return out, err
		}
		out = append(out, record)
	}
	if _, err := decoder.Token(); err != nil {
		return out, err
	}
	return out, nil
}

// skipJSONArray consumes one class's array, counting its elements, for the
// classes this parse does not record.
func skipJSONArray(decoder *json.Decoder) (int, error) {
	token, err := decoder.Token()
	if err != nil {
		return 0, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return 0, fmt.Errorf("want an array")
	}
	count := 0
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return count, err
		}
		count++
	}
	if _, err := decoder.Token(); err != nil {
		return count, err
	}
	return count, nil
}

// bloodhoundPrincipals reads a computer's Sessions or LocalAdmins field: an
// array of entries, or a wrapper object carrying them under `Results`.
func bloodhoundPrincipals(raw json.RawMessage) []bloodhoundPrincipal {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	if trimmed[0] == '{' {
		var wrapper struct {
			Results json.RawMessage `json:"Results"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil
		}
		return bloodhoundPrincipals(wrapper.Results)
	}
	var entries []struct {
		UserName         string `json:"UserName"`
		UserSID          string `json:"UserSID"`
		Name             string `json:"Name"`
		ObjectIdentifier string `json:"ObjectIdentifier"`
		ObjectID         string `json:"objectid"`
	}
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		return nil
	}
	out := make([]bloodhoundPrincipal, 0, len(entries))
	for _, entry := range entries {
		out = append(out, bloodhoundPrincipal{
			Name: firstNonEmpty(entry.UserName, entry.Name),
			SID:  firstNonEmpty(entry.UserSID, entry.ObjectIdentifier, entry.ObjectID),
		})
	}
	return out
}

// bloodhoundHostName is the name a computer record is recorded under: its
// distinguished `name` ("DC01.ACME.LOCAL"), else its SAM account name.
func bloodhoundHostName(record bloodhoundRecord) string {
	name := strings.TrimSpace(record.Properties.Name)
	if name == "" {
		name = strings.TrimSpace(record.Properties.SAMAccountName)
	}
	return strings.TrimSpace(strings.TrimSuffix(name, "$"))
}

// bloodhoundPrincipalName names an account: its recorded name when the
// collector gives one, else the security identifier it recorded instead. A SID
// is an identity too, and naming it is better than dropping the foothold.
func bloodhoundPrincipalName(principal bloodhoundPrincipal) string {
	return firstNonEmpty(principal.Name, principal.SID)
}

// firstNonEmpty returns the first non-blank value.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
