package parsers

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// nmapArgsCIDR pulls the scanned range out of nmap's own argv, which nmap
// records in the document's `args` attribute: it is the only place an XML
// artifact says what was scanned.
var nmapArgsCIDR = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b`)

// nmapHost is one `<host>` element (§6, `nmap_parse`).
type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   int    `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name    string `xml:"name,attr"`
			Product string `xml:"product,attr"`
			Version string `xml:"version,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
	OS []struct {
		Name string `xml:"name,attr"`
	} `xml:"os>osmatch"`
}

// extractNmap reads nmap XML output (`nmap -oX`). It records the hosts nmap
// found up, their open ports as services, and — from the scan range in nmap's
// own argv — the segment those hosts belong to.
//
// Recognized: an `<nmaprun>` root; `<host>` with `<status state>` ,
// `<address addr addrtype>`, `<hostnames><hostname name>`, open `<port
// protocol portid>` with `<state state="open">` and `<service name product
// version>`, and `<os><osmatch name>`. Ports are facts, not vulnerabilities, so
// the parse writes no findings (§6).
//
// Two deliberate reductions, both warned about in the receipt: a host that nmap
// reports down is not an observation this store records (a host carries no
// state, so recording a down host would be indistinguishable from an up one),
// and no RESOLVES_TO edge is written — nmap gives a host its PTR name as an
// attribute of the same record, and the store treats a hostname as an alias of
// one host, so there is only one node to relate.
func extractNmap(in input) (Records, error) {
	dec := xml.NewDecoder(in.file)
	start, err := rootElement(dec)
	if err != nil {
		return Records{}, in.unrecognized("nmap XML output with an <nmaprun> root element", err.Error())
	}
	if start.Name.Local != "nmaprun" {
		return Records{}, in.unrecognized("nmap XML output with an <nmaprun> root element",
			"the root element is <"+start.Name.Local+">")
	}

	var (
		records   Records
		args      string
		hosts     []HostRecord
		services  []ServiceRecord
		parsed    []nmapHost
		down      int
		notOpen   int
		truncated bool
	)
	for _, attr := range start.Attr {
		if attr.Name.Local == "args" {
			args = attr.Value
		}
	}

	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A truncated document: what was read before the break is still an
			// observation (§7 — a partial parse commits and says so).
			truncated = true
			break
		}
		element, ok := token.(xml.StartElement)
		if !ok || element.Name.Local != "host" {
			continue
		}
		var host nmapHost
		if err := dec.DecodeElement(&host, &element); err != nil {
			truncated = true
			break
		}
		parsed = append(parsed, host)
	}

	for _, host := range parsed {
		if strings.ToLower(host.Status.State) != "up" {
			down++
			continue
		}
		addrs := make([]string, 0, len(host.Addresses))
		for _, a := range host.Addresses {
			switch strings.ToLower(a.AddrType) {
			case "ipv4", "ipv6":
				if strings.TrimSpace(a.Addr) != "" {
					addrs = append(addrs, strings.TrimSpace(a.Addr))
				}
			}
		}
		if len(addrs) == 0 {
			records.Skipped = append(records.Skipped, Skipped{
				Record: fmt.Sprintf("<host> with %d address(es)", len(host.Addresses)),
				Reason: "no IP address: a host is recorded under its address",
			})
			continue
		}
		record := HostRecord{Addresses: addrs}
		if len(host.Hostnames) > 0 {
			record.Hostname = strings.TrimSpace(host.Hostnames[0].Name)
		}
		if len(host.OS) > 0 {
			record.OS = strings.TrimSpace(host.OS[0].Name)
		}
		hosts = append(hosts, record)

		for _, port := range host.Ports {
			proto := strings.ToLower(strings.TrimSpace(port.Protocol))
			if proto != engagementstate.ProtoTCP && proto != engagementstate.ProtoUDP {
				records.Skipped = append(records.Skipped, Skipped{
					Record: fmt.Sprintf("%s/%d", port.Protocol, port.PortID),
					Reason: "protocol is neither tcp nor udp",
				})
				continue
			}
			if strings.ToLower(port.State.State) != engagementstate.StateOpen {
				notOpen++
				continue
			}
			product := strings.TrimSpace(port.Service.Product)
			if product == "" {
				product = strings.TrimSpace(port.Service.Name)
			}
			services = append(services, ServiceRecord{
				Host:    addrs[0],
				Port:    port.PortID,
				Proto:   proto,
				Product: product,
				Version: strings.TrimSpace(port.Service.Version),
			})
		}
	}

	if len(parsed) == 0 {
		return Records{}, in.unrecognized("nmap XML output with at least one <host> element",
			"the document has an <nmaprun> root but no host element was read")
	}

	records.Hosts = hosts
	records.Services = services
	for _, s := range services {
		records.Edges = append(records.Edges, EdgeRecord{
			Type:       engagementstate.EdgeRunsOn,
			From:       serviceRef(s.Host, s.Port, s.Proto),
			To:         hostRef(s.Host),
			Confidence: engagementstate.ConfidenceHigh,
		})
	}

	// The scanned range: nmap's argv is the artifact's own record of it.
	if match := nmapArgsCIDR.FindStringSubmatch(args); match != nil {
		prefix, err := netip.ParsePrefix(match[1])
		if err == nil {
			record := SegmentRecord{Label: prefix.String(), CIDRs: []string{prefix.String()}}
			records.Segments = append(records.Segments, record)
			for _, host := range records.Hosts {
				addr, err := netip.ParseAddr(host.Addresses[0])
				if err != nil || !prefix.Contains(addr.Unmap()) {
					continue
				}
				records.Edges = append(records.Edges, EdgeRecord{
					Type:       engagementstate.EdgeInSegment,
					From:       hostRef(host.Addresses[0]),
					To:         segmentRef(record.Label),
					Confidence: engagementstate.ConfidenceHigh,
				})
			}
		}
	} else {
		records.Warnings = append(records.Warnings,
			"no scanned range in the artifact's nmap args; no segment was recorded")
	}
	if truncated {
		records.Warnings = append(records.Warnings,
			"the XML document ends mid-document; what was read before the break was recorded")
	}
	if down > 0 {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("%d host(s) reported down were not recorded (a host record carries no state)", down))
	}
	if notOpen > 0 {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("%d closed or filtered port(s) were not recorded (services are recorded open)", notOpen))
	}
	return records, nil
}

// rootElement reads the document's first element, for a parser that must
// recognize a format before reading it.
func rootElement(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		token, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return xml.StartElement{}, errors.New("the file is empty")
			}
			return xml.StartElement{}, err
		}
		if start, ok := token.(xml.StartElement); ok {
			return start, nil
		}
	}
}
