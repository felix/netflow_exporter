package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/client_model/go"
	"github.com/tehmaze/netflow"
	"github.com/tehmaze/netflow/ipfix"
	"github.com/tehmaze/netflow/netflow5"
	"github.com/tehmaze/netflow/netflow9"
	"github.com/tehmaze/netflow/session"
)

type collector struct {
	conn          *net.UDPConn
	ch            chan *netflowSample
	samples       map[string]*netflowSample
	expires       time.Duration
	mu            *sync.Mutex
	count         *regexp.Regexp
	exclude       *regexp.Regexp
	lastProcessed prometheus.Gauge
}

type netflowSample struct {
	Labels      map[string]string
	Counts      map[string]float64
	TimestampMs int64
}

type timeConstMetric struct {
	timestampMs int64
	metric      prometheus.Metric
}

func (m *timeConstMetric) Desc() *prometheus.Desc {
	return m.metric.Desc()
}
func (m *timeConstMetric) Write(out *model.Metric) error {
	return m.metric.Write(out)
}

func (c *collector) processReader() {
	defer c.conn.Close()
	decoders := make(map[string]*netflow.Decoder)

	for {
		buf := make([]byte, 65535)
		n, remoteAddr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading UDP packet from %s: %s", remoteAddr, err)
			continue
		}
		src := remoteAddr.String()
		srcIP := remoteAddr.IP.String()
		dec, found := decoders[src]
		if !found {
			s := session.New()
			dec = netflow.NewDecoder(s)
			decoders[src] = dec
		}
		m, err := dec.Read(bytes.NewBuffer(buf[:n]))
		if err != nil {
			log.Printf("Error decoding packet from %s: %s", src, err)
			continue
		}

		switch p := m.(type) {
		case *netflow5.Packet:
			timestampMs := int64(float64(p.Header.Unix.UnixNano()) / 1e6)
			for _, record := range p.Records {
				labels := prometheus.Labels{
					"sourceIPv4Address":           record.SrcAddr.String(),
					"destinationIPv4Address":      record.DstAddr.String(),
					"sourceTransportPort":         strconv.FormatUint(uint64(record.SrcPort), 10),
					"destinationTransportPort":    strconv.FormatUint(uint64(record.DstPort), 10),
					"protocolIdentifier":          strconv.FormatUint(uint64(record.Protocol), 10),
					"sourceIPv4PrefixLength":      strconv.FormatUint(uint64(record.SrcMask), 10),
					"destinationIPv4PrefixLength": strconv.FormatUint(uint64(record.DstMask), 10),
					"From":                        srcIP,
					"NetflowVersion":              "5",
				}
				counts := map[string]float64{
					"packetDeltaCount": float64(record.Packets),
					"octetDeltaCount":  float64(record.Bytes),
				}

				sample := &netflowSample{
					Labels:      labels,
					Counts:      counts,
					TimestampMs: timestampMs,
				}
				c.lastProcessed.Set(float64(time.Now().UnixNano()) / 1e9)
				c.ch <- sample
			}

		case *netflow9.Packet:
			timestampMs := int64(p.Header.UnixSecs) * 1000
			for _, set := range p.DataFlowSets {
				for _, record := range set.Records {
					labels := prometheus.Labels{}
					counts := make(map[string]float64)
					for _, field := range record.Fields {
						if len(field.Translated.Name) < 1 {
							continue
						}
						if c.exclude.MatchString(field.Translated.Name) {
							continue
						}
						if c.count.MatchString(field.Translated.Name) {
							counts[field.Translated.Name] = float64(field.Translated.Value.(uint64))
						} else {
							labels[field.Translated.Name] = fmt.Sprintf("%v", field.Translated.Value)
						}

					}
					if (len(counts) > 0) && (len(labels) > 0) {
						labels["From"] = srcIP
						labels["TemplateID"] = fmt.Sprintf("%d", record.TemplateID)
						labels["NetflowVersion"] = "9"

						sample := &netflowSample{
							Labels:      labels,
							Counts:      counts,
							TimestampMs: timestampMs,
						}
						c.lastProcessed.Set(float64(time.Now().UnixNano()) / 1e9)
						c.ch <- sample
					}
				}
			}

		case *ipfix.Message:
			timestampMs := int64(p.Header.ExportTime) * 1000
			for _, set := range p.DataSets {
				for _, record := range set.Records {
					labels := prometheus.Labels{}
					counts := make(map[string]float64)
					for _, field := range record.Fields {
						if len(field.Translated.Name) < 1 {
							continue
						}
						if c.exclude.MatchString(field.Translated.Name) {
							continue
						}
						if c.count.MatchString(field.Translated.Name) {
							counts[field.Translated.Name] = float64(field.Translated.Value.(uint64))
						} else {
							labels[field.Translated.Name] = fmt.Sprintf("%v", field.Translated.Value)
						}

					}
					if (len(counts) > 0) && (len(labels) > 0) {
						labels["From"] = srcIP
						labels["TemplateID"] = fmt.Sprintf("%d", record.TemplateID)
						labels["NetflowVersion"] = "10"

						sample := &netflowSample{
							Labels:      labels,
							Counts:      counts,
							TimestampMs: timestampMs,
						}
						c.lastProcessed.Set(float64(time.Now().UnixNano()) / 1e9)
						c.ch <- sample
					}
				}
			}
		default:
			log.Printf("unknown packet type: %s", p)
		}

	}
}

func (c *collector) processSamples() {
	ticker := time.NewTicker(time.Minute).C
	for {
		select {
		case sample := <-c.ch:
			c.mu.Lock()

			samplesKey := hashMap(sample.Labels)
			if _, exists := c.samples[samplesKey]; !exists {
				c.samples[samplesKey] = sample
			} else {
				// Make samples cumulative by incrementing the flow's counters
				c.samples[samplesKey].TimestampMs = int64(float64(time.Now().UnixNano()) / 1e6)
				for key, value := range sample.Counts {
					c.samples[samplesKey].Counts[key] += value
				}
			}
			c.mu.Unlock()

		case <-ticker:
			ageLimit := int64(float64(time.Now().Add(c.expires*-1).UnixNano()) / 1e6)
			c.mu.Lock()
			for k, sample := range c.samples {
				if ageLimit >= sample.TimestampMs {
					delete(c.samples, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.lastProcessed.Desc()
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ch <- c.lastProcessed
	c.mu.Lock()
	defer c.mu.Unlock()

	ageLimit := int64(float64(time.Now().Add(c.expires*-1).UnixNano()) / 1e6)
	for _, sample := range c.samples {
		if ageLimit >= sample.TimestampMs {
			continue
		}
		for key, value := range sample.Counts {
			desc := ""
			if sample.Labels["TemplateID"] != "" {
				desc = fmt.Sprintf("netflow_%s_TemplateID%s_%s", sample.Labels["From"], sample.Labels["TemplateID"], key)
			} else {
				desc = fmt.Sprintf("netflow_%s_%s", sample.Labels["From"], key)
			}
			desc = strings.Replace(desc, ".", "", -1)
			cMetric, err := prometheus.NewConstMetric(
				prometheus.NewDesc(desc, fmt.Sprintf("netflow metric %s", key), []string{}, sample.Labels),
				prometheus.GaugeValue,
				value,
				[]string{}...,
			)
			if err != nil {
				log.Printf("failed to create metric: %s", err)
			}

			metric := &timeConstMetric{
				timestampMs: sample.TimestampMs,
				metric:      cMetric,
			}
			ch <- metric
		}
	}
}

// Return a consistent string for a map for caching purposes.
func hashMap(m map[string]string) string {
	if m == nil {
		return ""
	}
	var buf strings.Builder
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(m[k])
	}
	return buf.String()
}
