package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
)

var (
	showVersion = flag.Bool("version", false, "Print version information.")

	// Netflow
	receiveAddr = ":9995"
	count       = "Count$"
	exclude     = "Time"
	expiry      = 10 * time.Minute

	// Prometheus
	listenAddr  = ":9103"
	metricsPath = "/metrics"
)

func init() {
	flag.StringVar(&receiveAddr, "netflow.listen", receiveAddr, "Address to accept netflow binary network packets")
	flag.StringVar(&count, "netflow.count", count, "Regexp to count metrics")
	flag.StringVar(&exclude, "netflow.exclude", exclude, "Regexp to exclude metrics")
	flag.DurationVar(&expiry, "netflow.expiry", expiry, "Metric sample validity")
	flag.StringVar(&listenAddr, "web.listen", listenAddr, "Address to expose prometheus metrics")
	flag.StringVar(&metricsPath, "web.telemetry-path", metricsPath, "Path to expose Prometheus metrics")
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Print("netflow_exporter"))
		os.Exit(0)
	}

	udpAddress, err := net.ResolveUDPAddr("udp", receiveAddr)
	if err != nil {
		log.Fatalf("failed to resolve address: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		log.Fatalf("failed to listening at: %w", err)
	}

	c := &collector{
		conn:    conn,
		ch:      make(chan *netflowSample, 0),
		samples: map[string]*netflowSample{},
		mu:      &sync.Mutex{},
		expires: expiry,
		lastProcessed: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "netflow_last_processed_timestamp_seconds",
				Help: "Unix timestamp of the last processed netflow metric.",
			},
		),
	}

	if count != "" {
		c.count, err = regexp.Compile(count)
		if err != nil {
			log.Fatalf("invalid count regexp: %s", err)
		}
	}

	if exclude != "" {
		c.exclude, err = regexp.Compile(exclude)
		if err != nil {
			log.Fatalf("invalid exclude regexp: %s", err)
		}
	}

	prometheus.MustRegister(c)

	go c.processSamples()
	go c.processReader()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
<head><title>netflow metrics</title></head><body>
<h1>netflow metrics</h1>
<p><a href='` + metricsPath + `'>Metrics</a></p>
</body></html>`))
	})

	log.Printf("listening on %s", listenAddr)
	http.Handle(metricsPath, promhttp.Handler())

	log.Printf("receiving on %s", receiveAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
