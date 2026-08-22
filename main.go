package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexcogojocaru/ja4"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	iface := flag.String("iface", "", "network interface to attach to (required)")
	flag.Parse()

	if *iface == "" {
		log.Fatal("missing -iface")
	}

	dev, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("interface %q: %v", *iface, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load ebpf objects: %v", err)
	}
	defer objs.Close()

	egress, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.CaptureEgressTls,
		Attach:    ebpf.AttachTCXEgress,
		Interface: dev.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach to %s egress: %v", *iface, err)
	}
	defer egress.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		rd.Close()
	}()

	log.Printf("attached to %s egress, waiting for handshakes (ctrl-c to exit)", *iface)

	var event ebpfTlsEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Print("detaching")
				return
			}

			log.Printf("read: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("decode: %v", err)
			continue
		}

		if event.Truncated != 0 {
			log.Printf("clienthello: %d bytes, truncated -- not fingerprinting", event.Len)
			continue
		}

		if event.Len > uint32(len(event.Data)) {
			log.Printf("bogus length %d, dropping", event.Len)
			continue
		}

		fingerprint, err := ja4.FingerprintBytes(event.Data[:event.Len])
		if err != nil {
			log.Fatal(err)
		}

		log.Println(fingerprint)
	}
}
