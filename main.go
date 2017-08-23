package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")

var filter = flag.String("f", "tcp and (dst port 80 or dst port 8080 or dst port 443 or dst port 10029)", "BPF filter for pcap")

//继承 tcpassembly.StreamFactory
type httpStreamFactory struct {
}

// httpStream 负责处理 http 请求.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run()

	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// EOF 返回
			return
		} else if err != nil {
			//log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			println("")
			println("SrcIP:", h.net.Src().String())
			println("SrcPort:", h.transport.Src().String())
			println("DstIP:", h.net.Dst().String())
			println("DstPort:", h.transport.Dst().String())
			println("ReqSize:", bodyBytes)
			println("Method:", req.Method)
			println("Url:", req.URL.String())
			println("")
		}
	}
}

func getNetDevices() []string {
	devices, _ := pcap.FindAllDevs()
	interfaces := []string{}
	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}

		if strings.HasPrefix(device.Name, "lo") {
			continue
		}

		if strings.HasPrefix(device.Name, "bond") {
			return []string{device.Name}
		}
		interfaces = append(interfaces, device.Name)
	}
	return interfaces

}

func GetAssembler() *tcpassembly.Assembler {
	// 设置 assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	return assembler
}

func capturePackets(faceName string, assembler *tcpassembly.Assembler) {
	handle, err := pcap.OpenLive(faceName, int32(*snaplen), true, 500)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packets:
			//数据包为空, 代表 pcap文件到结尾了
			if packet == nil {
				return
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}

			if packet.TransportLayer() == nil {
				continue
			}

			tcp, ok := packet.TransportLayer().(*layers.TCP)

			if !ok {
				continue
			}

			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			//每一分钟,自动刷新之前2分钟都处于不活跃的连接信息
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

func main() {
	flag.Parse()
	deviceList := getNetDevices()
	assembler := GetAssembler()
	for _, device := range deviceList {
		println("device >>>>>", device)
		go capturePackets(device, assembler)
	}
	select {}
}
