package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	_device        string = "eth0"
	snapshot_len   int32  = 1024
	promiscuous    bool   = false
	err            error
	timeout        time.Duration = -1 * time.Second
	handle         *pcap.Handle
	buffer         gopacket.SerializeBuffer
	options        gopacket.SerializeOptions
	srcMac, dstMac net.HardwareAddr
	//srcIp, dstIp    net.IP
	srcPort, dstPort int
	count            int
	counter          int = 0
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(_device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "udp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	ipv4Layer := &layers.IPv4{
		Version:    4,   //uint8
		IHL:        5,   //uint8
		TOS:        0,   //uint8
		Id:         0,   //uint16
		Flags:      0,   //IPv4Flag
		FragOffset: 0,   //uint16
		TTL:        255, //uint8
		Protocol:   17,  //IPProtocol UDP(17)
		SrcIP:      net.ParseIP("0.0.0.0"),
		DstIP:      net.ParseIP("0.0.0.0"),
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	ethernetLayerR := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: 0x800,
	}

	f, _ := os.Create("test.txt")
	w := bufio.NewWriter(f)
	_dstMac, _ := net.ParseMAC("12:34:56:78:9a:bc")
	_srcMac, _ := net.ParseMAC("00:22:48:0c:87:29")
	_srcIp := net.ParseIP("10.0.0.4")
	_dstIp := net.ParseIP("77.238.197.202")

	_srcPort := layers.UDPPort(27439)
	_dstPort := layers.UDPPort(60559)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip, _ := ipLayer.(*layers.IPv4)
		udplayer := packet.Layer(layers.LayerTypeUDP)
		udp, _ := udplayer.(*layers.UDP)

		applicationLayer := packet.ApplicationLayer()
		//rawBytes := []byte{byte(counter), byte(counter)}
		applicationLayerR := applicationLayer.Payload()

		if len(applicationLayerR) == 3 {
			fmt.Print(packet)
			_srcMac = ethernetPacket.DstMAC
			_dstMac = ethernetPacket.SrcMAC
			_srcIp = ip.DstIP
			_dstIp = ip.SrcIP
			_srcPort = udp.DstPort
			_dstPort = udp.SrcPort

		} else if len(applicationLayerR) == 1 {
			ipv4Layer.SrcIP = _srcIp
			ipv4Layer.DstIP = _dstIp
			ethernetLayerR.SrcMAC = _srcMac
			ethernetLayerR.DstMAC = _dstMac
			udpLayer.SrcPort = layers.UDPPort(_srcPort)
			udpLayer.DstPort = layers.UDPPort(_dstPort)
			// fmt.Println(ipv4Layer.SrcIP)
			// fmt.Println(ipv4Layer.DstIP)
			// fmt.Println(udpLayer.SrcPort)
			// fmt.Println(udpLayer.DstPort)
			// fmt.Println(ethernetLayerR.SrcMAC)
			// fmt.Println(ethernetLayerR.DstMAC)
			options.FixLengths = true
			options.ComputeChecksums = true

			udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
			send_udp(applicationLayerR, udpLayer, ipv4Layer, ethernetLayerR)

			fmt.Print("Poslan" + " " + strconv.Itoa(counter) + " " + "paket.\n")
			w.WriteString(strconv.Itoa(counter) + " " + time.Now().UTC().String() + "\n")
			counter++
		}

	}

	// parse and set command-line options
	flag.Parse()

}

func send_udp(data []byte,
	udpLayer *layers.UDP,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		udpLayer,
		gopacket.Payload(data),
	)
	return send_ipv4(buffer.Bytes(), ipv4Layer, ethernetLayer)
}

func send_ipv4(data []byte,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer_ipv4 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ipv4, options,
		ipv4Layer,
		gopacket.Payload(data),
	)
	return send_ethernet(buffer_ipv4.Bytes(), ethernetLayer)
}

func send_ethernet(data []byte,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer_ethernet := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ethernet, options,
		ethernetLayer,
		gopacket.Payload(data),
	)
	err = handle.WritePacketData(buffer_ethernet.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	return err
}

func parse_port_range(port string) (portStart, portEnd int, err error) {
	var p0, p1 int

	if strings.Contains(port, "-") {
		fmt.Println("port:", port)
		ports := strings.Split(port, "-")
		if len(ports) != 2 {
			err = errors.New("port parse failed.")
			return
		}
		p0, err = strconv.Atoi(ports[0])
		if err != nil {
			return
		}
		p1, err = strconv.Atoi(ports[1])
		if err != nil {
			return
		}
		if p0 < p1 {
			portStart = p0
			portEnd = p1
		} else {
			portStart = p1
			portEnd = p0
		}
	} else {
		portStart, err = strconv.Atoi(port)
		if err != nil {
			return
		}
		portEnd = portStart
	}
	return
}

// ipstart, ipend, err := parse_ipv4_range(_srcIp)
func parse_ipv4_range(ipv4 string) (ipstart, ipend net.IP, err error) {
	var i0, i1 int
	ipstart = net.ParseIP("0.0.0.0")
	ipend = net.ParseIP("0.0.0.0")

	ip := strings.Split(ipv4, ".")
	if len(ip) != 4 {
		err = fmt.Errorf("Cannot parse IPv4 address range (.): %s", ipv4)
		return
	}
	for i := 0; i < 4; i++ {
		if strings.Contains(ip[i], "-") {
			s := strings.Split(ip[i], "-")
			if len(s) != 2 {
				err = fmt.Errorf("Cannot parse IPv4 address range (-): %s", ipv4)
			}
			i0, err = strconv.Atoi(s[0])
			if err != nil {
				return
			}
			a0 := byte(i0)
			i1, err = strconv.Atoi(s[1])
			if err != nil {
				return
			}
			a1 := byte(i1)
			if a0 < a1 {
				ipstart[12+i] = a0
				ipend[12+i] = a1
			} else {
				ipstart[12+i] = a1
				ipend[12+i] = a0
			}
		} else {
			i0, err = strconv.Atoi(ip[i])
			if err != nil {
				return
			}
			a0 := byte(i0)
			ipstart[12+i] = a0
			ipend[12+i] = a0
		}
	}
	return
}
