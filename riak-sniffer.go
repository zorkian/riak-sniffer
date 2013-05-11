/*
 * riak-sniffer.go
 *
 * A straightforward program for sniffing Riak proto-buffer streams and providing
 * diagnostic information on the realtime queries your database is handling.
 *
 * FIXME: this assumes IPv4.
 *
 * Taken from:
 *    https://github.com/xb95/riak-sniffer
 *
 * See the LICENSE file at the above link for licensing terms.
 *
 * Written by Mark Smith <mark@qq.is> for Bump Technologies (http://bu.mp/).
 *
 */

package main

import (
	riak "./proto"
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"flag"
	"fmt"
	"github.com/akrennmair/gopcap"
	"log"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// Format constants. This is a somewhat complicated system to prevent us from
// doing simple string substitution in the middle of the key/bucket if they
// happen to contain '#k' or something.
const (
	F_NONE = iota
	F_BUCKET
	F_KEY
	F_SOURCE
	F_SOURCEIP
	F_METHOD
)

type packet struct {
	request bool // request or response
	data    []byte
}

type riakSourceChannel chan *packet
type riakSource struct {
	src       string
	srcip     string
	synced    bool
	reqbuffer []byte
	resbuffer []byte
	reqSent   *time.Time
	reqTimes  [100]uint64
	qbytes    uint64
	qdata     *queryData
	qtext     string
	ch        riakSourceChannel
}

type riakMessage struct {
	method string
	bucket []byte
	key    []byte
}

type queryData struct {
	count uint64
	bytes uint64
	times [100]uint64
}

var start int64 = UnixNow()
var qbuf map[string]*queryData = make(map[string]*queryData)
var querycount int
var chmap map[string]*riakSource = make(map[string]*riakSource)
var verbose bool = false
var format []interface{}
var port uint16
var times [100]uint64

func UnixNow() int64 {
	return time.Now().Unix()
}

func main() {
	var lport *int = flag.Int("P", 8087, "Riak protocol buffer port")
	var eth *string = flag.String("i", "eth0", "Interface to sniff")
	var period *int = flag.Int("t", 10, "Seconds between outputting status")
	var displaycount *int = flag.Int("d", 25, "Display this many queries in status updates")
	var doverbose *bool = flag.Bool("v", false, "Print every query received (spammy)")
	var formatstr *string = flag.String("f", "#b:#k", "Format for output aggregation")
	flag.Parse()

	verbose = *doverbose
	port = uint16(*lport)
	parseFormat(*formatstr)
	rand.Seed(time.Now().UnixNano())

	log.SetPrefix("")
	log.SetFlags(0)

	log.Printf("Initializing Riak sniffing on %s:%d...", *eth, port)
	iface, err := pcap.Openlive(*eth, 65535, false, 0)
	if iface == nil || err != nil {
		if err == nil {
			err = errors.New("unknown error")
		}
		log.Fatalf("Failed to open device: %s", err)
	}

	if err = iface.Setfilter(fmt.Sprintf("tcp port %d", port)); err != nil {
		log.Fatalf("Failed to set port filter: %s", err)
	}

	last := UnixNow()
	var pkt *pcap.Packet = nil
	var rv int32 = 0

	for rv = 0; rv >= 0; {
		for pkt, rv = iface.NextEx(); pkt != nil; pkt, rv = iface.NextEx() {
			handlePacket(pkt)

			// simple output printer... this should be super fast since we expect that a
			// system like this will have relatively few unique queries once they're
			// canonicalized.
			if !verbose && last <= UnixNow()-int64(*period) {
				last = UnixNow()
				handleStatusUpdate(*displaycount)
			}
		}
	}
}

func calculateTimes(timings *[100]uint64) (fmin, favg, fmax float64) {
	var counts, total, min, max, avg uint64 = 0, 0, 0, 0, 0
	has_min := false
	for _, val := range *timings {
		if val == 0 {
			// Queries should never take 0 nanoseconds. We are using 0 as a
			// trigger to mean 'uninitialized reading'.
			continue
		}
		if val < min || !has_min {
			has_min = true
			min = val
		}
		if val > max {
			max = val
		}
		counts++
		total += val
	}
	if counts > 0 {
		avg = total / counts // integer division
	}
	return float64(min) / 1000000, float64(avg) / 1000000,
		float64(max) / 1000000
}

func handleStatusUpdate(displaycount int) {
	elapsed := float64(UnixNow() - start)

	// print status bar
	log.Printf("\n")
	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("%d total queries, %0.2f per second", querycount, float64(querycount)/elapsed)
	log.SetFlags(0)

	// global timing values
	gmin, gavg, gmax := calculateTimes(&times)
	log.Printf("    %0.2fms min / %0.2fms avg / %0.2fms max query time",
		gmin, gavg, gmax)

	// we cheat so badly here...
	var tmp sort.StringSlice = make([]string, 0, len(qbuf))
	for q, c := range qbuf {
		qmin, qavg, qmax := calculateTimes(&c.times)
		tmp = append(tmp, fmt.Sprintf("%6d  %6.2f/s  %6.2f %6.2f %6.2f %8db  %s",
			c.count, float64(c.count)/elapsed, qmin, qavg, qmax, c.bytes, q))
	}
	sort.Sort(tmp)

	// now print top to bottom, since our sorted list is sorted backwards
	// from what we want
	if len(tmp) < displaycount {
		displaycount = len(tmp)
	}
	for i := 1; i <= displaycount; i++ {
		log.Printf(tmp[len(tmp)-i])
	}
}

// given a string, return a string with safe-to-print bytes
func safe_output(inp []byte) string {
	out := ""
	for _, v := range inp {
		if v >= 32 && v <= 126 {
			out += string(v)
		} else {
			out += fmt.Sprintf("\\x%02x", v)
		}
	}
	return out
}

// Listens on a channel for bytes. This is how we get data in from the various
// clients that are talking to Riak.
func riakSourceListener(rs *riakSource) {
	for {
		pkt := <-rs.ch
		//		log.Printf("[%s] request=%t, got %d bytes", rs.src, pkt.request,
		//			len(pkt.data))

		var ptype int = -1
		var pdata []byte

		if pkt.request {
			// If we still have response buffer, we're in some weird state and
			// didn't successfully process the response.
			if rs.resbuffer != nil {
				//				log.Printf("[%s] possibly pipelined request? %d bytes",
				//					rs.src, len(rs.resbuffer))
				//				rs.resbuffer = nil
				//				rs.synced = false
			}
			rs.reqbuffer = append(rs.reqbuffer, pkt.data...)
			ptype, pdata = carvePacket(&rs.reqbuffer)
		} else {
			rs.resbuffer = append(rs.resbuffer, pkt.data...)
			ptype, pdata = carvePacket(&rs.resbuffer)
		}

		// The synchronization logic: if we're not presently, then we want to
		// keep going until we are capable of carving off of a request.
		if !rs.synced {
			if !(pkt.request && ptype == 9) {
				rs.reqbuffer, rs.resbuffer = nil, nil
				continue
			}

			// It's a GET request, so try to pull a protobuf out of this as a
			// final test to make sure we're solid.
			err := proto.Unmarshal(pdata, &riak.RpbGetReq{})
			if err != nil {
				rs.reqbuffer, rs.resbuffer = nil, nil
				continue
			}

			rs.synced = true
		}

		// No (full) packet detected yet. Continue on our way.
		if ptype == -1 {
			continue
		}
		plen := uint64(len(pdata))

		// If this is a response then we want to record the timing and
		// store it with this channel so we can keep track of that.
		var reqtime uint64
		if !pkt.request {
			if rs.reqSent == nil {
				continue
			}
			reqtime = uint64(time.Since(*rs.reqSent).Nanoseconds())

			// We keep track of per-source, global, and per-query timings.
			randn := rand.Intn(100)
			rs.reqTimes[randn] = reqtime
			times[randn] = reqtime
			if rs.qdata != nil {
				// This should never fail but it has. Probably because of a
				// race condition I need to suss out, or sharing between
				// two different goroutines. :(
				rs.qdata.times[randn] = reqtime
				rs.qdata.bytes += plen
			}
			rs.reqSent = nil

			// If we're in verbose mode, just dump statistics from this one.
			if verbose {
				log.Printf("%s %d %d %0.2f\n", rs.qtext, rs.qbytes, plen,
					float64(reqtime)/1000000)
			}

			continue
		}

		// This is for sure a request, so let's count it as one.
		if rs.reqSent != nil {
			//			log.Printf("[%s] ...sending two requests without a response?",
			//				rs.src)
		}
		tnow := time.Now()
		rs.reqSent = &tnow

		// Now see if we can possibly parse out the proto from this
		// packet or if we get gibberish.
		msg, err := getProto(ptype, pdata)
		if err != nil {
			log.Printf("[%s] failed to parse proto: %s", rs.src, err)
			continue
		}
		if msg == nil {
			log.Printf("[%s] didn't parse message: type=%d", rs.src, ptype)
			continue
		}

		// Convert this request into whatever format the user wants.
		querycount++
		var text string
		for _, item := range format {
			switch item.(type) {
			case int:
				switch item.(int) {
				case F_NONE:
					log.Fatalf("F_NONE in format string")
				case F_KEY:
					text += safe_output((*msg).key)
				case F_BUCKET:
					text += string((*msg).bucket)
				case F_SOURCE:
					text += rs.src
				case F_SOURCEIP:
					text += rs.srcip
				case F_METHOD:
					text += (*msg).method
				default:
					log.Fatalf("Unknown F_XXXXXX int in format string")
				}
			case string:
				text += item.(string)
			default:
				log.Fatalf("Unknown type in format string")
			}
		}
		qdata, ok := qbuf[text]
		if !ok {
			qdata = &queryData{}
			qbuf[text] = qdata
		}
		qdata.count++
		qdata.bytes += plen
		rs.qtext, rs.qdata, rs.qbytes = text, qdata, plen
	}
}

// carvePacket tries to pull a packet out of a slice of bytes. If so, it removes
// those bytes from the slice.
func carvePacket(buf *[]byte) (int, []byte) {
	datalen := uint32(len(*buf))
	if datalen < 5 {
		return -1, nil
	}

	size := uint32((*buf)[0])<<24 + uint32((*buf)[1])<<16 + uint32((*buf)[2])<<8 +
		uint32((*buf)[3])
	if datalen < size+4 {
		return -1, nil
	}

	end := size + 4
	ptype := int((*buf)[4])
	data := (*buf)[5 : size+4]
	if end >= datalen {
		*buf = nil
	} else {
		*buf = (*buf)[end:]
	}

	//	log.Printf("datalen=%d size=%d end=%d ptype=%d data=%d buf=%d",
	//		datalen, size, end, ptype, len(data), len(*buf))

	return ptype, data
}

// Given a set of bytes and a type, return a protocol buffer object.
func getProto(msgtype int, data []byte) (*riakMessage, error) {
	var ret *riakMessage = nil

	switch msgtype {
	case 0x09:
		obj := &riak.RpbGetReq{}
		err := proto.Unmarshal(data, obj)
		if err != nil {
			return nil, err
		}

		ret = &riakMessage{method: "get", bucket: []byte(obj.Bucket),
			key: []byte(obj.Key)}
	case 0x0a:
		// get response
	case 0x0b:
		obj := &riak.RpbPutReq{}
		err := proto.Unmarshal(data, obj)
		if err != nil {
			return nil, err
		}

		ret = &riakMessage{method: "put", bucket: []byte(obj.Bucket),
			key: []byte(obj.Key)}
	case 0x0c:
		// put response
	}

	return ret, nil
}

// Given a source ("ip:port" string), return a channel that can be used to send
// payload bytes to. If that channel doesn't exist, it sets one up.
func getChannel(src string) riakSourceChannel {
	rs, ok := chmap[src]
	if !ok {
		srcip := src[0:strings.Index(src, ":")]
		rs = &riakSource{src: src, srcip: srcip, synced: false, ch: make(riakSourceChannel, 10)}
		go riakSourceListener(rs)
		chmap[src] = rs
	}
	return rs.ch
}

// extract the data... we have to figure out where it is, which means extracting data
// from the various headers until we get the location we want.  this is crude, but
// functional and it should be fast.
func handlePacket(pkt *pcap.Packet) {
	// Ethernet frame has 14 bytes of stuff to ignore, so we start our root position here
	var pos byte = 14

	// Grab the src IP address of this packet from the IP header.
	srcIP := pkt.Data[pos+12 : pos+16]
	dstIP := pkt.Data[pos+16 : pos+20]

	// The IP frame has the header length in bits 4-7 of byte 0 (relative).
	pos += pkt.Data[pos] & 0x0F * 4

	// Grab the source port from the TCP header.
	srcPort := uint16(pkt.Data[pos])<<8 + uint16(pkt.Data[pos+1])
	dstPort := uint16(pkt.Data[pos+2])<<8 + uint16(pkt.Data[pos+3])

	// The TCP frame has the data offset in bits 4-7 of byte 12 (relative).
	pos += byte(pkt.Data[pos+12]) >> 4 * 4

	// If this is a 0-length payload, do nothing. (Any way to change our filter
	// to only dump packets with data?)
	if len(pkt.Data[pos:]) <= 0 {
		return
	}

	// This is either an inbound or outbound packet. Determine by seeing which
	// end contains our port. Either way, we want to put this on the channel of
	// the remote end.
	var src string
	var request bool = false
	if srcPort == port {
		src = fmt.Sprintf("%d.%d.%d.%d:%d", dstIP[0], dstIP[1], dstIP[2],
			dstIP[3], dstPort)
		//		log.Printf("response to %s", src)
	} else if dstPort == port {
		src = fmt.Sprintf("%d.%d.%d.%d:%d", srcIP[0], srcIP[1], srcIP[2],
			srcIP[3], srcPort)
		request = true
		//		log.Printf("request from %s", src)
	} else {
		log.Fatalf("got packet src = %d, dst = %d", srcPort, dstPort)
	}

	// Now we have the source and payload information, we can pass this off to
	// somebody who is better equipped to process it.
	getChannel(src) <- &packet{request: request, data: pkt.Data[pos:]}
}

// parseFormat takes a string and parses it out into the given format slice
// that we later use to build up a string. This might actually be an overcomplicated
// solution?
func parseFormat(formatstr string) {
	formatstr = strings.TrimSpace(formatstr)
	if formatstr == "" {
		formatstr = "#b:#k"
	}

	is_special := false
	curstr := ""
	do_append := F_NONE
	for _, char := range formatstr {
		if char == '#' {
			if is_special {
				curstr += string(char)
				is_special = false
			} else {
				is_special = true
			}
			continue
		}

		if is_special {
			switch strings.ToLower(string(char)) {
			case "k":
				do_append = F_KEY
			case "b":
				do_append = F_BUCKET
			case "s":
				do_append = F_SOURCE
			case "i":
				do_append = F_SOURCEIP
			case "m":
				do_append = F_METHOD
			default:
				curstr += "#" + string(char)
			}
			is_special = false
		} else {
			curstr += string(char)
		}

		if do_append != F_NONE {
			if curstr != "" {
				format = append(format, curstr, do_append)
				curstr = ""
			} else {
				format = append(format, do_append)
			}
			do_append = F_NONE
		}
	}
	if curstr != "" {
		format = append(format, curstr)
	}
}
