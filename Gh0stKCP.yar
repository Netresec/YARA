rule Gh0stKCP
{
  meta:
    author = "Netresec"
    description = "Checks for Gh0stKCP. Forked from @stvemillertime's KCP catchall rule."
strings:
	$hex = { be b6 1f eb da 52 46 ba 92 33 59 db bf e6 c8 e4 }
        $a01 = "[RO] %ld bytes"
        $a02 = "recv sn=%lu"
        $a03 = "[RI] %d bytes"
        $a04 = "input ack: sn=%lu rtt=%ld rto=%ld"
        $a05 = "input psh: sn=%lu ts=%lu"
        $a06 = "input probe"
        $a07 = "input wins: %lu"
        $a08 = "rcv_nxt=%lu\\n"
        $a09 = "snd(buf=%d, queue=%d)\\n"
        $a10 = "rcv(buf=%d, queue=%d)\\n"
        $a11 = "rcvbuf"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 30MB and @hex and 5 of ($a*)
}
