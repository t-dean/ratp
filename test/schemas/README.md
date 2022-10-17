Test Schemas
============

Schemas are testable diagrams of RATP sessions. Schemas are used to quickly
describe how a RATP session is expected to behave and check that the
implementation matches that expectation.

Schema Organization
-------------------

Schemas are a series of packets and external operations. Schemas are executed
from the top of the file to the bottom. The left and right columns of the schema
represent the two ends of a RATP connection. All schemas start with both sides
in the CLOSED state. This must be stated as the first line of the schema file.

Schema Grammar
--------------

A schema file is made up of a sequence of lines. Each line can either be an
_external command_ or an expected _packet_ transmission.

External commands
-----------------

External commands are enclosed in brackets (i.e. `[` and `]`). There is a fixed
set of external commands. The set of possible external commands is as follows:

* Passive Open (listen)
* Active Open (connect)
* Send: 0x<hex data string> | "<ascii data string>"
* Close

An external command line format is as follows:

[ "[" COMMAND_LEFT "]" ]                               [ "[" COMMAND_RIGHT "]" ]

Packets
-------

Expected packet lines describe the state of both sides of the connection, the
packet sequence number and control flags. They also may declare the expected
acknowledgment number, MDL / LEN (used interchangeably), and data.

A packet line format is as follows:

```
<State Left> <"---" | "<---"> [ "[x]" ] < "<SN=" $SN ">" [ "<AN=" $AN ">" ] [ "<CTL=" CTL_VALUES ">" ][ "<MDL=" | "<LEN=" $LEN ">" ] [ "<DATA=" ("0x" $HEX_DATA | \" $ASCII_DATA \") ">" ] <"---" | "--->"> <State Right>
```

Packet lines are checked after the ratp_rx_packet call completes for the
receiving end. The if "[x]" appears in the packet line, the schema runner drops
the packet and the receiver's ratp_rx_packet function is never called. However,
the packet is still inspected to ensure it matches the packet defined in the
packet line.
