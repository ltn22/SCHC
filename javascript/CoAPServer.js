/*
SCHC compressor, Copyright (c) <2017><IMT Atlantique and Philippe Clavier>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

var path = require('path');
var express = require('express');

const packetCoAP = require ('coap-packet');
const parseCoAP  = packetCoAP.parse;
const generateCoAP = packetCoAP.generate
const cbor = require('cbor');

const util=require('util')

var dweetClient = require("node-dweetio");
var dweetio = new dweetClient();


var comp_decomp = require('./schc'); // IMPORTING CD MODULE
// Importing parser module
//var Parser = require('./parser');

// --------------------------------------------------------------
// RULES DEFINITIONS
var None = null;

//                           fID                  Pos  DI  TV                  MO           CDA
var rule_coap0 = {"ruleid"  : 0,
    "content" : [["IPv6.version",     1,  "bi", 6,                  "equal",  "not-sent"],
        ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
        ["IPv6.flowLabel",    1,  "bi", 0x000000,           "equal",  "not-sent"],
        ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
        ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
        ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
	["IPv6.prefixES",     1,  "bi", [0xFE800000,
						  0x00000000], "equal", "not-sent"],
        ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
        ["IPv6.prefixLA",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
        ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
        ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
        ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
        ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
        ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
        ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
        ["CoAP.type",         1,  "up", 0,                  "equal", "not-sent"],
	["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
        ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
        ["CoAP.code",         1,  "bi", 2,                  "equal", "not-sent"],
        ["CoAP.messageID",    1,  "bi", 1,                  "MSB(4)", "LSB"],
        ["CoAP.token",        1,  "bi", 0x01,               "MSB(4)", "LSB"],
        ["CoAP.Uri-Path",     1,  "up", "foo",              "equal", "not-sent"],
        ["CoAP.Uri-Path",     2,  "up", "bar",              "ignore", "value-sent"]
    ]};
var rule_coap1 = {"ruleid"  : 1,
    "content" : [["IPv6.version",     1,  "bi", 6,                  "equal",  "not-sent"],
		 ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
		 ["IPv6.flowLabel",    1,  "bi", 0x000000,            "equal",  "not-sent"],
		 ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
		 ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
		 ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
		 ["IPv6.prefixES",     1,  "bi", [0xFE800000, 0x00000000], "equal", "not-sent"],
		 ["IPv6.iidES",        1,  "bi", [0x00000000, 0x00000001], "equal", "not-sent"],
		 ["IPv6.prefixLA",     1,  "bi", [[0x20010660, 0x73010001],
						  [0x20011234, 0x56789012],
						  [0x20011234, 0x56789013],
						  [0xFE800000, 0x00000000]],"match-mapping", "mapping-sent"],
		 ["IPv6.iidLA",        1,  "bi", [0x00000000, 0x00000002], "equal", "not-sent"],
		 ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
		 ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
		 ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
		 ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
		 ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
		 ["CoAP.type",         1,  "up", 0,                  "equal", "not-sent"],
		 ["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
		 ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
		 ["CoAP.code",         1,  "up", 2,                  "equal", "not-sent"],
		 ["CoAP.code",         1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
		 ["CoAP.messageID",    1,  "bi", 0x00,               "MSB(12)", "LSB"],
		 ["CoAP.token",        1,  "bi", 0x80,               "MSB(4)", "LSB"],
		 ["CoAP.Uri-Path",     1,  "up", "foo",              "equal", "not-sent"],
		 ["CoAP.Uri-Path",     2,  "up", "bar",              "equal", "not-sent"],
		 ["CoAP.Uri-Path",     3,  "up", None,               "ignore", "value-sent"],
		 ["CoAP.Uri-Query",    1,  "up", "k=",               "MSB(16)", "LSB"],
		 ["CoAP.Option-End",   1,  "up", 0xFF,               "equal", "not-sent"]
    ]};


var CD = new comp_decomp(); // NEW (EMPTY) Compressor Decompressor Function


CD.initializeCD();  // COMPRESSOR-DECOMPRESSOR INITIALIZED
CD.addRule(rule_coap0); // COMPRESSION RULES ADDED TO THE CD
CD.addRule(rule_coap1);


// --------------------------------------------------------------

// HTTP server
var httpServer = express();

function IP_UDP(IPv6_SA, IPv6_DA, UDP_SP, UDP_DP, ulp) {
    len = ulp.length + 8

    l1 = len >> 8;
    l2 = (len & 0x00FF)

    l = [l1, l2]
    c = [0xCC, 0xCC]
    
    start = [0x60, 0x00, 0x00, 0x00, l1, l2, 17, 30]

    IP = start.concat(IPv6_SA, IPv6_DA, UDP_SP, UDP_DP, l, c); 

   for (var i =0; i <ulp.length; i++)
       IP = IP.concat(ulp[i])
    

    return IP;
}

// Route for POST /coap
httpServer.post('/coap', function(req, res){
    var buff = '';

    req.on('data',function(data){
        buff = data;
    });
    req.on('end',function(){
        console.log ('\nhttp receives on APP '+"["+buff.toString()+"]\n");
	
        var http_data = JSON.parse(buff.toString());

//	console.log ('RAW JSON', util.inspect(http_data))
	
        var ES_DID = http_data.devEUI;
        var message = http_data.data;

        // Message is passed from base64 to hex
        message = new Buffer(message, 'base64');
        message = message.toString('hex');

	rule = CD.findRule(ES_DID, message)

//	console.log('Found rule ', rule)
	if (rule) {
	    pkt = CD.forgePacket(rule, message, "up")

	    if (pkt != null) {
		// remove IPv6 and CoAP Header (should remember addresses and port)
		IPv6Header = pkt.slice (0, 40)

		IPv6_SourceAddress = IPv6Header.slice (8, 24)
		IPv6_DestinationAddress = IPv6Header.slice(24, 40)
		
		pkt.splice(0, 40); 
		UDPHeader = pkt.slice (0, 8);
		UDP_SourcePort = UDPHeader.slice (0, 2);
		UDP_DestinationPort = UDPHeader.slice (2, 4);
		
		pkt.splice(0, 8);

		data = Buffer.from(pkt)
		
		msgCoAP = parseCoAP(data)
		console.log(" CoAP request = ", util.inspect(msgCoAP))

		cbor.decodeFirst(msgCoAP.payload, function(error, obj) {
		    console.log (obj[1])
		    temp = obj[0]
		    humi = obj[1]

		    var dweetMsg = {
			temp : temp/100,
			press: humi/100
		    }

		    console.log(dweetMsg)

		    dweetio.dweet_for("coap-temp-bureau", dweetMsg, function(err, dweet){
			console.log(dweet)
		    });
		})

		// create CoAP Answer

		if (msgCoAP.confirmable) {
		    console.log ("send ACK")
		    repCoAP = {
			ack : true,
			code : '2.05',
			token: msgCoAP.token,
			messageId : msgCoAP.messageId
//			messageId : 8
		    }

		    console.log ('Token =', msgCoAP.token)
		    console.log ('MID   =', msgCoAP.messageId)

		    repCoAPbuf = generateCoAP(repCoAP)
		    console.log('CoAP response ' + repCoAPbuf.toString('hex'))
		    
		    
		    console.log (util.inspect(repCoAPbuf))
		    
		    // reply so Source and Destination are inversed
		    fullMessage = IP_UDP (IPv6_DestinationAddress, IPv6_SourceAddress, UDP_DestinationPort, UDP_SourcePort, repCoAPbuf)

		    
		    
		    v = CD.parser(fullMessage);
		    parsedPkt = v[0]
		    CoAPData  = v[1]
		    
		    rule = CD.find_rule_from_pkt (parsedPkt, "dw")
		    console.log ('found rule numner =', rule)
		    console.log ('sending back')

		    if (rule != null) {
			compressedResp = CD.apply (rule, parsedPkt, "dw")
			compressedResp.unshift(parseInt(rule)) // add ruleid at the beginning
		    }

		    // convert a byte arry into base64, do not find optimal
		    // method.

		    respStr = Buffer.from(compressedResp).toString('base64')
		    console.log(respStr)
		    
		    console.log ('compressed response=', compressedResp)
		    res.writeHead(200);
		    var responseStruct = {
			'fport' : 2,
			'data' : respStr,
			'devEUI' : ES_DID
		    }

		    console.log ('Response =', responseStruct)
		    res.end(JSON.stringify(responseStruct));
		}
		console.log('no more data');}
 
	}

    });
});

//httpServer.listen(3333);
//console.log('Listening on port 3333');

httpServer.listen(4004);
console.log('Listening on port 4004');
