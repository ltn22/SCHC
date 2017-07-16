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

//------------------------------------------
//
//    SCHC Compressor-Decompressor MODULE
//
//------------------------------------------

/* TODO
suppress readibuf
implement compute-* (make a list of function to apply at the end
allow TK to be the size given by Token length
allow LSB for 64 bits (not urgent)
verify MSB function 
*/

var cdf = function(array){
    this.array = array;
};

cdf.prototype.computeOption = function (Type, Value, Length) {
    Length = Math.floor(Length/8)
    if (Value.length != Length) {
	console.log("There is a problem in length");
	return null;
    }
       
    deltaT = Type - this.CoAPOptionType

    
    this.CoAPOptionType = Type;

    firstByte = 0;
    if ((deltaT < 14) && (Length < 14))  {
	firstByte = deltaT << 4 | Length
    }

    // /!\ define larger deltaT and Length 

    for (var i = 7; i >= 0; i--) {
	this.seteBufBit(firstByte & (1 << i))
    }

    for (var k = 0; k < Value.length; k++) {
	if (typeof Value[k] == 'number') {
	    charCode = Value[k]
	} else if (typeof Value[k] == 'string') {
	    charCode = Value[k].charCodeAt(0)
	} else console.log('MISSED TEST');
	
	for (var i = 7; i >= 0; i--) {
	    this.seteBufBit(charCode & (1 << i))
	}
    }
}

cdf.prototype.DA_notSent = function (that, TV, length, nature, arg, algo) {
    if (nature == "variable") {
	length = TV.length*8
    }

    if (typeof TV === 'number') {
	for (var i = length-1; i >= 0; i--) {
	    that.seteBufBit(TV & (1 << i))
	}

    } else if (typeof TV === 'string') {
	if (algo == "direct") {
	    for (var k = 0; k < TV.length; k++) {
		for (var i = 7; i >= 0; i--) {
		    that.seteBufBit(TV[k].charCodeAt(0) & (1 << i))
		}
	    }
	} else {
	    if ("CoAPOption" in algo) {
		that.computeOption (algo["CoAPOption"], TV, length)
	    }
	}
    } else if (typeof TV === 'object') { // int64, cut in two
	that.DA_notSent (that, TV[0], 32, "fixed", null)
	that.DA_notSent (that, TV[1], 32, "fixed", null)
    }
    
}

cdf.prototype.DA_valueSent = function (that, TV, length, nature, arg, algo) {

    if (nature == "variable") {
	len = 0;
	for (var i = 0; i < 4; i++) {
	    len <<= 1
	    len |= that.getiBufBit()
	}
	len *= 8
	
	if (algo == "direct") {
	    that.DA_valueSent(that, null, len, "fixed", null, algo)
	} else {
	    if ("CoAPOption" in algo) {

		buff = []
		for (var b = 0; b < len; b++) {
		    octet = Math.floor (b/8);
		    offset = 7 - (b % 8)
		    if (buff.length == octet) buff[octet] = 0x00;

		    buff[octet] |= (that.getiBufBit() << offset)
		}
		    
		
		that.computeOption (algo["CoAPOption"], buff, len)
	    }
	}
	
    } else if (nature == "fixed") {
	if (algo == 'direct') {
	    for (var i = 0; i < length; i++) {
		that.seteBufBit(that.getiBufBit())
	    }
	} 
    }
}

cdf.prototype.DA_mappingSent = function (that, TV,  length, nature, arg, algo) {
    elmNb= TV.length;
    bitNb =0;
    while ((1 << bitNb) < elmNb) bitNb++;

    index = 0;
    for (var i = 0; i < bitNb; i++) {
	var v =that.getiBufBit()
	index <<= 1
	index |= v
    }

    that.DA_notSent(that, TV[index], TV[index].length, "fixed", null, algo)
}

cdf.prototype.DA_LSB = function (that, TV,  length, nature, arg, algo) {

    if (nature == "variable") {
	len = 0;
	for (var i = 0; i < 4; i++) {
	    len <<= 1
	    len |= that.getiBufBit()
	}

	that.DA_LSB(that, TV, len*8, "fixed", null, algo)
    } else if (nature = "fixed") {

	if (typeof TV === 'number') {
	    merged = TV;
	    
	    for (var i = arg-1; i>= 0; i--) {
		bin = that.getiBufBit()

		merged |= bin << i
	    }
	    that.DA_notSent(that, merged, length, "fixed", null, algo)
	} else if (typeof TV == 'string') {
	    if ((length % 8) != 0) {
		console.log("error")
	    } else {
		charNb = Math.floor(length/8);
		for (var i=0; i < charNb; i++) {
		    value = 0
		    for (var k =7; k >= 0; k--) {
			value |= that.getiBufBit()  << k
		    }

		    TV += String.fromCharCode(value);
		}

		that.DA_notSent(that, TV, TV.length*8, "fixed", null, algo)

	    }
	}
    }
}

cdf.prototype.DA_computeLength = function (that, TV,  length, nature, arg, algo) {
    console.log("Compute Length");
    that.DA_notSent (that, 0xFFFF, 16, "fixed", null, algo)
}

cdf.prototype.DA_computeChecksum = function (that, TV, length, nature, arg, algo) {
    console.log("Compute Checksum");
    that.DA_notSent (that, 0xCCCC,  16, "fixed", null, algo)
}

// Compression Actions

cdf.prototype.CA_notSent = function (that, TV, FV, length, nature, arg) {
    console.log("notSent TV =", TV, "FV=", FV, "Length=", length, "arg=", arg, "nature=", nature);
}

cdf.prototype.CA_valueSent = function (that, TV, FV, length, nature, arg) {
    console.log("valueSent TV =", TV, typeof TV, "FV=", FV, typeof FV, "Length=", length, "arg=", arg, "nature=", nature);

    if (nature == 'variable') {
	byteLength = Math.floor (length/8)

	if (byteLength < 15) {
	    for (var b = 3; b >= 0; b--)
		that.seteBufBit (byteLength & (1 << b))
	}
	that.CA_valueSent(that, TV, FV, length, "fixed", arg)
	
    } else if (nature == "fixed") {
	if (typeof FV === 'number') {
	    for (var b = length-1; b >= 0; b--) {
		bit = FV & (1 << b)
		that.seteBufBit(bit)
	    }
	} else if (typeof FV == "string") {

	    if (length < FV.length) {
		console.log ("error on length for ", FV)
		return false
	    }
	    
	    for (var l = 0; l < length; l++) {
		for (var b = 7; b >= 0; b--) {
		    bit = FV & (1 << b)
		    that.seteBufBit(bin)
		}
	    }
	    
	} else if (typeof FV == "object") {
	    if (length != 64) {
		console.log ("error on length for ", TV)
		return false
	    }
	    that.valueSent(that, FV[0], null, 32, "fixed", arg)
	    that.valueSent(that, FV[1], null, 32, "fixed", arg)
	} else {
	    console.log ("TV type unknown ", typeof FV)
	    return false
	}

    } else {
	console.log ("Nature ", nature, " unknown");
	return
    }
}

cdf.prototype.CA_mappingSent = function (that, TV, FV, length, nature, arg) {
    console.log("mappingSent TV =", TV, "FV=", FV, "Length=", length, "arg=", arg, "nature=", nature);

    var nbElm = TV.length
    var bitNb = 0

    while ((1 << bitNb) < nbElm) bitNb++

    for (var idx in TV) {
	if ((typeof FV == 'number') || (typeof FV == 'string')) {
	    if (FV == TV[idx]) break
	} else if (typeof FV == 'object') {
	    if ((FV[0] == TV[idx][0]) && (FV[0] == TV[idx][0])) break
	}
    }
    that.CA_valueSent(that, parseInt(idx), parseInt(idx), bitNb, "fixed", null) 
}

cdf.prototype.CA_LSB = function (that, TV, FV, length, nature, arg) {
    console.log("LSB TV =", TV, "FV=", FV, "Length=", length, "arg=", arg, "nature=", nature);

    if (typeof FV == 'number') {
	that.CA_valueSent(that, TV, FV, arg, nature, 0)
    }
}

cdf.prototype.CA_computeLength = function (that, TV, FV, length, nature, arg) {
    console.log("computeLength TV =", TV, "FV=", FV, "Length=", length, "arg=", arg, "nature=", nature);
}

cdf.prototype.CA_computeChecksum = function (that, TV, FV, length, nature, arg) {
    console.log("computeChecksu TV =", TV, "FV=", FV, "Length=", length, "arg=", arg, "nature=", nature);;
}



cdf.prototype.MO_equal = function (TV, FV, length, arg) {
    console.log("equal ", TV, " FV ", FV, ' ', typeof TV)

    if (typeof TV === 'object') { // ugly test in case 64 bit long word is cut into [xx, yy]
	if ((TV[0] == FV[0]) && (TV[1] == FV[1])) return true
	return false
    }
    
    if (typeof TV != typeof FV) return false
    if (TV != FV) return false

    return true
}


cdf.prototype.MO_ignore= function (TV, FV, length, arg) {
    console.log("ignore ", TV, " FV ", FV)
    return true
}


cdf.prototype.MO_MSB = function (TV, FV, length, arg) {
    console.log("MSB ", TV, " FV ", FV)

    if (typeof TV != typeof FV) return false

    if (arg > length) {
	console.log ("MO_MSB: arg too large compare to field length")
	return false
    }

    if (typeof TV === 'number') {
	// /!\ we suppose the comparison is made on 32 bit words

	for (var b = (length - arg); b < length; b++) {
	    if ((TV & (1 << b)) != FV & (1 << b)) return false
	}
	return true	
    }

    if (typeof TV === 'string') {
	console.log ('/!\ STRING MSB missing')
    }
    
    return false
}


cdf.prototype.MO_matchMapping = function (TV, FV, length, arg) {
    console.log("matchMapping ", TV, " FV ", FV)

    if (typeof TV === 'object') {
	for (var e in TV) {
	    if (typeof FV === 'object') {
		if ((TV[e][0] == FV[0]) && (TV[e][1] == FV[1]))  return true
	    } else {
		if (typeof TV[e] == typeof FV) {
		    if (TV[e] == FV) return true
		}
	    }
	}
	
    }
    
    return false
}


cdf.prototype.noReadiBuf = function (that, length){
    return null, 0
}

cdf.prototype.getiBufBit = function () {
    var octet = Math.floor(this.iIdx / 8)
    var offset = 7 - (this.iIdx % 8)


    var msk = 1 << offset
    var bin = this.iBuf[octet] & msk

//    if (bin) console.log ("\t ", this.iIdx, " B=1")
//    else console.log ("\t ", this.iIdx, " B=0")

    this.iIdx++
    
    if (bin) return (0x01)
    else     return (0x00)
}

cdf.prototype.seteBufBit = function (bin) {
    var octet = Math.floor(this.eIdx / 8)
    var offset = 7 - (this.eIdx % 8)

    if (this.eBuf.length == octet) {
	this.eBuf[octet] = 0x00
    }

    if (bin) this.eBuf[octet] |= 1 << offset

    this.eIdx++

    /* // DUMP the exit buffer

    for (var l = 0; l < Math.floor(this.eIdx/8) +1; l++) {
	var val = parseInt(this.eBuf[l])

	if (val < 16) process.stdout.write('0')
	
	var txt = val.toString(16)
	process.stdout.write (txt)
	process.stdout.write (' ')

	if ((l+1) %32 == 0) console.log('')
	
    }
    txt = this.eIdx.toString()
    process.stdout.write('/');
    process.stdout.write(txt);
    console.log ('[', Math.floor(this.eIdx/8)+1,']')
*/
}



cdf.prototype.initializeCD = function(){
    // The context will store the rules that can be used for a compression
    this.context = [];
    // Header received from the EndSystem
    this.parsedHeaderFields = {};
    // Received payload for the decompression stage
    this.received_payload = "";
    // Fields sizes in bits
    this.field_size = {
        "IPv6.version": [4, "direct"],
        "IPv6.trafficClass": [8, "direct"],
        "IPv6.flowLabel": [20, "direct"],
        "IPv6.payloadLength": [16, "direct"],
        "IPv6.nextHeader": [8, "direct"],
        "IPv6.hopLimit": [8, "direct"],
	"IPv6.checksum": [16, "direct"],
        "IPv6.prefixES": [64, "direct"],
        "IPv6.iidES": [64, "direct"],
        "IPv6.prefixLA": [64, "direct"],
        "IPv6.iidLA": [64, "direct"],
        "UDP.PortES": [16, "direct"],
        "UDP.PortLA": [16, "direct"],
        "UDP.length": [16, "direct"],
        "UDP.checksum": [16, "direct"],
        "CoAP.version": [2, "direct"],
        "CoAP.type": [2, "direct"],
        "CoAP.tokenLength": [4, "direct"],
        "CoAP.code": [8, "direct"],
        "CoAP.messageID": [16, "direct"],
        "CoAP.token": [8, "direct"],   // MUST be set to TKL value
	"CoAP.Uri-Path" :  ["variable", {"CoAPOption": 11}],
	"CoAP.Uri-Query" : ["variable", {"CoAPOption": 15}],
	"CoAP.Option-End" : [8, "direct"]
    }
    this.DecompressionActions = {
	"not-sent":  this.DA_notSent,
	"value-sent": this.DA_valueSent,
	"mapping-sent": this.DA_mappingSent,
	"LSB":  this.DA_LSB,
	"compute-length": this.DA_computeLength,
	"compute-checksum": this.DA_computeChecksum
    }
    this.CompressionActions = {
	"not-sent":  this.CA_notSent,
	"value-sent": this.CA_valueSent,
	"mapping-sent": this.CA_mappingSent,
	"LSB":  this.CA_LSB,
	"compute-length": this.CA_computeLength,
	"compute-checksum": this.CA_computeChecksum
    }
    this.MatchingOperators = {
	"equal": this.MO_equal,
	"ignore": this.MO_ignore,
	"MSB": this.MO_MSB,
	"match-mapping": this.MO_matchMapping
    }
    
    var iBuf = []; // binary version of the message
    var eBuf = []; // uncompressed message
    var iIdx = 0 // pointing on the bit of the incoming message
    var eIdx = 0 // pointing on the bit of the egress message
    var CoAPOptionType = 0; 
    

};


//------------------------------------------
//
//              Decompression
//
//------------------------------------------



cdf.prototype.addRule = function(rule){
    var index = this.context.length;

    var nbUp = 0;
    var nbDw = 0;

    for (var e in rule['content']) {
	var entry = rule['content'][e]

	if ((entry[2] == "bi") || (entry[2] == "up")) nbUp +=1
	if ((entry[2] == "bi") || (entry[2] == "dw")) nbDw +=1
    }

    rule['upRules'] = nbUp
    rule['downRules'] = nbDw
    
    this.context[index] = rule;

};

/*
cdf.prototype.loadIIDs = function(ESiid,LAiid){
    this.ESiid = ESiid;
    this.LAiid = LAiid;
};
*/

// HACERLO BIEN COMO TOUTAIN

cdf.prototype.findRule = function ( ES_DID, message ) {
//    console.log("find rule for ", ES_DID);

    rule = message.slice(0,2)
    rule = parseInt(rule);

//    console.log ("Message RuleId is: ", rule);

    for (var i = 0; i < this.context.length; i++) {
//	console.log("rule ", this.context[i]);
	if (this.context[i]['ruleid'] == rule) {
//	    console.log('BINGO')
	    return this.context[i]
	}
    }
    return Null
}

cdf.prototype.forgePacket = function (rule, message, direction) {

    this.iBuf = []
    this.eBuf = []
    this.iIdx = 8;  // skip rule number 
    this.eIdx = 0;
    this.CoAPOptionType = 0; 
    
    for (i=0; i < message.length;i+=2) {
	byteIdx = this.iBuf.length
	this.iBuf[byteIdx] = parseInt(message.slice(i, i+2), 16)
    }
//    console.log ('iBuf =', this.iBuf)

    for (var e in rule['content']) {
	var entry = rule['content'][e]


        var FID = entry[0];
        var POS = entry[1];
	var DIR = entry[2];

	if ((DIR == "bi") || (DIR == direction)) {
	
            var TV = entry[3];
            var MO = entry[4];
            var DA = entry[5];
	    var FV = null
	    
	    var nature;
	    
	    var arg = null
            reg = /\((.*)\)/.exec(DA);
	    
	    if (reg != null) {
		arg = parseInt(reg[1])
	    } else {
		reg = /\((.*)\)/.exec(MO);
		if (reg != null) {
		    arg = parseInt(reg[1])
		}
	    }
	    
	    if (typeof this.field_size[FID][0] === 'number') {
		nature = "fixed"
		size = this.field_size[FID][0]
		if (arg != null) { // /!\ do not work if DA contains a value
		    arg = size - arg // /!\ check that the number is not negative 
		}
	    } else if (typeof this.field_size[FID][0] === 'string') {
		if (this.field_size[FID][0] == "variable") {
		    nature = "variable"
		}
		else {
		    console.log("Unknwon field size keywork")
		}
	    }
	    
	    algo = this.field_size[FID][1]
	    
//	    console.log ("DECOMPRESSION: ", "FID = ", FID, " ", DA, " TV= ", TV, " size= ", size, " nature = ", nature, " arg = ", arg, " algo = ", algo)
	    
	    this.DecompressionActions[DA](this, TV, size, nature,  arg, algo)
	}
	
    }

    // rest of iBuf are data, put them after the uncompressed header


    while (this.iIdx < this.iBuf.length*8) {

	val = this.getiBufBit()
	this.seteBufBit(val)
    }
    return this.eBuf;
}

// For compression

cdf.prototype.find_rule_from_pkt = function (headers, direction)
{
    for (r in this.context) {
	foundEntries = 0
	for (e in this.context[r].content) {
	    entry = this.context[r].content[e]

	    FID = entry[0]
	    POS  = entry[1]
	    DI = entry[2]

	    if ((DI == "bi") || (DI == direction)) {
		try{
		    FV = headers[FID][POS-1][0]
		}
		catch(err){
		    console.log("Rule header", FID," not in packet")
		    break;
		}
				
		
		foundEntries += 1
		TV = entry[3]
		MO = entry[4]

		fieldLength = headers[FID][POS-1][1]

		var arg = null
		reg = /\((.*)\)/.exec(MO);

		if (reg != null) {
		    arg = parseInt(reg[1])
		    MO = MO.replace(/\([^)]*\)/g, "")
		}
		if (! this.MatchingOperators[MO](TV, FV, fieldLength, arg)) {
		    console.log('entry do not fit')
		    break
		}
		
	    }

	}

	
	
	if (foundEntries == this.context[r].downRules) return r
	
    }
    return null
}



cdf.prototype.parser = function (pkt) {

    var field_poistion= {}
    var header_fields = []

// ES and LA are inverted compared to python code
    
    header_fields["IPv6.version"]      = [[pkt[0] >> 4, 4, 'fixed']]
    header_fields["IPv6.trafficClass"] = [[(pkt[0] & 0x0F) << 4 | (pkt[1] & 0xF0) >> 4, 8, 'fixed']]
    header_fields["IPv6.flowLabel"]    = [[(pkt[1] & 0x0F ) << 16 | pkt[2] << 8 | pkt[3], 20, 'fixed']]
    header_fields["IPv6.payloadLength"]= [[pkt[4] << 8 | pkt[5] , 16, 'fixed']]
    header_fields["IPv6.nextHeader"]   = [[pkt[6], 8, 'fixed']]
    header_fields["IPv6.hopLimit"]     = [[pkt[7], 8, 'fixed']]
    header_fields["IPv6.prefixLA"]     = [[ [(pkt[8]<<24 | pkt[9]<<16 | pkt[10]<<8 | pkt[11])>>>0,   (pkt[12]<<24 | pkt[13]<<16 | pkt[14]<<8 | pkt[15])>>>0 ], 64, 'fixed']]
       
    header_fields["IPv6.iidLA"]        = [[ [(pkt[16]<<24 | pkt[17]<<16 | pkt[18]<<8 | pkt[19])>>>0, (pkt[20]<<24 | pkt[21]<<16 | pkt[22]<<8 | pkt[23])>>>0 ], 64, 'fixed']]
    header_fields["IPv6.prefixES"]     = [[ [(pkt[24]<<24 | pkt[25]<<16 | pkt[26]<<8 | pkt[27])>>>0, (pkt[28]<<24 | pkt[29]<<16 | pkt[30]<<8 | pkt[31])>>>0 ], 64, 'fixed']]
    header_fields["IPv6.iidES"]        = [[ [(pkt[32]<<24 | pkt[33]<<16 | pkt[34]<<8 | pkt[35])>>>0, (pkt[36]<<24 | pkt[37]<<16 | pkt[38]<<8 | pkt[39])>>>0 ], 64, 'fixed']]
    header_fields["UDP.PortLA"]        = [[pkt[40] << 8 | pkt[41], 16, 'fixed']]
    header_fields["UDP.PortES"]        = [[pkt[42] << 8 | pkt[43], 16, 'fixed']]
    header_fields["UDP.length"]        = [[pkt[44] << 8 | pkt[45], 16, 'fixed']]
    header_fields["UDP.checksum"]      = [[pkt[46] << 8 | pkt[47], 16, 'fixed']]
    header_fields["CoAP.version"]      = [[pkt[48] >> 6, 2, 'fixed']]
    header_fields["CoAP.type"]         = [[(pkt[48] & 0x30) >> 4, 2, 'fixed']]  
    header_fields["CoAP.tokenLength"]  = [[pkt[48] & 0x0F, 4, 'fixed']]
    header_fields["CoAP.code"]         = [[pkt[49], 8, 'fixed']]
    header_fields["CoAP.messageID"]    = [[pkt[50] << 8 | pkt[51] , 16, 'fixed']]

    pos = 52;
    token = 0;

    for (var i =0; i < header_fields["CoAP.tokenLength"][0][0]; i++) {
	token <<= 8
	token |= pkt[pos]
	pos += 1
    }

    header_fields["CoAP.token"] = [[token, header_fields["CoAP.tokenLength"][0][0]*8, 'fixed']]

    option_number = 0

    while (pos < pkt.length) {
	if (pkt[pos] == 0xFF) break;

	console.log('COAP OPTION NOT PROCESSED')
	deltaTL = pkt[pos]
	pos += 1
    }

    
    return [header_fields, this.eBuf.slice(pos)]
    /* TO BE TRANSLATED IN JS

        option_number = 0[
        while (pos < len(packet)):
            if (int(packet[pos]) == 0xFF): break

            deltaTL = int(packet[pos])
            pos += 1
            deltaT = (deltaTL & 0xF0) >> 4
            # /!\ add long value
            option_number += int(deltaT)

            L = int(deltaTL & 0x0F)
            # /!\ add long values

            try:
                field_position[option_number] += 1
            except:
                field_position[option_number] = 1

            option_value = ''

            for i in range (0, L):
                option_value += chr(packet[pos])
                pos += 1
                # /!\ check if max length is reached

            self.header_fields[option_names[option_number], field_position[option_number]] = [option_value, L*8,  "variable"]

*/



}

cdf.prototype.apply = function (rule, headers, direction) {
    this.eBuf = []
    this.eIdx = 0

    
    for (e in this.context[rule].content) {
	entry = this.context[rule].content[e]

	FID = entry[0]
	POS  = entry[1]
	DI = entry[2]

	if ((DI == 'bi') || (DI == direction)) {
	    try{
		FV = headers[FID][POS-1][0]
	    }
	    catch(err){
		console.log("Rule header", FID," not in packet")
		return;
	    }

	    TV = entry[3]
	    MO = entry[4]
	    CA = entry[5]
	    
	    fieldLength = headers[FID][POS-1][1]
	    
	    var arg = null
	    reg = /\((.*)\)/.exec(CA);
	    
	    if (reg != null) {
		arg = parseInt(reg[1])
		CA = CA.replace(/\([^)]*\)/g, "")
	    } else {
		reg = /\((.*)\)/.exec(MO);
		
		if (reg != null) {
		    arg = fieldLength - parseInt(reg[1])
		}
	    }
	    
	    nature = headers[FID][POS-1][2]
		
	    this.CompressionActions[CA](this, TV, FV, fieldLength, nature, arg)

	}
    }
    return this.eBuf
    
}

module.exports = exports = cdf;

//------------------------------------------
//
//              AUXILIARY FUNCTIONS
//
//------------------------------------------

function checksum(msg){
    // Computes the UDP checksum for the decompressor
    // msg includes the pseudo-header for UDP, the UDP header and the UDP payload.
    // If the length of msg is not even a zero byte is added
    if (msg.length % 2 === 1){
        var zero = Buffer.alloc(1);
        msg = Buffer.concat([msg, zero]);
    }
    var s = 0;
    var w = 0;
    // Loop taking 2 bytes at a time (16 bits)
    for(i=0; i +2 <= msg.length ; i+=2){
        w = msg[i+1] + (msg[i] << 8);
        s = s + w;
    }
    while (s > 0xffff){
        s = (s >> 16) + (s & 0xffff);
    }
    // Complement and mask to 2 bytes (dont know for what is this last part)
    s = ~s & 0xffff;
    return s;
}
