#!/usr/bin/env node

var pcap = require("pcap"),
    pcap_session,
    tcp_tracker = new pcap.TCPTracker(),
    dataState = "",
    dateEnc = "",
    MYSQL_SLEEP = 0 /* not from client */ ,
    MYSQL_QUIT = 1,
    MYSQL_INIT_DB = 2,
    MYSQL_QUERY = 3,
    MYSQL_FIELD_LIST = 4,
    MYSQL_CREATE_DB = 5,
    MYSQL_DROP_DB = 6,
    MYSQL_REFRESH = 7,
    MYSQL_SHUTDOWN = 8,
    MYSQL_STATISTICS = 9,
    MYSQL_PROCESS_INFO = 10,
    MYSQL_CONNECT = 11 /* not from client */ ,
    MYSQL_PROCESS_KILL = 12,
    MYSQL_DEBUG = 13,
    MYSQL_PING = 14,
    MYSQL_TIME = 15 /* not from client */ ,
    MYSQL_DELAY_INSERT = 16 /* not from client */ ,
    MYSQL_CHANGE_USER = 17,
    MYSQL_BINLOG_DUMP = 18 /* replication */ ,
    MYSQL_TABLE_DUMP = 19 /* replication */ ,
    MYSQL_CONNECT_OUT = 20 /* replication */ ,
    MYSQL_REGISTER_SLAVE = 21 /* replication */ ,
    MYSQL_STMT_PREPARE = 22,
    MYSQL_STMT_EXECUTE = 23,
    MYSQL_STMT_SEND_LONG_DATA = 24,
    MYSQL_STMT_CLOSE = 25,
    MYSQL_STMT_RESET = 26,
    MYSQL_SET_OPTION = 27,
    MYSQL_STMT_FETCH = 28;


if (process.argv.length > 4) {
    console.error("usage: mysql_jdbc_metrics interface filter");
    console.error("Examples: ");
    console.error("  tcp_metrics lo0 \"ip proto \\tcp and tcp port 3306\"");
    process.exit(1);
}

function lpad(str, len) {
    while (str.length < len) {
        str = "0" + str;
    }
    return str;
}

var int8_to_hex = [];
var int8_to_hex_nopad = [];
var int8_to_dec = [];

for (var i = 0; i <= 255; i++) {
    int8_to_hex[i] = lpad(i.toString(16), 2);
    int8_to_hex_nopad[i] = i.toString(16);
    int8_to_dec[i] = i.toString();
}

// decoding table: command 
// thank you wireshark
var mysql_commands = [
    "SLEEP", "Quit", "Use Database", "Query", "Show Fields", "Create Database", "Drop Database", "Refresh", "Shutdown", "Statistics",
    "Process List", "Connect", "Kill Server Thread", "Dump Debuginfo", "Ping", "Time", "Insert Delayed", "Change User", "Send Binlog", "Send Table",
    "Slave Connect", "Register Slave", "Prepare Statement", "Execute Statement", "Send BLOB", "Close Statement", "Reset Statement", "Set Option",
    "Fetch Data"
];


pcap_session = pcap.createSession(process.argv[2], process.argv[3], 20 * 1024 * 1024, null);

// listen for packets, decode them, and feed TCP to the tracker
pcap_session.on("packet", function(raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    tcp_tracker.track_packet(packet);
});

// tracker emits sessions, and sessions emit data
tcp_tracker.on("session", function(session) {
    console.log("Start of TCP session between " + session.src_name + " and " + session.dst_name);
    session.on("data send", function(session, data) {
        console.log(session.src_name + " -> " + session.dst_name + " data send " + session.send_bytes_payload + " + " + data.length + " bytes");
        outputSendData(session, data);
    });
    session.on("data recv", function(session, data) {
        console.log(session.dst_name + " -> " + session.src_name + " data recv " + session.recv_bytes_payload + " + " + data.length + " bytes");
        outputRecvData(session, data);
    });
    session.on("end", function(session) {
        console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
        console.log("Set stats for session: ", session.session_stats());
    });
});

function outputSendData(session, data) {
    var payload = "",
        opCode = data.readUInt8(4),
        offset = 5,
        lenstr = 0;

    switch (opCode) {

        case MYSQL_QUIT:
            payload = decode(data.slice(offset));
            break;

        case MYSQL_PROCESS_INFO:
            dataState = "RESPONSE_TABULAR";
            payload = decode(data.slice(offset));
            break;

        case MYSQL_DEBUG:
        case MYSQL_PING:
            dataState = "RESPONSE_OK";
            payload = decode(data.slice(offset));
            break;

        case MYSQL_STATISTICS:
            dataState = "RESPONSE_MESSAGE";
            payload = decode(data.slice(offset));
            break;

        case MYSQL_INIT_DB:
        case MYSQL_CREATE_DB:
        case MYSQL_DROP_DB:
            lenstr = getBufferRemaining(data, offset);
            payload = decode(data.slice(offset));
            dataState = "RESPONSE_OK";
            break;

        case MYSQL_QUERY:
            payload = decode(data.slice(offset));
            dataState = "RESPONSE_TABULAR";
            break;

        case MYSQL_STMT_PREPARE:
            payload = decode(data.slice(offset));
            dataState = "RESPONSE_PREPARE";
            break;

        case MYSQL_STMT_CLOSE:
            payload = data.readUInt8(offset);
            dataState = "REQUEST";
            break;

        case MYSQL_STMT_RESET:
            payload = data.readUInt8(offset);
            dataState = "RESPONSE_OK";
            break;

        case MYSQL_FIELD_LIST:
            payload = decode(data.slice(offset));
            dataState = RESPONSE_SHOW_FIELDS;
            break;

        case MYSQL_PROCESS_KILL:
            payload = data.readUInt8(offset);
            dataState = "RESPONSE_OK";
            break;

        case MYSQL_CHANGE_USER:
            payload = decode(data.slice(offset));
            dataState = "RESPONSE_OK";
            break;

        case MYSQL_REFRESH:
            dataState = "RESPONSE_OK";
            break;

        case MYSQL_SHUTDOWN:
            dataState = "RESPONSE_OK";
            break;

        case MYSQL_SET_OPTION:
            payload = data.readUInt8(offset);
            dataState = "RESPONSE_OK";
            break;

        case MYSQL_STMT_FETCH:
            payload = data.readUInt8(offset);
            payload += ", ";
            payload += data.readUInt8(offset);
            dataState = "RESPONSE_TABULAR";
            break;

        case MYSQL_STMT_SEND_LONG_DATA:
            payload = "Statement id: " + data.readUInt16LE(offset);
            offset += 4;
            payload += " Statement data: " + decode(data.slice(offset));
            dataState = "REQUEST";
            break;

        case MYSQL_STMT_EXECUTE:
            payload = "Statement id: " + data.readUInt16LE(offset);
            offset += 4;
            payload += " Statement data: " + decode(data.slice(offset));
            dataState = "RESPONSE_TABULAR";
            break;

        case MYSQL_BINLOG_DUMP:
            payload += "Binlog position: " + data.readUInt16LE(offset);
            offset += 4;
            payload += " flags: " + data.readUInt8BE(offset);
            offset += 2;
            payload += " binlog server id: " + data.readUInt16LE(offset);
            offset += 4;
            /* binlog file name ? */
            payload += " binlog file name: " + decode(data.slice(offset));
            dataState = "REQUEST";
            break;

        case MYSQL_TABLE_DUMP:
        case MYSQL_CONNECT_OUT:
        case MYSQL_REGISTER_SLAVE:
            payload = decode(data.slice(offset));
            dataState = "REQUEST";
            break;

        default:
            payload += "opCode: " + opCode + " - " + decode(data.slice(offset));
            dataState = "UNDEFINED";
    }
    console.log("request: " + mysql_commands[opCode] + " - \"" + payload + "\" expecting response " + dataState);
}

function outputRecvData(session, data) {
    var payload = decode(data),
        responseCode = data.readUInt8(4);
    console.log("responseCode: " + responseCode);
    console.log("payload.length: " + payload.length);



    //console.log("recieved: " + payload);
}

function decodeResultHeader(buf, offset)
{
    gint fle;
    guint64 num_fields, extra;

    col_append_str(pinfo->cinfo, COL_INFO, " TABULAR" );

    fle = tvb_get_fle(tvb, offset, &num_fields, NULL);
    proto_tree_add_uint64(tree, hf_mysql_num_fields, tvb, offset, fle, num_fields);
    offset += fle;

    if (tvb_reported_length_remaining(tvb, offset)) {
        fle = tvb_get_fle(tvb, offset, &extra, NULL);
        proto_tree_add_uint64(tree, hf_mysql_extra, tvb, offset, fle, extra);
        offset += fle;
    }

    if (num_fields) {
        conn_data->state = FIELD_PACKET;
    } else {
        conn_data->state = ROW_PACKET;
    }

    return offset;
}

function decode(buf) {
    var ret = "";
    for (var value of buf.values()) {
        if (value < 32 || value > 126) {
            ret += "[" + int8_to_hex[value] + "]";
        } else {
            ret += String.fromCharCode(value);
        }
    }
    return ret;
}

function getBufferRemaining(buff, offset) {
    return buf.values().length - offset;
}
