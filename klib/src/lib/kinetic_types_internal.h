/*
* kinetic-c
* Copyright (C) 2014 Seagate Technology.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*
*/

#ifndef _KINETIC_TYPES_INTERNAL_H
#define _KINETIC_TYPES_INTERNAL_H
#include <netinet/in.h>
#include <ifaddrs.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include "kinetic_list.h"
#include "kinetic_types.h"
#include "kinetic_proto.h"
#define KINETIC_SESSIONS_MAX (6)
#define KINETIC_PDUS_PER_SESSION_DEFAULT (2)
#define KINETIC_PDUS_PER_SESSION_MAX (10)
#define KINETIC_SOCKET_DESCRIPTOR_INVALID (-1)
#define EPOLL_EVENT_MAX						(2)
#define EPOLL_WAIT							(1000)

// Ensure __func__ is defined (for debugging)
#if !defined __func__
#define __func__ __FUNCTION__
#endif

// Expose normally private data for test builds to allow inspection
#ifdef TEST
#define STATIC
#else
#define STATIC static
#endif
typedef struct _KineticPDU KineticPDU;

// Kinetic Device Client Connection
typedef struct _KineticConnection {
    bool    					connected;       // state of connection
    int     					socket;          // socket file descriptor
    int64_t 					connectionID;    // initialized to seconds since epoch
    int64_t 					sequence;        // increments for each request in a session
    KineticSession 				session;  // session configuration
	pthread_mutex_t 			mutex;
	struct kinetic_list_head 	free_op_list;
	struct kinetic_list_head	pending_op_list;
	struct kinetic_list_head 	inprogress_op_list;
	pthread_mutex_t				pending_op_mutex;
	pthread_mutex_t				inprogress_op_mutex;
	pthread_t					send_thread;
	pthread_t					rcv_thread;
	int							send_epoll;
	int							rcv_epoll;
	int							send_fd;
	KineticPDU					*rawPDU;
} KineticConnection;



// Kinetic Message HMAC
typedef struct _KineticHMAC {
    KineticProto_Security_ACL_HMACAlgorithm algorithm;
    uint32_t len;
    uint8_t data[KINETIC_HMAC_MAX_LEN];
} KineticHMAC;


// Kinetic Device Message Request
typedef struct _KineticMessage {
    // Kinetic Protocol Buffer Elements
    KineticProto                proto;
    KineticProto_Command        command;
    KineticProto_Header         header;
    KineticProto_Body           body;
    KineticProto_Status         status;
    KineticProto_Security       security;
    KineticProto_Security_ACL   acl;
    KineticProto_KeyValue       keyValue;
    KineticProto_Range       	range;
    uint8_t                     hmacData[KINETIC_HMAC_MAX_LEN];
} KineticMessage;

// Kinetic PDU Header
#define PDU_HEADER_LEN              (1 + (2 * sizeof(int32_t)))
#define PDU_PROTO_MAX_LEN           (1024 * 1024)
#define PDU_PROTO_MAX_UNPACKED_LEN  (PDU_PROTO_MAX_LEN * 2)
#define PDU_MAX_LEN                 (PDU_HEADER_LEN + \
                                    PDU_PROTO_MAX_LEN + PDU_VALUE_MAX_LEN)
typedef struct __attribute__((__packed__)) _KineticPDUHeader {
    uint8_t     versionPrefix;
    uint32_t    protobufLength;
    uint32_t    valueLength;
} KineticPDUHeader;
/*
#define KINETIC_PDU_HEADER_INIT \
    (KineticPDUHeader) {.versionPrefix = 'F'}

*/
// Kinetic PDU
struct _KineticPDU {
    // Binary PDU header
    KineticPDUHeader header;    // Header struct in native byte order must be first member
    KineticPDUHeader headerNBO; // Header struct in network-byte-order

    // Message associated with this PDU instance
    union {
        KineticProto protoBase;

        // Pre-structured message w/command
        KineticMessage message;

        // Pad protobuf to max size for extraction of arbitrary packed proto
        uint8_t buffer[PDU_PROTO_MAX_UNPACKED_LEN];
    } protoData;        // Proto will always be first
    KineticProto* proto;
    bool protobufDynamicallyExtracted;
    // bool rawProtoEnabled;
    uint8_t protobufRaw[PDU_PROTO_MAX_LEN];

    // Object meta-data to be used/populated if provided and pertinent to the operation
    ByteBuffer value;

    // Embedded HMAC instance
    KineticHMAC hmac;

    // Exchange associated with this PDU instance (info gets embedded in protobuf message)
    KineticConnection* connection;
};

typedef  void (*Kinetic_Callback)(KineticStatus, void *);

// Kinetic Operation
typedef struct _KineticOperation {
	struct kinetic_list_node list; /* must be the first member */
    KineticConnection* 		connection;  // Associated KineticSession
    KineticPDU 				request;
    KineticPDU 				response;
    pthread_cond_t			callback_cond;
    pthread_mutex_t			callback_mutex;
    Kinetic_Callback		callback_internal;
    KineticStatus 			status;

} KineticOperation;
#define KINETIC_OPERATION_INIT(_op, _con) \
    assert((_op) != NULL); \
    assert((_con) != NULL); \
    *(_op) = (KineticOperation) { \
        .connection = (_con), \
    }


KineticProto_Algorithm KineticProto_Algorithm_from_KineticAlgorithm(
    KineticAlgorithm kinteicAlgorithm);
KineticAlgorithm KineticAlgorithm_from_KineticProto_Algorithm(
    KineticProto_Algorithm protoAlgorithm);

KineticProto_Synchronization KineticProto_Synchronization_from_KineticSynchronization(
    KineticSynchronization sync_mode);
KineticSynchronization KineticSynchronization_from_KineticProto_Synchronization(
    KineticProto_Synchronization sync_mode);

KineticStatus KineticProtoStatusCode_to_KineticStatus(
    KineticProto_Status_StatusCode protoStatus);
ByteArray ProtobufCBinaryData_to_ByteArray(ProtobufCBinaryData protoData);
bool Copy_ProtobufCBinaryData_to_ByteArray(ByteArray dest, ProtobufCBinaryData src);
bool Copy_ProtobufCBinaryData_to_ByteBuffer(ByteBuffer dest, ProtobufCBinaryData src);
bool Copy_KineticProto_KeyValue_to_KineticEntry(KineticProto_KeyValue* keyValue, KineticEntry* entry);

#endif // _KINETIC_TYPES_INTERNAL_H
