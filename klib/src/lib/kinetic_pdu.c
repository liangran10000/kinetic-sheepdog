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

#include "kinetic_pdu.h"
#include "kinetic_nbo.h"
#include "kinetic_connection.h"
#include "kinetic_socket.h"
#include "kinetic_hmac.h"
#include "kinetic_logger.h"
#include "kinetic_proto.h"

void KineticPDU_HeaderInit(KineticPDUHeader *header)
{
	header->versionPrefix = 'F';
}
void KineticPDU_Init(KineticPDU* const pdu,
                     KineticConnection* const connection)
{
		assert(pdu != NULL && connection != NULL);
		/* FIXME remove memset to improve performance */
		memset(pdu, 0x00, sizeof(*pdu));
		pdu->connection = connection;
		KineticPDU_HeaderInit(&pdu->header);
		KineticPDU_HeaderInit(&pdu->headerNBO);
		KineticMessage_HeaderInit(&(pdu->protoData.message.header), connection);

}

void KineticPDU_AttachEntry(KineticPDU* const pdu, KineticEntry* const entry)
{
    assert(pdu != NULL);
    assert(entry != NULL);
    pdu->value = entry->value;
}

KineticStatus KineticPDU_Send(KineticPDU* request)
{
    assert(request != NULL);
    assert(request->connection != NULL);
    LOGF("Attempting to send PDU via fd=%d", request->connection->socket);

    KineticStatus status = KINETIC_STATUS_INVALID;

    // Populate the HMAC for the protobuf
    KineticHMAC_Init(
        &request->hmac,
        KINETIC_PROTO_SECURITY_ACL_HMACALGORITHM_HmacSHA1);
    KineticHMAC_Populate(
        &request->hmac,
        &request->protoData.message.proto,
        request->connection->session.hmacKey);

    // Configure PDU header length fields
    request->header.versionPrefix = 'F';
    request->header.protobufLength =
        KineticProto__get_packed_size(&request->protoData.message.proto);
    request->header.valueLength =
        (request->value.array.data == NULL) ? 0 : request->value.bytesUsed;
    KineticLogger_LogHeader(&request->header);

    // Create NBO copy of header for sending
    request->headerNBO.versionPrefix = 'F';
    request->headerNBO.protobufLength =
        KineticNBO_FromHostU32(request->header.protobufLength);
    request->headerNBO.valueLength =
        KineticNBO_FromHostU32(request->header.valueLength);

    // Pack and send the PDU header
    ByteBuffer hdr = ByteBuffer_Create(&request->headerNBO, sizeof(KineticPDUHeader));
    hdr.bytesUsed = hdr.array.len;
    status = KineticSocket_Write(request->connection->socket, &hdr);
    if (status != KINETIC_STATUS_SUCCESS) {
        LOG("Failed to send PDU header!");
        return status;
    }

    // Send the protobuf message
    LOG("Sending PDU Protobuf:");
    KineticLogger_LogProtobuf(&request->protoData.message.proto);
    status = KineticSocket_WriteProtobuf(
        request->connection->socket, request);
    if (status != KINETIC_STATUS_SUCCESS) {
        LOG("Failed to send PDU protobuf message!");
        return status;
    }

    // Send the value/payload, if specified
    ByteBuffer* value = &request->value;
    if ((value->array.data != NULL) && (value->array.len > 0) && (value->bytesUsed > 0)) {
        status = KineticSocket_Write(request->connection->socket, value);
        if (status != KINETIC_STATUS_SUCCESS) {
            LOG("Failed to send PDU value payload!");
            return status;
        }
    }

    return KINETIC_STATUS_SUCCESS;
}

KineticStatus KineticPDU_Receive(KineticPDU* const response)
{
    assert(response != NULL);
    const int fd = response->connection->socket;
    assert(fd >= 0);
    LOGF("Attempting to receive PDU via fd=%d", fd);

    KineticStatus status;

    // Receive the PDU header
    ByteBuffer rawHeader =
        ByteBuffer_Create(&response->headerNBO, sizeof(KineticPDUHeader));
    status = KineticSocket_Read(fd, &rawHeader, rawHeader.array.len);
    if (status != KINETIC_STATUS_SUCCESS) {
        LOG("Failed to receive PDU header!");
        return status;
    }
    else {
        LOG("PDU header received successfully");
        KineticPDUHeader* headerNBO = &response->headerNBO;
        response->header = (KineticPDUHeader) {
            .versionPrefix = headerNBO->versionPrefix,
             .protobufLength = KineticNBO_ToHostU32(headerNBO->protobufLength),
              .valueLength = KineticNBO_ToHostU32(headerNBO->valueLength),
        };
        KineticLogger_LogHeader(&response->header);
    }

    // Receive the protobuf message
    status = KineticSocket_ReadProtobuf(fd, response);
    if (status != KINETIC_STATUS_SUCCESS) {
        LOG("Failed to receive PDU protobuf message!");
        return status;
    }
    else {
        LOG("Received PDU protobuf");
        KineticLogger_LogProtobuf(response->proto);
    }

    // Validate the HMAC for the recevied protobuf message
    if (!KineticHMAC_Validate(response->proto,
                              response->connection->session.hmacKey)) {
        LOG("Received PDU protobuf message has invalid HMAC!");
        KineticMessage* msg = &response->protoData.message;
        msg->proto.command = &msg->command;
        msg->command.status = &msg->status;
        msg->status.code = KINETIC_PROTO_STATUS_STATUS_CODE_DATA_ERROR;
        return KINETIC_STATUS_DATA_ERROR;
    }
    else {
        LOG("Received protobuf HMAC validation succeeded");
    }

    // Receive the value payload, if specified
    if (response->header.valueLength > 0) {
        assert(response->value.array.data != NULL);
        LOGF("Receiving value payload (%lld bytes)...",
             (long long)response->header.valueLength);

        response->value.bytesUsed = 0;
        status = KineticSocket_Read(fd,
            &response->value, response->header.valueLength);
        if (status != KINETIC_STATUS_SUCCESS) {
            LOG("Failed to receive PDU value payload!");
            return status;
        }
        else {
            LOG("Received value payload successfully");
        }

        //KineticLogger_LogByteBuffer("Value Buffer", response->value);
    }

    // Update connectionID to match value returned from device, if provided
    KineticProto_Command* cmd = response->proto->command;
    if ((cmd != NULL) && (cmd->header != NULL) && (cmd->header->has_connectionID)) {
        response->connection->connectionID = cmd->header->connectionID;
    }

    return KineticPDU_GetStatus(response);
}

KineticStatus KineticPDU_GetStatus(KineticPDU* pdu)
{
    KineticStatus status = KINETIC_STATUS_INVALID;

    if (pdu != NULL &&
        pdu->proto != NULL &&
        pdu->proto->command != NULL &&
        pdu->proto->command->status != NULL &&
        pdu->proto->command->status->has_code != false) {

        status = KineticProtoStatusCode_to_KineticStatus(
            pdu->proto->command->status->code);
    }

    return status;
}

KineticProto_KeyValue* KineticPDU_GetKeyValue(KineticPDU* pdu)
{
    KineticProto_KeyValue* keyValue = NULL;

    if (pdu != NULL &&
        pdu->proto != NULL &&
        pdu->proto->command != NULL &&
        pdu->proto->command->body != NULL) {

        keyValue = pdu->proto->command->body->keyValue;
    }
    return keyValue;
}
/*FIXME */
KineticStatus KineticPDU_GetKeyRange(KineticPDU* pdu, KineticRange *range)
{
		ByteBuffer *dest = range->keys;
		if (pdu && pdu->proto && pdu->proto->command && pdu->proto->command->body &&
				pdu->proto->command->body->range) {
				int available  = (int)pdu->proto->command->body->range->n_key;
    			ProtobufCBinaryData* src =  pdu->proto->command->body->range->key;
				for (range->returned = 0;
					range->returned < range->maxRequested && range->returned < available;  src++, dest++) {
					if (dest->array.len < src->len) return KINETIC_STATUS_BUFFER_OVERRUN;
					dest->bytesUsed = src->len;
					memcpy(dest->array.data, src->data, src->len);
					range->returned++;
				}
				return KINETIC_STATUS_SUCCESS;
		}
		return KINETIC_STATUS_INTERNAL_ERROR;
}

void  KineticPDU_InitWithMessage(KineticPDU * const pdu, KineticConnection* const connection,
    				KineticProto_MessageType msg_type)
{
		KineticPDU_Init(pdu, connection);
		pdu->proto = &(pdu->protoData.message.proto);
		KineticMessage_Init(&(pdu->protoData.message), msg_type);
		pdu->proto->command = &(pdu->protoData.message.command);
		pdu->proto->command->header = &(pdu->protoData.message.header);
		KineticMessage_HeaderInit(&(pdu->protoData.message.header), connection);


}
