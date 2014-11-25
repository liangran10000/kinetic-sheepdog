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

#ifndef _KINETIC_PDU_H
#define _KINETIC_PDU_H

#include "kinetic_types_internal.h"
#include "kinetic_proto.h"
void KineticPDU_Init(KineticPDU* const pdu, KineticConnection* const connection);
void KineticPDU_AttachEntry(KineticPDU* const pdu, KineticEntry* const entry);
KineticStatus KineticPDU_Receive(KineticConnection* const connection);
KineticStatus KineticPDU_Send(KineticPDU* request);
KineticStatus KineticPDU_GetStatus(KineticPDU* pdu);
KineticProto_KeyValue* KineticPDU_GetKeyValue(KineticPDU* pdu);
KineticStatus KineticPDU_GetKeyRange(KineticPDU* pdu, KineticRange *range);
void KineticPDU_HeaderInit(KineticPDUHeader *header);
void KineticPDU_HeaderInit(KineticPDUHeader *header);
void  KineticPDU_InitWithMessage(KineticPDU * const pdu, KineticConnection* const connection,
    				KineticProto_MessageType msg_type);

#endif // _KINETIC_PDU_H
