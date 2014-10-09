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

#include "kinetic_allocator.h"
#include "kinetic_logger.h"
#include <stdlib.h>
#include "kinetic_connection.h"
STATIC KINETIC_LIST_HEAD (PDUList); //= {.start = NULL, .last = NULL};
#define PDU2LIST(pdu) ( ((uint8_t *)(pdu)) - sizeof( struct kinetic_list_node))

KineticPDU* KineticAllocator_NewPDU(KineticConnection *connection)
{
   KineticPDUItem * item = malloc(sizeof(KineticPDUItem));
   assert(item);
   item->PDU.proto = NULL;
	KineticConnection_Lock(connection);
   kinetic_list_add(&item->kinetic_list, &PDUList);
   KineticConnection_Unlock(connection);
   return &item->PDU;

}

void KineticAllocator_FreePDU(KineticPDU* pdu, KineticConnection *connection)
{
	assert(pdu);
    if ((pdu->proto != NULL) && pdu->protobufDynamicallyExtracted) {
        LOG("Freeing dynamically allocated protobuf");
        KineticProto__free_unpacked(pdu->proto, NULL);
    };
	KineticPDUItem *item = (KineticPDUItem *)PDU2LIST(pdu);
	KineticConnection_Lock(connection);
	kinetic_list_del( &item->kinetic_list);
	KineticConnection_Unlock(connection);
	free(item);
}

void KineticAllocator_FreeAllPDUs(KineticConnection *connection)
{
	KineticPDUItem *item;
	KineticConnection_Lock(connection);
	while (!kinetic_list_empty(&connection->pdus)) {
    	item = (KineticPDUItem *)(connection->pdus.n.next);
	 	KineticPDU *pdu = &item->PDU; 
        if ( pdu->proto != NULL && pdu->protobufDynamicallyExtracted) {
               KineticProto__free_unpacked(pdu->proto, NULL);
         }
	  	kinetic_list_del(&item->kinetic_list);
		free(item);
	}
	KineticConnection_Unlock(connection);
}

bool KineticAllocator_ValidateAllMemoryFreed(KineticConnection *connection)
{
	bool rc;
	KineticConnection_Lock(connection);
    rc = kinetic_list_empty(&connection->pdus);
	KineticConnection_Unlock(connection);
	return rc;
}
