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

#ifndef _KINETIC_ALLOCATOR_H
#define _KINETIC_ALLOCATOR_H
#include "kinetic_types_internal.h"
#include "list.h"
typedef struct _KineticPDUItem {
		struct list_node		list;
		KineticPDU				PDU;
}KineticPDUItem;

KineticPDU* KineticAllocator_NewPDU(KineticConnection* const connection);
void KineticAllocator_FreePDU(KineticPDU* pdu, KineticConnection* const connection);
void KineticAllocator_FreeAllPDUs(KineticConnection* const connection);
bool KineticAllocator_ValidateAllMemoryFreed(KineticConnection* const connection);

#endif // _KINETIC_ALLOCATOR
