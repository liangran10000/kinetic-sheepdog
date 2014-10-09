/*
* kinetic-c-client
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

#ifndef _SYSTEM_TEST_FIXTURE
#define _SYSTEM_TEST_FIXTURE

#include "kinetic_types.h"
#include "kinetic_logger.h"

typedef struct _SystemTestFixture {
    KineticSession config;
    KineticSessionHandle handle;
    bool testIgnored;
    bool connected;
    int64_t expectedSequence;
} SystemTestFixture;

void SystemTestSetup(SystemTestFixture* fixture);
void SystemTestTearDown(SystemTestFixture* fixture);
void SystemTestSuiteTearDown(SystemTestFixture* fixture);

#define SYSTEM_TEST_SUITE_TEARDOWN(_fixture) \
void test_Suite_TearDown(void) \
{ \
    LOG("BLARF!!!!!!!!!!!!!!!"); \
    if ((_fixture)->handle != KINETIC_HANDLE_INVALID && (_fixture)->connected) { \
        KineticClient_Disconnect(&(_fixture)->handle); } \
    (_fixture)->connected = false; \
}

#endif // _SYSTEM_TEST_FIXTURE
