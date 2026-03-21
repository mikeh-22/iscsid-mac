/*
 * iSCSIInitiator.cpp - DriverKit SCSI controller for iSCSI
 *
 * This file is a buildable stub demonstrating the DriverKit integration
 * architecture.  Full implementation requires:
 *   1. Apple Developer Program membership
 *   2. com.apple.developer.driverkit.family.scsicontroller entitlement
 *   3. Xcode project with system extension target
 *
 * See docs/dext-architecture.md for the full integration design.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "iSCSIInitiator.h"
#include <os/log.h>

/* DriverKit class registration */
#define super IOUserSCSIParallelInterfaceController
OSDefineMetaClassAndStructors(iSCSIInitiator, IOUserSCSIParallelInterfaceController)

static os_log_t sLog = OS_LOG_DEFAULT;

/* -----------------------------------------------------------------------
 * Driver lifecycle
 * ----------------------------------------------------------------------- */

kern_return_t iSCSIInitiator::Start(IOService *provider)
{
    kern_return_t ret;

    os_log(sLog, "iSCSIInitiator: Start");

    ret = super::Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        os_log_error(sLog, "iSCSIInitiator: super::Start failed 0x%x", ret);
        return ret;
    }

    ret = ConnectToDaemon();
    if (ret != kIOReturnSuccess) {
        os_log_error(sLog, "iSCSIInitiator: ConnectToDaemon failed 0x%x", ret);
        /* Non-fatal: commands will fail until daemon connects */
    }

    RegisterService();
    return kIOReturnSuccess;
}

kern_return_t iSCSIInitiator::Stop(IOService *provider)
{
    os_log(sLog, "iSCSIInitiator: Stop");
    DisconnectFromDaemon();
    return super::Stop(provider, SUPERDISPATCH);
}

void iSCSIInitiator::free()
{
    OSSafeReleaseNULL(fUserClient);
    super::free();
}

/* -----------------------------------------------------------------------
 * IOUserSCSIParallelInterfaceController implementation
 * ----------------------------------------------------------------------- */

bool iSCSIInitiator::InitializeController()
{
    os_log(sLog, "iSCSIInitiator: InitializeController");
    fTargetCount = 0;
    return true;
}

void iSCSIInitiator::TerminateController()
{
    os_log(sLog, "iSCSIInitiator: TerminateController");
}

void iSCSIInitiator::StartController(IOOperationID opID)
{
    /*
     * This is called when the SCSI parallel family wants to execute a command.
     *
     * Full implementation:
     *   1. Get SCSI command from opID (using GetSCSITaskIdentifier etc.)
     *   2. Serialise it into an iSCSI SCSI Command PDU
     *   3. Send to iscsid via the IOUserClient channel (Mach RPC / shared mem)
     *   4. iscsid sends it over TCP, gets a SCSI Response PDU
     *   5. iscsid notifies the extension via IOUserClient
     *   6. Extension calls CompleteParallelTask() with the result
     *
     * The socket I/O MUST remain in iscsid (DriverKit has no socket API).
     */
    os_log_debug(sLog, "iSCSIInitiator: StartController opID=%llu",
                 (unsigned long long)opID);

    /* Stub: fail the command until daemon integration is complete */
    CompleteParallelTask(opID, kSCSITaskStatus_TaskTimeoutOccurred,
                         kSCSIServiceResponse_TASK_COMPLETE);
}

uint32_t iSCSIInitiator::ReportHBAHighestLogicalUnitNumber()
{
    return 255;   /* iSCSI supports up to 16384 LUNs; report 255 for safety */
}

uint32_t iSCSIInitiator::ReportMaximumTaskCount()
{
    return 128;
}

uint32_t iSCSIInitiator::ReportInitiatorIdentifier()
{
    return 7;     /* Convention: SCSI ID 7 for initiator */
}

uint32_t iSCSIInitiator::ReportHighestSupportedDeviceLUN()
{
    return 255;
}

uint32_t iSCSIInitiator::ReportIOSASupportedEncoding()
{
    return 0;
}

bool iSCSIInitiator::DoesHBAPerformDeviceManagement()
{
    /*
     * Return true: we manage target registration ourselves.
     * When a new iSCSI session comes up, iscsid notifies the extension,
     * which calls CreateTargetForID() to register the target with the
     * SCSI parallel family.
     */
    return true;
}

/* -----------------------------------------------------------------------
 * Daemon connection
 * ----------------------------------------------------------------------- */

kern_return_t iSCSIInitiator::ConnectToDaemon()
{
    /*
     * Open an IOUserClient channel to iscsid.
     *
     * In a full implementation this uses IOService::CopyClientWithType()
     * or a Mach port registered by iscsid via IOUserClientMethodDispatch.
     *
     * The channel carries:
     *   - SCSI command descriptors (from extension to daemon)
     *   - SCSI completion descriptors (from daemon to extension)
     *   - Target add/remove notifications
     */
    os_log(sLog, "iSCSIInitiator: ConnectToDaemon (stub)");
    fSessionHandle = 0;
    return kIOReturnSuccess;
}

void iSCSIInitiator::DisconnectFromDaemon()
{
    os_log(sLog, "iSCSIInitiator: DisconnectFromDaemon");
    fSessionHandle = 0;
}
