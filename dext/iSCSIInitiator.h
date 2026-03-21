/*
 * iSCSIInitiator.h - DriverKit system extension for iSCSI SCSI interface
 *
 * This extension implements IOUserSCSIParallelInterfaceController to expose
 * iSCSI logical units as SCSI devices to macOS.  The actual iSCSI protocol
 * (TCP sockets, login, PDU handling) lives in the iscsid user-space daemon;
 * this extension only handles the SCSI ↔ iSCSI PDU translation layer.
 *
 * Communication with iscsid:
 *   The extension opens an IOUserClient channel.  iscsid passes SCSI
 *   commands to the extension, which translates them to iSCSI SCSI Command
 *   PDUs and returns responses.  The actual TCP I/O stays in iscsid.
 *
 * Required entitlements (Info.plist):
 *   com.apple.developer.driverkit                          = true
 *   com.apple.developer.driverkit.family.scsicontroller   = true
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <DriverKit/DriverKit.h>
#include <SCSIControllerDriverKit/IOUserSCSIParallelInterfaceController.h>

class iSCSIInitiator : public IOUserSCSIParallelInterfaceController
{
public:
    /*
     * Driver lifecycle – called by DriverKit when the driver is matched.
     */
    virtual kern_return_t   Start(IOService *provider) override;
    virtual kern_return_t   Stop(IOService *provider)  override;
    virtual void            free()                     override;

    /*
     * IOUserSCSIParallelInterfaceController overrides.
     */

    /* Return adapter capabilities to the SCSI parallel family. */
    virtual bool            InitializeController() override;
    virtual void            TerminateController()  override;

    /* Start I/O: translate a SCSI command to an iSCSI Command PDU. */
    virtual void            StartController(IOOperationID opID) override;

    /* Report the maximum number of targets this controller can address. */
    virtual uint32_t        ReportHBAHighestLogicalUnitNumber() override;
    virtual uint32_t        ReportMaximumTaskCount()            override;
    virtual uint32_t        ReportInitiatorIdentifier()         override;
    virtual uint32_t        ReportHighestSupportedDeviceLUN()   override;

    /* Data buffer mapping */
    virtual uint32_t        ReportIOSASupportedEncoding() override;
    virtual bool            DoesHBAPerformDeviceManagement()    override;

private:
    /* IOUserClient connection to iscsid for command passing */
    IOUserClient   *fUserClient;

    /* Number of SCSI targets currently registered */
    uint32_t        fTargetCount;

    /*
     * iSCSI session handle (opaque token passed to/from iscsid).
     * In practice this would be a mach_port_t or shared memory handle.
     */
    uint64_t        fSessionHandle;

    /* Internal helpers */
    kern_return_t   ConnectToDaemon();
    void            DisconnectFromDaemon();
};
