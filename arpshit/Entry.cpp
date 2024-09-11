#include <ntifs.h>
#include <wdm.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <stdlib.h>


PDRIVER_DISPATCH g_original_nsi_control = 0; // save original driver object 


BOOLEAN IsKernelAddress(PVOID va) { 
	return (size_t)va >> (62);
}

#define IOCTL_NSI_GETALLPARAM 0x0012001B // ioctl call needed
#define NSI_GET_IP_NET_TABLE   (11) // paremeter used for arp table (so we dont hook other shit by accident)


void DebugPrint(_In_z_ _Printf_format_string_ const char* format, ...)
{
	char fullMessage[1024];
	va_list args;

	va_start(args, format);
	RtlStringCchVPrintfA(fullMessage, ARRAYSIZE(fullMessage), format, args);
	va_end(args);

	DbgPrintEx(0, 0, ("[MINIMALIST] %s"), fullMessage);
}

typedef struct _NSI_PARAMS {
	__int64 field_0;
	__int64 field_8;
	__int64 field_10;
	int Type;
	int field_1C;
	int field_20;
	int field_24;
	char field_42;
	__int64 AddrTable;
	int AddrEntrySize;
	int field_34;
	__int64 NeighborTable;
	int NeighborTableEntrySize;
	int field_44;
	__int64 StateTable;
	int StateTableEntrySize;
	int field_54;
	__int64 OwnerTable;
	int OwnerTableEntrySize;
	int field_64;
	int Count;
	int field_6C;
} NSI_PARAMS, * PNSI_PARAMS;


extern "C"
{
	NTSTATUS ObReferenceObjectByName(
		PUNICODE_STRING objectName,
		ULONG attributes,
		PACCESS_STATE accessState,
		ACCESS_MASK desiredAccess,
		POBJECT_TYPE objectType,
		KPROCESSOR_MODE accessMode,
		PVOID parseContext, PVOID* object);

	extern POBJECT_TYPE* IoDriverObjectType;
}


NTSTATUS NsiControl(PDEVICE_OBJECT device, PIRP irp) {

	if (g_original_nsi_control &&
		device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]) {
		if (IsKernelAddress(irp)) { //prevents bsod
			PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
			if (!MmIsAddressValid(ioc))
				return g_original_nsi_control(device, irp);

			switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
			case IOCTL_NSI_GETALLPARAM: {
				DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
				NTSTATUS ret = g_original_nsi_control(device, irp);
				PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
				if (MmIsAddressValid(params)
					&& ((NSI_GET_IP_NET_TABLE == params->Type))
					) {
					memset(irp->UserBuffer, 0, length);
					DebugPrint("Hooked ARP!\n");
					return STATUS_ACCESS_DENIED;
				}
				return ret;
			}
			}
		}
		return g_original_nsi_control(device, irp);
	}
	return STATUS_SUCCESS;
}


PDRIVER_DISPATCH add_irp_hook(const wchar_t* name, PDRIVER_DISPATCH new_func)
{
	UNICODE_STRING str;
	RtlInitUnicodeString(&str, name);

	PDRIVER_OBJECT driver_object = 0;
	NTSTATUS status = ObReferenceObjectByName(&str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (void**)&driver_object);
	if (!NT_SUCCESS(status)) return 0;

	PDRIVER_DISPATCH old_func = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = new_func;

	ObDereferenceObject(driver_object);
	DebugPrint("added hook!");
	return old_func;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING Driverregistry)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(Driverregistry);
	DebugPrint("HOOKING ARP!");
	g_original_nsi_control = add_irp_hook((L"\\Driver\\nsiproxy"), NsiControl);

	return STATUS_SUCCESS;
}