#include <ntddk.h>
#include <stdio.h>
#include "DriverDemoHeader.h"

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP irp);
VOID UnloadRoutine(PDRIVER_OBJECT DriverObject);

PVOID AllocatedPoolMemoryBuffered;
PVOID AllocatedPoolMemoryDirect;

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceControlHandler(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	_IO_STACK_LOCATION* StackLocation = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_SUCCESS;
	char message[512] = {0};
	ULONG information = 0;
	ULONG InputBufferLength = StackLocation->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputBufferLength = StackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_BUFFERED_METHOD:
	{
		/*
		This IOCTL demonstrates the Buffered I/O buffering method
		The IOCTL will receive an input buffer that will hold value which is a number of bytes of kernel paged-pool memory that will
		be allocated through ExAllocatePool2()
		*/
		KdPrint(("[+] IOCTL_BUFFERED_METHOD has been invoked!!\n"));
		auto InputBuffer = (ULONG*)irp->AssociatedIrp.SystemBuffer; // Buffered I/O input Buffer that holds the number of bytes to allocate
		auto OutputBuffer = (CHAR*)irp->AssociatedIrp.SystemBuffer; // Buffered I/O output buffer that will return a sucess message after execution.
		if (OutputBufferLength <= 0 || InputBufferLength < sizeof(ULONG))
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		
		ULONG NumberOfBytes = (ULONG)*InputBuffer;
;		KdPrint(("[*] DemoDriver::DeviceControlHandler: Number of bytes that's going to be allocated: %d\n", NumberOfBytes));

		AllocatedPoolMemoryBuffered = ExAllocatePool2(POOL_FLAG_PAGED, NumberOfBytes, 'omeD');
		KdPrint(("[+] DemoDriver::DeviceControlHandler: Memory was successfully allocated at address: 0x%p\n", AllocatedPoolMemoryBuffered));
		sprintf(message, "IOCTL IOCTL_BUFFERED_METHOD (0x%x) was executed successfully!! allocated %d bytes at address: 0x%p\n", status, NumberOfBytes, AllocatedPoolMemoryBuffered);
		information = (ULONG)strlen(message) + 1;
		RtlCopyMemory(OutputBuffer, message, information);
		break;
	}

	case IOCTL_DIRECT_METHOD:
	{
		KdPrint(("[+] IOCTL_DIRECT_METHOD has been invoked!!\n"));
		if (OutputBufferLength <= 0 || InputBufferLength < sizeof(ULONG)) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		auto InputBuffer = (ULONG*)irp->AssociatedIrp.SystemBuffer;	//Input buffer is received in Buffered I/O method.
		auto OutputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority); //output buffer is in direct memory mapping through _MDL structure

		ULONG NumberOfBytes = (ULONG)*InputBuffer;
		KdPrint(("[*] DemoDriver::DeviceControlHandler: Number of bytes that's going to be allocated: %d\n", NumberOfBytes));

		AllocatedPoolMemoryDirect = ExAllocatePool2(POOL_FLAG_PAGED, NumberOfBytes, 'omeD'); // tag is 'Demo' reversed because of endianness
		KdPrint(("[+] DemoDriver::DeviceControlHandler: Memory was successfully allocated at address: 0x%p\n", AllocatedPoolMemoryDirect));

		sprintf(message, "IOCTL IOCTL_DIRECT_METHOD (0x%x) was executed successfully!! allocated %d bytes at address: 0x%p\n", status, NumberOfBytes, AllocatedPoolMemoryDirect);
		information = (ULONG)strlen(message) + 1;
		RtlCopyMemory(OutputBuffer, message, information);
		break;
	}

	case IOCTL_METHOD_NEITHER:
	{
		KdPrint(("No input and output is expected to be received here!"));
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = information;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

VOID UnloadRoutine(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING DeviceSymLink = RTL_CONSTANT_STRING(L"\\??\\DriverDemoDevice");
	PDEVICE_OBJECT DevObj = DriverObject->DeviceObject;

	IoDeleteDevice(DevObj);
	KdPrint(("[+] DriverDemo::UnloadRoutine: Device deleted successfully!!\n"));

	IoDeleteSymbolicLink(&DeviceSymLink);
	KdPrint(("[+] DriverDemo::UnloadRoutine: Symlink deleted successfully!!\n"));

	if (AllocatedPoolMemoryDirect)
	{
		KdPrint(("[+] DriverDemo::UnloadRoutine: Allocated Pool memory from Direct at address 0x%p was freed successfully!\n", AllocatedPoolMemoryDirect));
		ExFreePool(AllocatedPoolMemoryDirect);
	}

	if (AllocatedPoolMemoryBuffered)
	{
		ExFreePool(AllocatedPoolMemoryBuffered);
		KdPrint(("[+] DriverDemo::UnloadRoutine: Allocated Pool memory from Buffered at address 0x%p was freed successfully!\n", AllocatedPoolMemoryBuffered));
	}

	KdPrint(("[+] DriverDemo::UnloadRoutine: Unload routine was completed successfully!\n"));
}

extern "C" 
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\DriverDemoDevice");
	UNICODE_STRING DeviceSymLink = RTL_CONSTANT_STRING(L"\\??\\DriverDemoDevice");
	PDEVICE_OBJECT DevObj;

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DevObj);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[-] DriverDemo::DriverEntry: Couldn't create the device (0x%x)\n", status));
		return status;
	}

	KdPrint(("[+] DriverDemo::DriverEntry: Device %wZ created successfully!\n", &DeviceName));

	status = IoCreateSymbolicLink(&DeviceSymLink, &DeviceName);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[-] DriverDemo::DriverEntry: Couldn't create a Symbolic Link to the device (0x%x)\n", status));
		IoDeleteDevice(DevObj);		// Deletes the device and returns if symlink creation wasn't successful
		return status;
	}
	
	KdPrint(("[+] DriverDemo::DriverEntry: Device Symlink %wZ created successfully!\n", &DeviceSymLink));

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlHandler;
	DriverObject->DriverUnload = UnloadRoutine;

	return status;
}