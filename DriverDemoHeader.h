#pragma once

#define DriverDemoType 0x8005

#define IOCTL_BUFFERED_METHOD CTL_CODE(DriverDemoType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DIRECT_METHOD CTL_CODE(DriverDemoType, 0x802, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_METHOD_NEITHER CTL_CODE(DriverDemoType, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
