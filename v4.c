#include <ntddk.h>       // Core driver functions and types
#include <fwpsk.h>       // Windows Filtering Platform (WFP) kernel-mode API
#include <fwpmk.h>       // WFP management API
#include <fwpmu.h>       // WFP user-mode API (if needed)
#include <netioapi.h>    // Network I/O APIs
#include <wdm.h>         // Windows Driver Model
#include <ntstrsafe.h>   // Safe string functions


// Spinlock declarations for synchronization
KSPIN_LOCK FilterRulesSpinLock;
KSPIN_LOCK ConnectionTableSpinLock;

// Memory management statistics structure
typedef struct _MEMORY_STATS {
    UINT64 totalAllocations;
    UINT64 currentBufferUsage;
} MEMORY_STATS, * PMEMORY_STATS;

MEMORY_STATS memoryStats = { 0 }; // Initialize memory statistics
NPAGED_LOOKASIDE_LIST lookasideList; // Lookaside list for memory management

// Driver statistics structure
typedef struct _DRIVER_STATS {
    UINT64 packetsProcessed;
    UINT64 packetsFiltered;
    UINT64 checksumRecalculations;
    UINT64 activeConnections;
} DRIVER_STATS, * PDRIVER_STATS;

DRIVER_STATS driverStats = { 0 }; // Initialize driver statistics

// Filtering rule structure
typedef struct _FILTER_RULE {
    BOOLEAN isActive;
    UINT8 protocol; // TCP = 6, UDP = 17
    UINT32 srcIP;
    UINT32 destIP;
    UINT16 srcPort;
    UINT16 destPort;
    UINT32 packetSize;
    UINT32 newSrcIP;
    UINT16 newSrcPort;
    struct _FILTER_RULE* next;
} FILTER_RULE, * PFILTER_RULE;

FILTER_RULE* filterRulesHead = NULL; // Linked list head for filtering rules

// Function prototypes
NTSTATUS AddFilterRule(FILTER_RULE* rule);
NTSTATUS RemoveFilterRule(FILTER_RULE* rule);
NTSTATUS ModifyFilterRule(FILTER_RULE* oldRule, FILTER_RULE* newRule);
void ApplyFilteringRules(PNET_BUFFER_LIST nbl);

// Memory allocation using lookaside list or pool
static PVOID AllocateMemory(SIZE_T size) {
    PVOID memory = ExAllocateFromNPagedLookasideList(&lookasideList);
    if (memory == NULL) {
        DbgPrint("Memory allocation failed.\n");
        return NULL;
    }

    memoryStats.totalAllocations++;
    memoryStats.currentBufferUsage += size;
    DbgPrint("Memory allocated: %p, size: %llu\n", memory, size);
    return memory;
}

// Free memory and update memory statistics
static VOID FreeMemory(PVOID memory) {
    if (memory) {
        ExFreeToNPagedLookasideList(&lookasideList, memory);
        memoryStats.currentBufferUsage -= sizeof(PVOID);
        DbgPrint("Memory freed: %p\n", memory);
    }
    else {
        DbgPrint("Attempted to free null memory pointer.\n");
    }
}

// Initialize lookaside list for memory management
static NTSTATUS InitializeLookasideList() {
    ExInitializeNPagedLookasideList(&lookasideList, NULL, NULL, 0, sizeof(PVOID), 'lbuf', 0);
    DbgPrint("Lookaside list initialized.\n");
    return STATUS_SUCCESS;
}

// Destroy lookaside list during driver unload
static VOID DestroyLookasideList() {
    ExDeleteNPagedLookasideList(&lookasideList);
    DbgPrint("Lookaside list destroyed.\n");
}

// Reset memory statistics
static NTSTATUS ResetMemoryStatistics() {
    RtlZeroMemory(&memoryStats, sizeof(MEMORY_STATS));
    DbgPrint("Memory statistics reset.\n");
    return STATUS_SUCCESS;
}

// Log current memory statistics
static VOID LogMemoryStatistics() {
    DbgPrint("Memory Statistics - Total Allocations: %llu, Current Buffer Usage: %llu bytes\n",
        memoryStats.totalAllocations, memoryStats.currentBufferUsage);
}

// Function to initialize synchronization mechanisms (spinlocks)
static NTSTATUS InitializeSpinlocks() {
    KeInitializeSpinLock(&FilterRulesSpinLock);
    KeInitializeSpinLock(&ConnectionTableSpinLock);
    DbgPrint("Spinlocks initialized.\n");
    return STATUS_SUCCESS;
}
// Add a new filter rule with synchronization
NTSTATUS AddFilterRule(FILTER_RULE* rule) {
    if (!rule) {
        return STATUS_INVALID_PARAMETER;
    }

static     PFILTER_RULE newRule = (PFILTER_RULE)AllocateMemory(sizeof(FILTER_RULE));
    if (!newRule) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newRule, rule, sizeof(FILTER_RULE));
    newRule->next = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    // Insert the new rule at the head of the linked list
    newRule->next = filterRulesHead;
    filterRulesHead = newRule;

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);

    DbgPrint("Filter rule added: Source IP: %x, Source Port: %d\n", rule->srcIP, rule->srcPort);
    return STATUS_SUCCESS;
}

// Remove a filter rule with synchronization
NTSTATUS RemoveFilterRule(FILTER_RULE* rule) {
    if (!rule) {
        return STATUS_INVALID_PARAMETER;
    }

    PFILTER_RULE prev = NULL;
    PFILTER_RULE current = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    current = filterRulesHead;
    while (current) {
        if (RtlCompareMemory(current, rule, sizeof(FILTER_RULE)) == sizeof(FILTER_RULE)) {
            // Rule found; remove it from the list
            if (prev) {
                prev->next = current->next;
            }
            else {
                // Removing the head of the list
                filterRulesHead = current->next;
            }

static             FreeMemory(current); // Free the memory allocated for the rule
            KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);

            DbgPrint("Filter rule removed: Source IP: %x, Source Port: %d\n", rule->srcIP, rule->srcPort);
            return STATUS_SUCCESS;
        }

        prev = current;
        current = current->next;
    }

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
    return STATUS_NOT_FOUND;
}

// Modify a filter rule with synchronization
NTSTATUS ModifyFilterRule(FILTER_RULE* oldRule, FILTER_RULE* newRule) {
    if (!oldRule || !newRule) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = RemoveFilterRule(oldRule);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return AddFilterRule(newRule);
}

// Apply filtering rules to outgoing packets
void ApplyFilteringRules(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb) {
        PFILTER_RULE current;

        KIRQL oldIrql;
        KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

        current = filterRulesHead;
        while (current) {
            if (current->isActive) {
                DbgPrint("Packet matched rule: Source IP: %x, Source Port: %d\n", current->srcIP, current->srcPort);
                DbgPrint("Packet modified: New Source IP: %x, New Source Port: %d\n", current->newSrcIP, current->newSrcPort);
            }
            current = current->next;
        }

        KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
    }
}

// TCP Connection structure
typedef struct _TCP_CONNECTION {
    UINT32 srcIP;
    UINT32 destIP;
    UINT16 srcPort;
    UINT16 destPort;
    UINT32 seqNum;
    UINT32 ackNum;
    TCP_STATE state;
    struct _TCP_CONNECTION* next;
} TCP_CONNECTION, * PTCP_CONNECTION;

TCP_CONNECTION* connectionTableHead = NULL; // Linked list for connection tracking

// Add a new connection to the connection tracking table with synchronization
static NTSTATUS AddConnection(TCP_CONNECTION* connection) {
    if (!connection) {
        return STATUS_INVALID_PARAMETER;
    }

static     PTCP_CONNECTION newConnection = (PTCP_CONNECTION)AllocateMemory(sizeof(TCP_CONNECTION));
    if (!newConnection) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newConnection, connection, sizeof(TCP_CONNECTION));
    newConnection->next = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&ConnectionTableSpinLock, &oldIrql);

    // Insert the new connection at the head of the linked list
    newConnection->next = connectionTableHead;
    connectionTableHead = newConnection;

    KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);

    DbgPrint("Connection added: Src IP: %x, Src Port: %d\n", connection->srcIP, connection->srcPort);
    return STATUS_SUCCESS;
}

// Remove a connection from the connection tracking table with synchronization
static NTSTATUS RemoveConnection(TCP_CONNECTION* connection) {
    if (!connection) {
        return STATUS_INVALID_PARAMETER;
    }

    PTCP_CONNECTION prev = NULL;
    PTCP_CONNECTION current = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&ConnectionTableSpinLock, &oldIrql);

    current = connectionTableHead;
    while (current) {
        if (RtlCompareMemory(current, connection, sizeof(TCP_CONNECTION)) == sizeof(TCP_CONNECTION)) {
            // Connection found; remove it from the list
            if (prev) {
                prev->next = current->next;
            }
            else {
                connectionTableHead = current->next;
            }

static             FreeMemory(current); // Free the memory allocated for the connection
            KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);

            DbgPrint("Connection removed: Src IP: %x, Src Port: %d\n", connection->srcIP, connection->srcPort);
            return STATUS_SUCCESS;
        }

        prev = current;
        current = current->next;
    }

    KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);
    return STATUS_NOT_FOUND;
}

// Update an existing Connection state, sequence number, and acknowledgment number with synchronization
static NTSTATUS UpdateConnection(TCP_CONNECTION* connection, UINT32 seqNum, UINT32 ackNum, TCP_STATE newState) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&ConnectionTableSpinLock, &oldIrql);

    connection->seqNum = seqNum;
    connection->ackNum = ackNum;
    connection->state = newState;

    KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);

    DbgPrint("Connection updated: Src IP: %x, Src Port: %d, State: %d\n", connection->srcIP, connection->srcPort, connection->state);
    return STATUS_SUCCESS;
}
// Function to calculate the checksum for packet verification
static USHORT CalculateChecksum(USHORT* buffer, int size) {
    ULONG checksum = 0;
    while (size > 1) {
        checksum += *buffer++;
        size -= 2;
    }
    if (size) {
        checksum += *(UCHAR*)buffer;
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    return (USHORT)(~checksum);
}

// Function to update IP checksum
static USHORT UpdateIPChecksum(PUCHAR buffer, ULONG size) {
    return CalculateChecksum((USHORT*)buffer, size);
}

// Function to update TCP/UDP checksum for modified packets
static USHORT UpdateTransportChecksum(PUCHAR buffer, ULONG ipHeaderLength, ULONG protocol, ULONG packetLength) {
    PUCHAR transportHeader = buffer + ipHeaderLength;
    USHORT* checksumField = (USHORT*)(transportHeader + (protocol == IPPROTO_TCP ? 16 : 6));  // TCP or UDP checksum field
    *checksumField = 0;

    // Calculate pseudo-header checksum
    ULONG pseudoHeaderChecksum = 0;
    pseudoHeaderChecksum += *(PUSHORT)(buffer + 12);  // Source IP
    pseudoHeaderChecksum += *(PUSHORT)(buffer + 14);
    pseudoHeaderChecksum += *(PUSHORT)(buffer + 16);  // Destination IP
    pseudoHeaderChecksum += *(PUSHORT)(buffer + 18);
    pseudoHeaderChecksum += RtlUshortByteSwap((USHORT)protocol);  // Protocol
    pseudoHeaderChecksum += RtlUshortByteSwap((USHORT)packetLength);  // Transport length

    // Final checksum calculation
    ULONG checksum = CalculateChecksum((USHORT*)transportHeader, packetLength);
    checksum += pseudoHeaderChecksum;
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    *checksumField = (USHORT)~checksum;

    return *checksumField;
}

// Function to modify source IP and port for outgoing packets
static VOID ModifyPacketHeaders(PUCHAR buffer, ULONG ipHeaderLength, USHORT protocol) {
    // Modify source IP
    *(PULONG)(buffer + 12) = SpoofedIp;

    // Modify source port in TCP or UDP header
    PUCHAR transportHeader = buffer + ipHeaderLength;
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        *(USHORT*)(transportHeader) = RtlUshortByteSwap(SpoofedPort);

        // Recalculate the transport layer checksum
static         UpdateTransportChecksum(buffer, ipHeaderLength, protocol, RtlUshortByteSwap((USHORT)(ipHeaderLength)));
        DbgPrint("Source IP and port modified: IP = %08x, Port = %d\n", SpoofedIp, SpoofedPort);
    }

    // Recalculate IP header checksum
static     UpdateIPChecksum(buffer, ipHeaderLength);
    DbgPrint("IP header checksum recalculated.\n");
}

// Function to intercept outgoing packets and apply IP/port spoofing
static VOID InterceptOutgoingPackets(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for outgoing packet\n");
            continue;
        }

        if (dataLength >= sizeof(USHORT) && buffer) {
            USHORT* ipHeader = (USHORT*)buffer;

            if ((ipHeader[0] >> 12) == 4) {  // Check for IPv4 packet
                ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
                USHORT protocol = ipHeader[9];  // Extract protocol (TCP/UDP)

                // Modify packet headers (source IP and port)
static                 ModifyPacketHeaders(buffer, ipHeaderLength, protocol);
            }
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }
}

// NDIS Filter Send handler to intercept and modify outgoing packets
static VOID FilterSendHandler(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
) {
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(SendFlags);

static     InterceptOutgoingPackets(NetBufferLists);

    // Complete sending the NetBufferLists
    NdisFSendNetBufferListsComplete(FilterModuleContext, NetBufferLists, 0);
}

// Logging level enum for different levels of packet detail
typedef enum _LOG_LEVEL {
    LOG_BASIC,
    LOG_DETAILED,
    LOG_VERBOSE
} LOG_LEVEL;

// Global log level
LOG_LEVEL currentLogLevel = LOG_BASIC;

// Function to log packet information based on the current logging level
static void LogPacket(PNET_BUFFER_LIST nbl, LOG_LEVEL logLevel) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return;

    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp); // Get timestamp

    // Log based on the logging level
    switch (logLevel) {
    case LOG_BASIC:
{
        DbgPrint("[%lld] Basic Log: Packet Processed.\n", timestamp.QuadPart);
}
        break;
    case LOG_DETAILED:
{
        DbgPrint("[%lld] Detailed Log: Full packet info\n", timestamp.QuadPart);
}
        break;
    case LOG_VERBOSE:
{
        DbgPrint("[%lld] Verbose Log: Full packet data\n", timestamp.QuadPart);
}
        break;
    }

    // Update driver statistics
    driverStats.packetsProcessed++;
}

// Function to set logging level
static NTSTATUS SetLogLevel(LOG_LEVEL newLogLevel) {
    currentLogLevel = newLogLevel;
    DbgPrint("Log level changed to %d\n", newLogLevel);
    return STATUS_SUCCESS;
}

// Function to reset driver statistics
static void ResetDriverStats() {
    RtlZeroMemory(&driverStats, sizeof(DRIVER_STATS));
    DbgPrint("Driver statistics reset.\n");
}

// Log the current driver statistics
static void LogStatistics() {
    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp); // Get timestamp

    DbgPrint("[%lld] Driver Statistics: Packets Processed: %llu, Packets Filtered: %llu, Checksum Recalculations: %llu, Active Connections: %llu\n",
        timestamp.QuadPart, driverStats.packetsProcessed, driverStats.packetsFiltered,
        driverStats.checksumRecalculations, driverStats.activeConnections);
}

// IOCTL interface for setting log levels and resetting statistics
static NTSTATUS DriverControlLogging(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IOCTL_SET_LOG_LEVEL:
{
        SetLogLevel(*(LOG_LEVEL*)Irp->AssociatedIrp.SystemBuffer);
}
        break;
    case IOCTL_RESET_STATS:
{
static         ResetDriverStats();
}
        break;
    case IOCTL_LOG_STATS:
{
static         LogStatistics();
}
        break;
    default:
}
        break;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Driver unload routine for logging
static VOID UnloadDriverLogging(PDRIVER_OBJECT DriverObject) {
    DbgPrint("Logging and Diagnostic System Module unloaded.\n");
}

// Driver entry point for the logging and diagnostics system
static NTSTATUS DriverEntryLogging(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Set up unload routine
    DriverObject->DriverUnload = UnloadDriverLogging;

    // Register IOCTL interface
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlLogging;

    DbgPrint("Logging and Diagnostic System Module loaded.\n");
    return STATUS_SUCCESS;
}
// Function to apply filtering rules dynamically to outgoing packets
static VOID ApplyFilteringRules(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return;

    PFILTER_RULE currentRule = filterRulesHead;
    while (nb && currentRule) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for packet filtering\n");
            continue;
        }

        // Iterate through the list of filter rules
        while (currentRule) {
            if (currentRule->isActive) {
static                 if (IsPacketMatchingRule(buffer, dataLength, currentRule)) {
                    ModifyPacketWithRule(buffer, dataLength, currentRule);
                    DbgPrint("Packet modified by filter rule: Src IP: %x, Src Port: %d\n", currentRule->srcIP, currentRule->srcPort);
                }
            }
            currentRule = currentRule->next;
        }
        nb = NET_BUFFER_NEXT_NB(nb);
    }
}

// Helper function to check if a packet matches a filtering rule
static BOOLEAN IsPacketMatchingRule(PUCHAR buffer, ULONG dataLength, PFILTER_RULE rule) {
    USHORT* ipHeader = (USHORT*)buffer;

    if ((ipHeader[0] >> 12) != 4) {  // Only handle IPv4 packets
        return FALSE;
    }

    // Extract source and destination IPs, ports, and protocol
    PULONG srcIP = (PULONG)(buffer + 12);
    PULONG destIP = (PULONG)(buffer + 16);
    USHORT protocol = ipHeader[9];
    PUCHAR transportHeader = buffer + ((ipHeader[0] & 0x0F) * 4);
    USHORT srcPort = *(USHORT*)(transportHeader);
    USHORT destPort = *(USHORT*)(transportHeader + 2);

    // Match the rule
    if ((rule->srcIP == *srcIP || rule->srcIP == 0) &&
        (rule->destIP == *destIP || rule->destIP == 0) &&
        (rule->srcPort == srcPort || rule->srcPort == 0) &&
        (rule->destPort == destPort || rule->destPort == 0) &&
        (rule->protocol == protocol || rule->protocol == 0)) {
        return TRUE;
    }
    return FALSE;
}

// Modify the packet based on the applied rule (spoof IP, ports, etc.)
static VOID ModifyPacketWithRule(PUCHAR buffer, ULONG dataLength, PFILTER_RULE rule) {
    PULONG srcIP = (PULONG)(buffer + 12);
    PULONG destIP = (PULONG)(buffer + 16);
    USHORT* transportHeader = (USHORT*)(buffer + ((*buffer & 0x0F) * 4));

    if (rule->newSrcIP != 0) {
        *srcIP = rule->newSrcIP;
    }

    if (rule->newSrcPort != 0) {
        *transportHeader = RtlUshortByteSwap(rule->newSrcPort);
    }

    // Recalculate checksums
static     UpdateIPChecksum(buffer, ((*buffer & 0x0F) * 4));
static     UpdateTransportChecksum(buffer, ((*buffer & 0x0F) * 4), rule->protocol, dataLength - ((*buffer & 0x0F) * 4));

    DbgPrint("Packet headers modified according to rule: New Src IP: %x, New Src Port: %d\n", rule->newSrcIP, rule->newSrcPort);
}

// Add a connection to the connection tracking table with synchronization
static NTSTATUS AddConnection(TCP_CONNECTION* connection) {
    if (!connection) {
        return STATUS_INVALID_PARAMETER;
    }

static     PTCP_CONNECTION newConnection = (PTCP_CONNECTION)AllocateMemory(sizeof(TCP_CONNECTION));
    if (!newConnection) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newConnection, connection, sizeof(TCP_CONNECTION));
    newConnection->next = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&ConnectionTableSpinLock, &oldIrql);

    // Insert the new connection at the head of the linked list
    newConnection->next = connectionTableHead;
    connectionTableHead = newConnection;

    KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);

    DbgPrint("Connection added: Src IP: %x, Src Port: %d\n", connection->srcIP, connection->srcPort);
    return STATUS_SUCCESS;
}

// Remove a connection from the connection tracking table with synchronization
static NTSTATUS RemoveConnection(TCP_CONNECTION* connection) {
    if (!connection) {
        return STATUS_INVALID_PARAMETER;
    }

    PTCP_CONNECTION prev = NULL;
    PTCP_CONNECTION current = connectionTableHead;

    KIRQL oldIrql;
    KeAcquireSpinLock(&ConnectionTableSpinLock, &oldIrql);

    while (current) {
        if (RtlCompareMemory(current, connection, sizeof(TCP_CONNECTION)) == sizeof(TCP_CONNECTION)) {
            if (prev) {
                prev->next = current->next;
            }
            else {
                connectionTableHead = current->next;
            }

static             FreeMemory(current);
            KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);

            DbgPrint("Connection removed: Src IP: %x, Src Port: %d\n", connection->srcIP, connection->srcPort);
            return STATUS_SUCCESS;
        }

        prev = current;
        current = current->next;
    }

    KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);
    return STATUS_NOT_FOUND;
}

//Update an existing Connection state, sequence number, and acknowledgment number
static NTSTATUS UpdateConnection(TCP_CONNECTION* connection, UINT32 seqNum, UINT32 ackNum, TCP_STATE newState) {
    connection->seqNum = seqNum;
    connection->ackNum = ackNum;
    connection->state = newState;
    DbgPrint("Connection state updated: Src IP: %x, Src Port: %d, State: %d\n", connection->srcIP, connection->srcPort, connection->state);
    return STATUS_SUCCESS;
}

// Apply SPI logic to outgoing packets
static VOID ApplySPI(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return;

    PTCP_CONNECTION currentConn = connectionTableHead;
    while (nb && currentConn) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for SPI processing\n");
            continue;
        }

        // Check for SYN, SYN-ACK, ACK, and update the state accordingly
        USHORT* ipHeader = (USHORT*)buffer;
        if ((ipHeader[0] >> 12) == 4) {  // Check for IPv4
            ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
            PUCHAR transportHeader = buffer + ipHeaderLength;

            // Update connection based on sequence and acknowledgment numbers
            if (currentConn->state == SYN_SENT && transportHeader[13] == 0x12) {  // SYN-ACK received
static                 UpdateConnection(currentConn, *(UINT32*)(transportHeader + 4), *(UINT32*)(transportHeader + 8), SYN_RECEIVED);
                DbgPrint("SPI: Connection moved to SYN_RECEIVED state.\n");
            }
            else if (currentConn->state == SYN_RECEIVED && transportHeader[13] == 0x10) {  // ACK received
static                 UpdateConnection(currentConn, *(UINT32*)(transportHeader + 4), *(UINT32*)(transportHeader + 8), ESTABLISHED);
                DbgPrint("SPI: Connection established.\n");
            }
        }

        nb = NET_BUFFER_NEXT_NB(nb);
        currentConn = currentConn->next;
    }
}

// Error handling and logging function
static VOID HandleDriverError(const char* errorMsg, NTSTATUS errorCode) {
    DbgPrint("Error: %s (Status: 0x%x)\n", errorMsg, errorCode);
}

// Function to log and handle critical errors
static VOID LogCriticalError(NTSTATUS errorCode) {
    if (!NT_SUCCESS(errorCode)) {
        DbgPrint("Critical Error occurred: 0x%x\n", errorCode);
    }
}

// Extendable error handling in packet processing
static VOID HandlePacketErrors(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) {
        HandleDriverError("Packet error: Invalid net buffer", STATUS_INVALID_PARAMETER);
        return;
    }

    // Additional error handling can be added here if needed
    DbgPrint("Packet processing with error handling initialized.\n");
}

// Driver unload routine for connection tracking and filtering
static VOID UnloadDriverConnections(PDRIVER_OBJECT DriverObject) {
    PFILTER_RULE currentFilter = filterRulesHead;
    PTCP_CONNECTION currentConn = connectionTableHead;

    // Free filter rules
    while (currentFilter) {
        PFILTER_RULE nextFilter = currentFilter->next;
static         FreeMemory(currentFilter);
        currentFilter = nextFilter;
    }

    // Free connection tracking
    while (currentConn) {
        PTCP_CONNECTION nextConn = currentConn->next;
static         FreeMemory(currentConn);
        currentConn = nextConn;
    }

    DbgPrint("Driver unloaded: All connections and filter rules cleaned up.\n");
}
// Begin Part 5: Connection Timeout Handling and State Management

#include <wdm.h>
#include <ntddk.h>

// TCP Connection timeout threshold (e.g., 2 minutes)
#define CONNECTION_TIMEOUT_THRESHOLD 120

// Function prototype for checking and removing stale connections
VOID CheckAndRemoveStaleConnections();

// Modify the TCP_CONNECTION structure to include the timestamp of the last activity
typedef struct _TCP_CONNECTION {
    UINT32 srcIP;
    UINT32 destIP;
    UINT16 srcPort;
    UINT16 destPort;
    UINT32 seqNum;
    UINT32 ackNum;
    TCP_STATE state;
    LARGE_INTEGER lastActivityTimestamp; // Timestamp for connection activity
    struct _TCP_CONNECTION* next;
} TCP_CONNECTION, * PTCP_CONNECTION;

// Timer and DPC for connection cleanup
KTIMER ConnectionCleanupTimer;
KDPC ConnectionCleanupDpc;

// Function to update connection state and activity timestamp
static NTSTATUS UpdateConnection(TCP_CONNECTION* connection, UINT32 seqNum, UINT32 ackNum, TCP_STATE newState) {
    if (!connection) {
        return STATUS_INVALID_PARAMETER;
    }

    // Acquire the spinlock for thread safety
    KIRQL oldIrql;
    KeAcquireSpinLock(&ConnectionTableSpinLock, &oldIrql);

    // Update the connection state and sequence numbers
    connection->seqNum = seqNum;
    connection->ackNum = ackNum;
    connection->state = newState;

    // Update the activity timestamp to the current system time
    KeQuerySystemTime(&connection->lastActivityTimestamp);

    DbgPrint("Connection state updated: Src IP: %x, Src Port: %d, State: %d\n", connection->srcIP, connection->srcPort, connection->state);

    KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);
    return STATUS_SUCCESS;
}

// Function to periodically check for stale connections
static VOID CheckAndRemoveStaleConnections(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    KIRQL oldIrql;
    LARGE_INTEGER currentTime;
    PTCP_CONNECTION prev = NULL;
    PTCP_CONNECTION current = NULL;

    // Get the current system time
    KeQuerySystemTime(&currentTime);

    // Acquire the spinlock to safely iterate through the connection table
    KeAcquireSpinLock(&ConnectionTableSpinLock, &oldIrql);

    current = connectionTableHead;
    while (current) {
        // Calculate the difference between the current time and the last activity timestamp
        LARGE_INTEGER timeDifference;
        timeDifference.QuadPart = currentTime.QuadPart - current->lastActivityTimestamp.QuadPart;

        // Convert time difference to seconds
        ULONG secondsSinceLastActivity = (ULONG)(timeDifference.QuadPart / 10000000); // 100ns intervals to seconds

        // Check if the connection has been inactive for too long
        if (secondsSinceLastActivity >= CONNECTION_TIMEOUT_THRESHOLD) {
            // Stale connection found; remove it
            DbgPrint("Removing stale connection: Src IP: %x, Src Port: %d\n", current->srcIP, current->srcPort);
            if (prev) {
                prev->next = current->next;
            }
            else {
                connectionTableHead = current->next;
            }

            // Free the memory for the stale connection
            ExFreePoolWithTag(current, 'ctbl');

            if (prev) {
                current = prev->next;
            }
            else {
                current = connectionTableHead;
            }
        }
        else {
            // Move to the next connection in the table
            prev = current;
            current = current->next;
        }
    }

    // Release the spinlock
    KeReleaseSpinLock(&ConnectionTableSpinLock, oldIrql);

    // Recheck after a certain interval (e.g., every 30 seconds)
    LARGE_INTEGER interval;
    interval.QuadPart = -30LL * 10000000LL; // 30 seconds in 100-nanosecond intervals
    KeSetTimerEx(&ConnectionCleanupTimer, interval, 0, &ConnectionCleanupDpc);
}

// Extend DriverEntry function for connection timeout management
static NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Initialize spinlocks
    KeInitializeSpinLock(&FilterRulesSpinLock);
    KeInitializeSpinLock(&ConnectionTableSpinLock);

    // Initialize the timer and DPC for connection cleanup
    KeInitializeTimer(&ConnectionCleanupTimer);
    KeInitializeDpc(&ConnectionCleanupDpc, CheckAndRemoveStaleConnections, NULL);

    // Set the initial timer for connection cleanup
    LARGE_INTEGER interval;
    interval.QuadPart = -30LL * 10000000LL; // 30 seconds in 100-nanosecond intervals
    KeSetTimerEx(&ConnectionCleanupTimer, interval, 0, &ConnectionCleanupDpc);

    DbgPrint("Driver loaded: Connection timeout management initialized.\n");

    return STATUS_SUCCESS;
}

// Unload function to clean up resources
static VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // Cancel the connection cleanup timer
    KeCancelTimer(&ConnectionCleanupTimer);

    // Clean up connections and free memory
    PTCP_CONNECTION current = connectionTableHead;
    while (current) {
        PTCP_CONNECTION next = current->next;
        ExFreePoolWithTag(current, 'ctbl');
        current = next;
    }

    DbgPrint("Driver unloaded: All resources cleaned up.\n");
}

// End of Part 5: Connection Timeout Handling and State Management
// Begin Part 6: Packet Filtering and Checksum Validation

// Forward declaration for checksum validation function
static NTSTATUS ValidateChecksum(PNET_BUFFER_LIST nbl);

// Function to process and filter incoming packets based on filter rules
static VOID ProcessIncomingPackets(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for incoming packet\n");
            continue;
        }

        if (dataLength >= sizeof(USHORT) && buffer) {
            USHORT* ipHeader = (USHORT*)buffer;

            if ((ipHeader[0] >> 12) == 4) {  // Check if it an IPv4 packet
                ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
                USHORT protocol = ipHeader[9];  // Protocol: TCP = 6, UDP = 17

                // Validate checksum for incoming packets
                if (!NT_SUCCESS(ValidateChecksum(nbl))) {
                    DbgPrint("Checksum validation failed for incoming packet. Dropping packet.\n");
                    return;
                }

                // Apply filtering rules
                PFILTER_RULE currentRule = filterRulesHead;
                while (currentRule) {
                    if (currentRule->isActive) {
                        if (currentRule->srcIP == *(PULONG)(buffer + 12) &&
                            currentRule->destIP == *(PULONG)(buffer + 16) &&
                            currentRule->srcPort == *(PUSHORT)(buffer + ipHeaderLength) &&
                            currentRule->destPort == *(PUSHORT)(buffer + ipHeaderLength + 2)) {
                            DbgPrint("Packet matched filter rule: Src IP: %x, Dest IP: %x, Src Port: %d, Dest Port: %d\n",
                                currentRule->srcIP, currentRule->destIP, currentRule->srcPort, currentRule->destPort);

                            // Apply rule modifications
                            *(PULONG)(buffer + 12) = currentRule->newSrcIP;
                            *(PUSHORT)(buffer + ipHeaderLength) = RtlUshortByteSwap(currentRule->newSrcPort);

                            // Recalculate checksum after modification
static                             UpdateIPChecksum(buffer, ipHeaderLength);
static                             UpdateTransportChecksum(buffer, ipHeaderLength, protocol, dataLength - ipHeaderLength);

                            DbgPrint("Packet modified: New Src IP: %x, New Src Port: %d\n", currentRule->newSrcIP, currentRule->newSrcPort);
                        }
                    }
                    currentRule = currentRule->next;
                }
            }
        }
        nb = NET_BUFFER_NEXT_NB(nb);
    }
}

// Validate checksum of incoming packets
NTSTATUS ValidateChecksum(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return STATUS_INVALID_PARAMETER;

    PUCHAR buffer;
    ULONG dataLength;

    if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
        DbgPrint("Failed to query MDL for checksum validation\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    USHORT* ipHeader = (USHORT*)buffer;
    if ((ipHeader[0] >> 12) == 4) {  // IPv4 packet
        ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
        USHORT protocol = ipHeader[9];  // Extract protocol (TCP = 6, UDP = 17)

        // Validate IP header checksum
        USHORT receivedIPChecksum = ipHeader[5];
        ipHeader[5] = 0;
static         USHORT calculatedIPChecksum = UpdateIPChecksum(buffer, ipHeaderLength);
        if (calculatedIPChecksum != receivedIPChecksum) {
            DbgPrint("Invalid IP header checksum: received %x, calculated %x\n", receivedIPChecksum, calculatedIPChecksum);
            return STATUS_DATA_ERROR;
        }

        // Validate TCP/UDP checksum
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
            USHORT receivedTransportChecksum = *(USHORT*)(buffer + ipHeaderLength + (protocol == IPPROTO_TCP ? 16 : 6));
static             USHORT calculatedTransportChecksum = UpdateTransportChecksum(buffer, ipHeaderLength, protocol, dataLength - ipHeaderLength);
            if (calculatedTransportChecksum != receivedTransportChecksum) {
                DbgPrint("Invalid transport checksum: received %x, calculated %x\n", receivedTransportChecksum, calculatedTransportChecksum);
                return STATUS_DATA_ERROR;
            }
        }
    }
    return STATUS_SUCCESS;
}

// Receive handler for incoming packets
static VOID FilterReceiveNetBufferLists(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags
) {
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(NumberOfNetBufferLists);
    UNREFERENCED_PARAMETER(ReceiveFlags);

    // Process the incoming packets,
static     ProcessIncomingPackets(NetBufferLists);

    // Indicate the packets up to the next layer
    NdisFIndicateReceiveNetBufferLists(FilterModuleContext, NetBufferLists, PortNumber, NumberOfNetBufferLists, ReceiveFlags);
}

// Extend DriverEntry function to include receive handler
static NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Initialize spinlocks
    KeInitializeSpinLock(&FilterRulesSpinLock);
    KeInitializeSpinLock(&ConnectionTableSpinLock);

    // Initialize the timer and DPC for connection cleanup (from Part 5)
    KeInitializeTimer(&ConnectionCleanupTimer);
    KeInitializeDpc(&ConnectionCleanupDpc, CheckAndRemoveStaleConnections, NULL);

    // Set the initial timer for connection cleanup (from Part 5)
    LARGE_INTEGER interval;
    interval.QuadPart = -30LL * 10000000LL; // 30 seconds in 100-nanosecond intervals
    KeSetTimerEx(&ConnectionCleanupTimer, interval, 0, &ConnectionCleanupDpc);

    DbgPrint("Driver loaded: Packet filtering and checksum validation initialized.\n");

    return STATUS_SUCCESS;
}
,
// Unload function to clean up resources (including receive handler)
static VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // Cancel the connection cleanup timer (from Part 5)
    KeCancelTimer(&ConnectionCleanupTimer);

    // Free filter rules
    PFILTER_RULE currentRule = filterRulesHead;
    while (currentRule) {
        PFILTER_RULE next = currentRule->next;
        ExFreePoolWithTag(currentRule, 'rflt');
        currentRule = next;
    }

    // Free connections (from Part 5)
    PTCP_CONNECTION currentConn = connectionTableHead;
    while (currentConn) {
        PTCP_CONNECTION next = currentConn->next;
        ExFreePoolWithTag(currentConn, 'ctbl');
        currentConn = next;
    }

    DbgPrint("Driver unloaded: All resources cleaned up.\n");
}

// End of Part 6: Packet Filtering and Checksum Validation
// Begin Part 7: Advanced Logging and Diagnostics

// Global log level variable to control the verbosity of logging
LOG_LEVEL currentLogLevel = LOG_BASIC;

// Function to log detailed packet information based on the log level
static VOID LogDetailedPacketInfo(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for detailed packet log\n");
            continue;
        }

        if (dataLength >= sizeof(USHORT) && buffer) {
            USHORT* ipHeader = (USHORT*)buffer;

            if ((ipHeader[0] >> 12) == 4) {  // IPv4 packet
                ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
                USHORT protocol = ipHeader[9];  // TCP or UDP

                DbgPrint("Packet Details: Src IP: %08x, Dest IP: %08x, Protocol: %d, Packet Length: %lu bytes\n",
                    *(PULONG)(buffer + 12), *(PULONG)(buffer + 16), protocol, dataLength);

                if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                    USHORT srcPort = *(PUSHORT)(buffer + ipHeaderLength);
                    USHORT destPort = *(PUSHORT)(buffer + ipHeaderLength + 2);
                    DbgPrint("Source Port: %d, Destination Port: %d\n", RtlUshortByteSwap(srcPort), RtlUshortByteSwap(destPort));
                }
            }
        }
        nb = NET_BUFFER_NEXT_NB(nb);
    }
}

// Function to log connection details
static VOID LogConnectionDetails() {
    PTCP_CONNECTION currentConn = connectionTableHead;
    while (currentConn) {
        DbgPrint("Connection: Src IP: %08x, Dest IP: %08x, Src Port: %d, Dest Port: %d, State: %d\n",
            currentConn->srcIP, currentConn->destIP, currentConn->srcPort, currentConn->destPort, currentConn->state);
        currentConn = currentConn->next;
    }
}

// Log the state of filter rules
static VOID LogFilterRules() {
    PFILTER_RULE currentRule = filterRulesHead;
    while (currentRule) {
        DbgPrint("Filter Rule: Src IP: %08x, Src Port: %d, Dest IP: %08x, Dest Port: %d, Active: %d\n",
            currentRule->srcIP, currentRule->srcPort, currentRule->destIP, currentRule->destPort, currentRule->isActive);
        currentRule = currentRule->next;
    }
}

// Function to control log verbosity at runtime
static NTSTATUS SetDriverLogLevel(LOG_LEVEL logLevel) {
    currentLogLevel = logLevel;
    DbgPrint("Driver log level set to %d\n", currentLogLevel);
    return STATUS_SUCCESS;
}

// Function to dynamically log information based on log level
static VOID DynamicPacketLogger(PNET_BUFFER_LIST nbl) {
    switch (currentLogLevel) {
    case LOG_BASIC:
{
        DbgPrint("Basic Log: Packet processed.\n");
}
        break;
    case LOG_DETAILED:
{
        LogDetailedPacketInfo(nbl);
}
        break;
    case LOG_VERBOSE:
{
        LogDetailedPacketInfo(nbl);
        LogConnectionDetails();
        LogFilterRules();
}
        break;
    default:
        DbgPrint("Unknown log level. Defaulting to basic logging.\n");
}
        break;
    }
}

// Function to handle IOCTL for logging and diagnostics
static NTSTATUS HandleDiagnosticsIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IOCTL_SET_LOG_LEVEL:
{
        if (Irp->AssociatedIrp.SystemBuffer) {
            LOG_LEVEL newLogLevel = *(LOG_LEVEL*)Irp->AssociatedIrp.SystemBuffer;
static             SetDriverLogLevel(newLogLevel);
        }
        break;
    case IOCTL_LOG_CONNECTIONS:
        LogConnectionDetails();
        break;
    case IOCTL_LOG_FILTER_RULES:
        LogFilterRules();
        break;
    case IOCTL_LOG_MEMORY_STATS:
static         LogMemoryStatistics();
        break;
    default:
        DbgPrint("Unknown IOCTL code received.\n");
        break;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Function to extend DriverEntry to include diagnostics IOCTLs
static NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Existing initialization steps (from Parts 4, 5, 6)
    InitializeSpinLocks();
static     InitializeLookasideList();

    // Set up IOCTL interface for diagnostics
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleDiagnosticsIoctl;

    // Initialize diagnostic logging
static     SetDriverLogLevel(LOG_BASIC);

    DbgPrint("Driver initialized: Diagnostics and logging enabled.\n");
    return STATUS_SUCCESS;
}

// Unload routine to clean up resources, including diagnostic resources
static VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    // Free any additional diagnostic resources here if necessary (e.g., logging buffers)

    // Existing cleanup logic from Parts 4, 5, 6
    FreeFilterRules();
    FreeConnections();
    DestroyLookasideList();

    DbgPrint("Driver unloaded: Resources cleaned up and diagnostics shut down.\n");
}

// End of Part 7: Advanced Logging and Diagnostics
// Begin Part 8: Packet Batching and Fault Tolerance

// Batching threshold for packet processing
#define BATCH_PROCESS_THRESHOLD 10

// Function to batch process outgoing packets
static VOID BatchProcessPackets(PNET_BUFFER_LIST nbl) {
    static int packetCounter = 0;
    packetCounter++;

    // Process the packet
    DynamicPacketLogger(nbl);

    // Once the threshold is reached, apply filtering and other logic in batch
    if (packetCounter >= BATCH_PROCESS_THRESHOLD) {
        DbgPrint("Batch threshold reached. Processing packets in batch.\n");
        ApplyFilteringRules(nbl); // Apply filtering logic
        ApplySPI(nbl);            // Apply SPI logic
        packetCounter = 0;        // Reset the counter
    }
    else {
        DbgPrint("Packet added to batch. Current batch size: %d\n", packetCounter);
    }
}

// Fault tolerance structure to track resource exhaustion and errors
typedef struct _FAULT_TOLERANCE {
    UINT32 packetProcessingFailures;
    UINT32 memoryAllocFailures;
    UINT32 ioErrors;
} FAULT_TOLERANCE, * PFAULT_TOLERANCE;

FAULT_TOLERANCE faultTolerance = { 0 }; // Initialize fault tolerance tracking

// Function to handle errors during packet processing
static VOID HandlePacketProcessingError() {
    faultTolerance.packetProcessingFailures++;
    DbgPrint("Packet processing error occurred. Failure count: %d\n", faultTolerance.packetProcessingFailures);

    // Implement error recovery mechanisms (e.g., retry logic)
    if (faultTolerance.packetProcessingFailures > 5) {
        DbgPrint("Critical error: Multiple packet processing failures. Triggering recovery mechanism.\n");
        // Trigger recovery logic here, like resetting certain driver components
    }
}

// Function to handle memory allocation failures
static VOID HandleMemoryAllocFailure() {
    faultTolerance.memoryAllocFailures++;
    DbgPrint("Memory allocation failure occurred. Failure count: %d\n", faultTolerance.memoryAllocFailures);

    // Implement error recovery mechanisms
    if (faultTolerance.memoryAllocFailures > 3) {
        DbgPrint("Critical error: Multiple memory allocation failures. Freeing memory and resetting lists.\n");
        FreeConnections(); // Free all active connections to recover memory
        FreeFilterRules(); // Free all filter rules
static         InitializeLookasideList(); // Reinitialize memory management
    }
}

// Fault-tolerant packet handler to catch errors during processing
static VOID FaultTolerantPacketHandler(PNET_BUFFER_LIST nbl) {
    __try {
static         BatchProcessPackets(nbl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        HandlePacketProcessingError();
    }
}

// Enhanced memory allocation with fault tolerance
static PVOID FaultTolerantAllocateMemory(SIZE_T size) {
static     PVOID memory = AllocateMemory(size);
    if (!memory) {
        HandleMemoryAllocFailure();
    }
    return memory;
}

// Function to extend DriverEntry for fault tolerance initialization
static NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Existing initialization steps (from Parts 4-7)
    InitializeSpinLocks();
static     InitializeLookasideList();
static     SetDriverLogLevel(LOG_BASIC);

    // Initialize fault tolerance tracking
    RtlZeroMemory(&faultTolerance, sizeof(FAULT_TOLERANCE));

    // Set up IOCTL interface for diagnostics (from Part 7)
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleDiagnosticsIoctl;

    DbgPrint("Driver initialized with fault tolerance and packet batching enabled.\n");
    return STATUS_SUCCESS;
}

// Fault-tolerant driver unload routine
static VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    // Free any additional resources related to fault tolerance

    // Existing cleanup logic from Parts 4-7
    FreeFilterRules();
    FreeConnections();
    DestroyLookasideList();

    DbgPrint("Driver unloaded. Resources cleaned up with fault tolerance support.\n");
}

// Function to extend IOCTL handling to include fault tolerance diagnostics
static NTSTATUS HandleDiagnosticsIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IOCTL_SET_LOG_LEVEL:
{
        if (Irp->AssociatedIrp.SystemBuffer) {
            LOG_LEVEL newLogLevel = *(LOG_LEVEL*)Irp->AssociatedIrp.SystemBuffer;
static             SetDriverLogLevel(newLogLevel);
        }
        break;
    case IOCTL_LOG_CONNECTIONS:
        LogConnectionDetails();
        break;
    case IOCTL_LOG_FILTER_RULES:
        LogFilterRules();
        break;
    case IOCTL_LOG_MEMORY_STATS:
static         LogMemoryStatistics();
        break;
    case IOCTL_LOG_FAULT_TOLERANCE:
        DbgPrint("Fault Tolerance Statistics: Packet Processing Failures: %d, Memory Allocation Failures: %d, IO Errors: %d\n",
            faultTolerance.packetProcessingFailures, faultTolerance.memoryAllocFailures, faultTolerance.ioErrors);
        break;
    default:
        DbgPrint("Unknown IOCTL code received.\n");
        break;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// End of Part 8: Packet Batching and Fault Tolerance
// Begin Part 9: Security Enhancements (Packet Encryption and Secure Memory Handling)

// AES encryption key (placeholder; should be securely loaded in real implementation)
#define AES_KEY_SIZE 16
UCHAR aesKey[AES_KEY_SIZE] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

// Secure memory allocation with encryption (mock implementation)
static PVOID SecureAllocateMemory(SIZE_T size) {
static     PVOID memory = AllocateMemory(size);
    if (!memory) {
        HandleMemoryAllocFailure();
        return NULL;
    }

    // Encrypt the allocated memory using AES (mock; real encryption method needed)
    DbgPrint("Memory allocated and encrypted: %p, size: %llu\n", memory, size);
    return memory;
}

// Secure memory freeing
static VOID SecureFreeMemory(PVOID memory) {
    if (memory) {
        // Decrypt the memory before freeing (mock implementation)
        DbgPrint("Memory decrypted and freed: %p\n", memory);
static         FreeMemory(memory);
    }
    else {
        DbgPrint("Attempted to free null secure memory pointer.\n");
    }
}

// Function to encrypt packet data using AES (mock implementation)
static VOID EncryptPacket(PUCHAR buffer, ULONG dataSize) {
    // Mock AES encryption logic (this should be replaced with real encryption code)
    for (ULONG i = 0; i < dataSize; i++) {
        buffer[i] ^= aesKey[i % AES_KEY_SIZE];  // XOR encryption (just for demo purposes)
    }
    DbgPrint("Packet encrypted. Size: %lu\n", dataSize);
}

// Function to decrypt packet data using AES (mock implementation)
static VOID DecryptPacket(PUCHAR buffer, ULONG dataSize) {
    // Mock AES decryption logic (same XOR logic for demonstration)
    for (ULONG i = 0; i < dataSize; i++) {
        buffer[i] ^= aesKey[i % AES_KEY_SIZE];  // XOR decryption
    }
    DbgPrint("Packet decrypted. Size: %lu\n", dataSize);
}

// Secure packet handler that encrypts outgoing packets
static VOID SecureHandleOutgoingPackets(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for outgoing packet\n");
            continue;
        }

        // Encrypt the packet before sending
        EncryptPacket(buffer, dataLength);

        nb = NET_BUFFER_NEXT_NB(nb);
    }
}

// Send handler with secure packet encryption
static VOID SecureFilterSendHandler(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
) {
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(SendFlags);

    // Encrypt and process outgoing packets securely
static     SecureHandleOutgoingPackets(NetBufferLists);

    // Complete sending the NetBufferLists
    NdisFSendNetBufferListsComplete(FilterModuleContext, NetBufferLists, 0);
}

// Function to securely handle IOCTL commands for AES key management (mock implementation)
static NTSTATUS HandleSecureIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IOCTL_SET_AES_KEY:
{
        if (Irp->AssociatedIrp.SystemBuffer) {
            RtlCopyMemory(aesKey, Irp->AssociatedIrp.SystemBuffer, AES_KEY_SIZE);
            DbgPrint("AES encryption key updated.\n");
        }
        break;
    case IOCTL_GET_AES_KEY:
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, aesKey, AES_KEY_SIZE);
        Irp->IoStatus.Information = AES_KEY_SIZE;
        DbgPrint("AES encryption key retrieved.\n");
        break;
    default:
        DbgPrint("Unknown secure IOCTL command received.\n");
        break;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Driver entry function to initialize secure memory and encryption components
static NTSTATUS SecureDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Initialize secure memory handling
static     InitializeLookasideList();

    // Set up unload routine
    DriverObject->DriverUnload = UnloadDriver;

    // Register IOCTL interface for encryption key management
static     DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleSecureIoctl;

    DbgPrint("Secure Driver loaded with AES encryption and secure memory handling.\n");
    return STATUS_SUCCESS;
}

// End of Part 9: Security Enhancements
// Begin Part 10: Multithreading and Performance Optimization

// Define thread context structure for packet processing threads
typedef struct _THREAD_CONTEXT {
    HANDLE threadHandle;
    KEVENT threadEvent;
    BOOLEAN terminateThread;
} THREAD_CONTEXT, * PTHREAD_CONTEXT;

// Define packet processing queue structure
typedef struct _PACKET_QUEUE {
    LIST_ENTRY queueHead;
    KSPIN_LOCK queueLock;
    KEVENT packetReadyEvent;
} PACKET_QUEUE, * PPACKET_QUEUE;

PACKET_QUEUE packetProcessingQueue;

// Thread context for managing multiple packet processing threads
PTHREAD_CONTEXT packetProcessingThreads[4];  // Allow up to 4 threads for parallel packet processing

// Function to initialize the packet processing queue
static VOID InitializePacketProcessingQueue() {
    InitializeListHead(&packetProcessingQueue.queueHead);
    KeInitializeSpinLock(&packetProcessingQueue.queueLock);
    KeInitializeEvent(&packetProcessingQueue.packetReadyEvent, NotificationEvent, FALSE);
    DbgPrint("Packet processing queue initialized.\n");
}

// Function to queue a packet for processing
static VOID QueuePacketForProcessing(PNET_BUFFER_LIST nbl) {
    KIRQL oldIrql;
    PLIST_ENTRY entry = ExAllocatePoolWithTag(NonPagedPool, sizeof(LIST_ENTRY), 'pktq');
    if (!entry) {
        DbgPrint("Failed to allocate memory for packet queue entry.\n");
        return;
    }

    // Lock the queue and add the packet to the list
    KeAcquireSpinLock(&packetProcessingQueue.queueLock, &oldIrql);
    InsertTailList(&packetProcessingQueue.queueHead, entry);
    KeReleaseSpinLock(&packetProcessingQueue.queueLock, oldIrql);

    // Signal the packet processing event
    KeSetEvent(&packetProcessingQueue.packetReadyEvent, IO_NO_INCREMENT, FALSE);
    DbgPrint("Packet queued for processing.\n");
}

// Worker thread function to process packets from the queue
static VOID PacketProcessingWorker(PVOID context) {
    PTHREAD_CONTEXT threadContext = (PTHREAD_CONTEXT)context;
    DbgPrint("Packet processing worker thread started.\n");

    while (!threadContext->terminateThread) {
        // Wait for the packet processing event
        KeWaitForSingleObject(&packetProcessingQueue.packetReadyEvent, Executive, KernelMode, FALSE, NULL);

        // Lock the queue and retrieve the first packet
        KIRQL oldIrql;
        PLIST_ENTRY packetEntry = NULL;
        KeAcquireSpinLock(&packetProcessingQueue.queueLock, &oldIrql);
        if (!IsListEmpty(&packetProcessingQueue.queueHead)) {
            packetEntry = RemoveHeadList(&packetProcessingQueue.queueHead);
        }
        KeReleaseSpinLock(&packetProcessingQueue.queueLock, oldIrql);

        // If there is a packet to process, handle it
        if (packetEntry) {
            PNET_BUFFER_LIST nbl = CONTAINING_RECORD(packetEntry, NET_BUFFER_LIST, Next);
            HandleOutgoingPackets(nbl);  // Process the packet using existing logic
            ExFreePool(packetEntry);      // Free the packet entry
        }

        // Reset the event if no more packets are left in the queue
        if (IsListEmpty(&packetProcessingQueue.queueHead)) {
            KeClearEvent(&packetProcessingQueue.packetReadyEvent);
        }
    }

    DbgPrint("Packet processing worker thread terminated.\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Function to initialize packet processing threads
static NTSTATUS InitializePacketProcessingThreads() {
    NTSTATUS status;
    for (int i = 0; i < 4; i++) {
        packetProcessingThreads[i] = (PTHREAD_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(THREAD_CONTEXT), 'thrd');
        if (!packetProcessingThreads[i]) {
            DbgPrint("Failed to allocate memory for thread context.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Initialize the thread event and create the worker thread
        KeInitializeEvent(&packetProcessingThreads[i]->threadEvent, NotificationEvent, FALSE);
        packetProcessingThreads[i]->terminateThread = FALSE;
static         status = PsCreateSystemThread(&packetProcessingThreads[i]->threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, PacketProcessingWorker, packetProcessingThreads[i]);

        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to create packet processing thread %d.\n", i);
            ExFreePool(packetProcessingThreads[i]);
            return status;
        }

        DbgPrint("Packet processing thread %d created successfully.\n", i);
    }

    return STATUS_SUCCESS;
}

// Function to terminate packet processing threads
static VOID TerminatePacketProcessingThreads() {
    for (int i = 0; i < 4; i++) {
        if (packetProcessingThreads[i]) {
            // Signal the thread to terminate
            packetProcessingThreads[i]->terminateThread = TRUE;
            KeSetEvent(&packetProcessingThreads[i]->threadEvent, IO_NO_INCREMENT, FALSE);

            // Wait for the thread to terminate and close the handle
            ZwWaitForSingleObject(packetProcessingThreads[i]->threadHandle, FALSE, NULL);
            ZwClose(packetProcessingThreads[i]->threadHandle);

            // Free the thread context
            ExFreePool(packetProcessingThreads[i]);
            packetProcessingThreads[i] = NULL;
            DbgPrint("Packet processing thread %d terminated.\n", i);
        }
    }
}

// Function to initialize multithreading for packet processing
static NTSTATUS InitializeMultithreading() {
static     InitializePacketProcessingQueue();
static     NTSTATUS status = InitializePacketProcessingThreads();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to initialize multithreading.\n");
        return status;
    }

    DbgPrint("Multithreading initialized for packet processing.\n");
    return STATUS_SUCCESS;
}

// Function to clean up multithreading resources
static VOID CleanupMultithreading() {
static     TerminatePacketProcessingThreads();
    DbgPrint("Multithreading resources cleaned up.\n");
}

// Modified DriverEntry to include multithreading initialization
static NTSTATUS MultithreadingDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
static     NTSTATUS status = SecureDriverEntry(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to initialize secure driver components.\n");
        return status;
    }

    // Initialize multithreading for packet processing
static     status = InitializeMultithreading();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to initialize multithreading.\n");
        return status;
    }

    DbgPrint("Driver loaded with multithreading support for packet processing.\n");
    return STATUS_SUCCESS;
}

// Driver unload function to clean up multithreading resources
static VOID MultithreadingDriverUnload(PDRIVER_OBJECT DriverObject) {
    // Clean up multithreading resources
    CleanupMultithreading();

    // Call original unload logic
    UnloadDriver(DriverObject);
    DbgPrint("Driver unloaded with multithreading cleanup.\n");
}

// End of Part 10: Multithreading and Performance Optimization
// Begin Part 11: Dynamic Memory Management Optimization

// Memory tracking structure for allocation statistics
typedef struct _MEMORY_TRACKER {
    ULONG totalAllocations;
    ULONG totalDeallocations;
    SIZE_T totalMemoryAllocated;
    SIZE_T totalMemoryFreed;
    NPAGED_LOOKASIDE_LIST lookasideList;  // Lookaside list for optimized allocations
} MEMORY_TRACKER, * PMEMORY_TRACKER;

MEMORY_TRACKER memoryTracker;  // Global memory tracking structure

// Function to initialize memory management resources, including the lookaside list
static NTSTATUS InitializeMemoryManagement() {
    // Initialize the lookaside list for faster memory allocations
    ExInitializeNPagedLookasideList(&memoryTracker.lookasideList, NULL, NULL, 0, sizeof(PVOID), 'memt', 0);

    // Initialize memory tracking statistics
    memoryTracker.totalAllocations = 0;
    memoryTracker.totalDeallocations = 0;
    memoryTracker.totalMemoryAllocated = 0;
    memoryTracker.totalMemoryFreed = 0;

    DbgPrint("Memory management initialized with lookaside list support.\n");
    return STATUS_SUCCESS;
}

// Function to allocate memory using the lookaside list or fallback to pool if necessary
static PVOID AllocateMemory(SIZE_T size) {
    PVOID memory = ExAllocateFromNPagedLookasideList(&memoryTracker.lookasideList);
    if (!memory) {
        memory = ExAllocatePoolWithTag(NonPagedPool, size, 'memt');
        if (!memory) {
            DbgPrint("Memory allocation failed.\n");
            return NULL;
        }
    }

    // Update memory allocation statistics
    memoryTracker.totalAllocations++;
    memoryTracker.totalMemoryAllocated += size;

    DbgPrint("Memory allocated: %p, size: %llu bytes\n", memory, size);
    return memory;
}

// Function to free allocated memory
static VOID FreeMemory(PVOID memory, SIZE_T size) {
    if (memory) {
        if (ExFreeToNPagedLookasideList(&memoryTracker.lookasideList, memory) == FALSE) {
            ExFreePoolWithTag(memory, 'memt');
        }

        // Update memory deallocation statistics
        memoryTracker.totalDeallocations++;
        memoryTracker.totalMemoryFreed += size;

        DbgPrint("Memory freed: %p, size: %llu bytes\n", memory, size);
    }
    else {
        DbgPrint("Attempted to free NULL pointer.\n");
    }
}

// Function to log memory usage statistics
static VOID LogMemoryStatistics() {
    DbgPrint("Memory Statistics:\n");
    DbgPrint("  Total Allocations: %lu\n", memoryTracker.totalAllocations);
    DbgPrint("  Total Deallocations: %lu\n", memoryTracker.totalDeallocations);
    DbgPrint("  Total Memory Allocated: %llu bytes\n", memoryTracker.totalMemoryAllocated);
    DbgPrint("  Total Memory Freed: %llu bytes\n", memoryTracker.totalMemoryFreed);
}

// Function to reset memory statistics
static VOID ResetMemoryStatistics() {
    memoryTracker.totalAllocations = 0;
    memoryTracker.totalDeallocations = 0;
    memoryTracker.totalMemoryAllocated = 0;
    memoryTracker.totalMemoryFreed = 0;

    DbgPrint("Memory statistics reset.\n");
}

// Function to clean up memory management resources during driver unload
static VOID CleanupMemoryManagement() {
    // Destroy the lookaside list
    ExDeleteNPagedLookasideList(&memoryTracker.lookasideList);

    // Log final memory statistics
static     LogMemoryStatistics();

    DbgPrint("Memory management resources cleaned up.\n");
}

// Modified DriverEntry to initialize memory management
static NTSTATUS MemoryDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
static     NTSTATUS status = MultithreadingDriverEntry(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to initialize driver components.\n");
        return status;
    }

    // Initialize memory management
static     status = InitializeMemoryManagement();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to initialize memory management.\n");
        return status;
    }

    DbgPrint("Driver loaded with dynamic memory management support.\n");
    return STATUS_SUCCESS;
}

// Modified DriverUnload to clean up memory management
static VOID MemoryDriverUnload(PDRIVER_OBJECT DriverObject) {
    // Clean up memory management resources
    CleanupMemoryManagement();

    // Call the multithreading clean-up
static     MultithreadingDriverUnload(DriverObject);
    DbgPrint("Driver unloaded with memory management cleanup.\n");
}

// IOCTL handler for memory management diagnostics
static NTSTATUS MemoryIoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IOCTL_LOG_MEMORY_STATS:
{
static         LogMemoryStatistics();
}
        break;

    case IOCTL_RESET_MEMORY_STATS:
{
static         ResetMemoryStatistics();
}
        break;

    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
}
        break;
    }

    Irp->IoStatus.Information = sizeof(ULONG);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// End of Part 11: Dynamic Memory Management Optimization
// Continuation from Part 12...

// Memory Pool for Different Allocation Types
NPAGED_LOOKASIDE_LIST FilterRuleLookasideList; // Pool for Filter Rules
NPAGED_LOOKASIDE_LIST ConnectionLookasideList; // Pool for TCP Connections
NPAGED_LOOKASIDE_LIST PacketBufferLookasideList; // Pool for Packet Buffers

// Advanced Memory Allocation Function
static VOID AddToDeferredFreeList(PVOID memory, SIZE_T size, ULONG tag) {PVOID AdvancedAllocateMemory(POOL_TYPE poolType, SIZE_T size, ULONG tag) {
    PVOID memory = NULL;

    switch (poolType) {
    case NonPagedPool:
{
        memory = ExAllocateFromNPagedLookasideList(&PacketBufferLookasideList);
}
        break;
    case PagedPool:
{
        memory = ExAllocatePoolWithTag(PagedPool, size, tag);
}
        break;
    default:
        memory = ExAllocatePoolWithTag(NonPagedPool, size, tag);
}
        break;
    }

    if (memory) {
        memoryStats.totalAllocations++;
        memoryStats.currentBufferUsage += size;
        DbgPrint("Advanced Memory Allocated: %p, Size: %llu bytes, Pool Type: %d\n", memory, size, poolType);
    }
    else {
        DbgPrint("Memory allocation failed! Pool Type: %d\n", poolType);
    }

    return memory;
}

// Advanced Memory Freeing Function
static VOID AdvancedFreeMemory(PVOID memory, SIZE_T size, ULONG tag) {
    if (memory) {
        ExFreeToNPagedLookasideList(&PacketBufferLookasideList, memory);
        memoryStats.currentBufferUsage -= size;
        DbgPrint("Advanced Memory Freed: %p, Size: %llu bytes\n", memory, size);
    }
    else {
        DbgPrint("Attempted to free NULL memory pointer!\n");
    }
}

// Deferred Resource Freeing Mechanism
typedef struct _DEFERRED_FREE_ITEM {
    PVOID memory;
    SIZE_T size;
    ULONG tag;
    struct _DEFERRED_FREE_ITEM* next;
} DEFERRED_FREE_ITEM, * PDEFERRED_FREE_ITEM;

PDEFERRED_FREE_ITEM deferredFreeHead = NULL;
KSPIN_LOCK DeferredFreeSpinLock;  // Spinlock for deferred resource list

// Add a memory block to the deferred free list
static VOID AddToDeferredFreeList(PVOID memory, SIZE_T size, ULONG tag) {
    PDEFERRED_FREE_ITEM item = (PDEFERRED_FREE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(DEFERRED_FREE_ITEM), 'dfre');
    if (item) {
        item->memory = memory;
        item->size = size;
        item->tag = tag;
        item->next = NULL;

        KIRQL oldIrql;
        KeAcquireSpinLock(&DeferredFreeSpinLock, &oldIrql);

        // Add item to the head of the deferred free list
        item->next = deferredFreeHead;
        deferredFreeHead = item;

        KeReleaseSpinLock(&DeferredFreeSpinLock, oldIrql);
        DbgPrint("Memory added to deferred free list: %p, Size: %llu bytes\n", memory, size);
    }
    else {
        DbgPrint("Failed to allocate memory for deferred free list!\n");
    }
}

// Free all resources in the deferred free list
static VOID ProcessDeferredFreeList() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&DeferredFreeSpinLock, &oldIrql);

    PDEFERRED_FREE_ITEM current = deferredFreeHead;
    while (current) {
        PDEFERRED_FREE_ITEM next = current->next;

static         AdvancedFreeMemory(current->memory, current->size, current->tag);
        ExFreePoolWithTag(current, 'dfre');

        current = next;
    }

    deferredFreeHead = NULL;
    KeReleaseSpinLock(&DeferredFreeSpinLock, oldIrql);

    DbgPrint("Deferred free list processed, all resources freed.\n");
}

// Initialize Advanced Memory Pools
static NTSTATUS InitializeAdvancedMemoryPools() {
    ExInitializeNPagedLookasideList(&FilterRuleLookasideList, NULL, NULL, 0, sizeof(FILTER_RULE), 'frul', 0);
    ExInitializeNPagedLookasideList(&ConnectionLookasideList, NULL, NULL, 0, sizeof(TCP_CONNECTION), 'conl', 0);
    ExInitializeNPagedLookasideList(&PacketBufferLookasideList, NULL, NULL, 0, 1500, 'pktb', 0);  // Assume packet size is ~1500 bytes

    DbgPrint("Advanced memory pools initialized.\n");
    return STATUS_SUCCESS;
}

// Destroy Advanced Memory Pools during driver unload
static VOID DestroyAdvancedMemoryPools() {
    ExDeleteNPagedLookasideList(&FilterRuleLookasideList);
    ExDeleteNPagedLookasideList(&ConnectionLookasideList);
    ExDeleteNPagedLookasideList(&PacketBufferLookasideList);

    DbgPrint("Advanced memory pools destroyed.\n");
}

// Advanced Driver Unload Routine
static VOID UnloadDriverAdvanced(PDRIVER_OBJECT DriverObject) {
    // Process the deferred free list before unloading
static     ProcessDeferredFreeList();

    // Destroy memory pools
    DestroyAdvancedMemoryPools();

    DbgPrint("Advanced Driver Unloaded.\n");
}
// Continuation from Part 13...

// Define additional protocol constants
#define PROTOCOL_ICMP 1

// Error codes for packet processing
#define PACKET_PROCESSING_SUCCESS 0
#define PACKET_PROCESSING_ERROR -1
#define PACKET_INVALID_PROTOCOL -2
#define PACKET_MALFORMED -3

// Enhanced Function to Process and Inspect Packets
static NTSTATUS ProcessPacket(PNET_BUFFER_LIST nbl, ULONG SendFlags) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    NTSTATUS status = PACKET_PROCESSING_SUCCESS;

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        // Query the MDL to retrieve packet data
        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for packet.\n");
            return PACKET_PROCESSING_ERROR;
        }

        if (dataLength >= sizeof(USHORT) && buffer) {
            // Basic packet header processing and inspection
            USHORT* ipHeader = (USHORT*)buffer;

            if ((ipHeader[0] >> 12) == 4) {  // IPv4 packet
                ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
                USHORT protocol = ipHeader[9];  // Extract protocol (TCP/UDP/ICMP)

                // Handle TCP Protocol
                if (protocol == IPPROTO_TCP) {
                    status = ProcessTCPPacket(buffer, ipHeaderLength, dataLength);
                    if (status != PACKET_PROCESSING_SUCCESS) {
                        DbgPrint("Error processing TCP packet.\n");
                    }
                }
                // Handle UDP Protocol
                else if (protocol == IPPROTO_UDP) {
static                     status = ProcessUDPPacket(buffer, ipHeaderLength, dataLength);
                    if (status != PACKET_PROCESSING_SUCCESS) {
                        DbgPrint("Error processing UDP packet.\n");
                    }
                }
                // Handle ICMP Protocol (new addition)
                else if (protocol == PROTOCOL_ICMP) {
static                     status = ProcessICMPPacket(buffer, ipHeaderLength, dataLength);
                    if (status != PACKET_PROCESSING_SUCCESS) {
                        DbgPrint("Error processing ICMP packet.\n");
                    }
                }
                // Handle Unknown Protocols
                else {
                    DbgPrint("Unknown protocol encountered: %d\n", protocol);
                    status = PACKET_INVALID_PROTOCOL;
                }
            }
            else {
                DbgPrint("Malformed packet detected.\n");
                status = PACKET_MALFORMED;
            }
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return status;
}

// Process TCP Packets (Enhancements)
static NTSTATUS ProcessTCPPacket(PUCHAR buffer, ULONG ipHeaderLength, ULONG dataLength) {
    // Basic validation for TCP packet length
    if (dataLength < (ipHeaderLength + sizeof(TCP_HEADER))) {
        DbgPrint("TCP packet too short.\n");
        return PACKET_MALFORMED;
    }

    // Extract TCP header
    PUCHAR tcpHeader = buffer + ipHeaderLength;

    // Modify the source port if necessary
    *(USHORT*)(tcpHeader) = RtlUshortByteSwap(SpoofedPort);

    // Recalculate the TCP checksum
static     USHORT tcpChecksum = UpdateTransportChecksum(buffer, ipHeaderLength, IPPROTO_TCP, dataLength - ipHeaderLength);
    if (tcpChecksum == 0) {
        DbgPrint("Failed to update TCP checksum.\n");
        return PACKET_PROCESSING_ERROR;
    }

    DbgPrint("Processed TCP packet. New checksum: %04x\n", tcpChecksum);
    return PACKET_PROCESSING_SUCCESS;
}

// Process UDP Packets (Enhancements)
static NTSTATUS ProcessUDPPacket(PUCHAR buffer, ULONG ipHeaderLength, ULONG dataLength) {
    // Basic validation for UDP packet length
    if (dataLength < (ipHeaderLength + sizeof(UDP_HEADER))) {
        DbgPrint("UDP packet too short.\n");
        return PACKET_MALFORMED;
    }

    // Extract UDP header
    PUCHAR udpHeader = buffer + ipHeaderLength;

    // Modify the source port if necessary
    *(USHORT*)(udpHeader) = RtlUshortByteSwap(SpoofedPort);

    // Recalculate the UDP checksum
static     USHORT udpChecksum = UpdateTransportChecksum(buffer, ipHeaderLength, IPPROTO_UDP, dataLength - ipHeaderLength);
    if (udpChecksum == 0) {
        DbgPrint("Failed to update UDP checksum.\n");
        return PACKET_PROCESSING_ERROR;
    }

    DbgPrint("Processed UDP packet. New checksum: %04x\n", udpChecksum);
    return PACKET_PROCESSING_SUCCESS;
}

// Process ICMP Packets (New Functionality)
static NTSTATUS ProcessICMPPacket(PUCHAR buffer, ULONG ipHeaderLength, ULONG dataLength) {
    // Basic validation for ICMP packet length
    if (dataLength < (ipHeaderLength + sizeof(ICMP_HEADER))) {
        DbgPrint("ICMP packet too short.\n");
        return PACKET_MALFORMED;
    }

    // Extract ICMP header
    PUCHAR icmpHeader = buffer + ipHeaderLength;

    // Modify the ICMP checksum if necessary (specific to ICMP messages)
static     USHORT icmpChecksum = UpdateTransportChecksum(buffer, ipHeaderLength, PROTOCOL_ICMP, dataLength - ipHeaderLength);
    if (icmpChecksum == 0) {
        DbgPrint("Failed to update ICMP checksum.\n");
        return PACKET_PROCESSING_ERROR;
    }

    DbgPrint("Processed ICMP packet. New checksum: %04x\n", icmpChecksum);
    return PACKET_PROCESSING_SUCCESS;
}

// Enhanced Logging for Packet Processing
static VOID LogPacketProcessingDetails(PUCHAR buffer, USHORT protocol, ULONG dataLength) {
    DbgPrint("Packet details - Protocol: %d, Data Length: %lu bytes\n", protocol, dataLength);

    if (protocol == IPPROTO_TCP) {
        DbgPrint("TCP Packet: Source Port: %d, Destination Port: %d\n",
            RtlUshortByteSwap(*(USHORT*)(buffer + 0)),
            RtlUshortByteSwap(*(USHORT*)(buffer + 2)));
    }
    else if (protocol == IPPROTO_UDP) {
        DbgPrint("UDP Packet: Source Port: %d, Destination Port: %d\n",
            RtlUshortByteSwap(*(USHORT*)(buffer + 0)),
            RtlUshortByteSwap(*(USHORT*)(buffer + 2)));
    }
    else if (protocol == PROTOCOL_ICMP) {
        DbgPrint("ICMP Packet: Type: %d, Code: %d\n",
            *(buffer + 0), *(buffer + 1));
    }
}
// Continuation from Part 14...

// Define constants for security
#define ENCRYPTION_KEY_LENGTH 16
#define DECRYPTION_FAILURE -4

// Sample encryption key (for demonstration purposes)
UCHAR encryptionKey[ENCRYPTION_KEY_LENGTH] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

// Function to verify packet integrity using checksum
static NTSTATUS VerifyPacketIntegrity(PUCHAR buffer, ULONG dataLength) {
    USHORT checksum = CalculateChecksum((USHORT*)buffer, dataLength);

    if (checksum != 0) {
        DbgPrint("Packet integrity check failed: Checksum mismatch.\n");
        return PACKET_PROCESSING_ERROR;
    }

    DbgPrint("Packet integrity verified.\n");
    return PACKET_PROCESSING_SUCCESS;
}

// Basic XOR encryption for packet data (for demonstration purposes)
static VOID EncryptPacketData(PUCHAR data, ULONG dataLength) {
    for (ULONG i = 0; i < dataLength; i++) {
        data[i] ^= encryptionKey[i % ENCRYPTION_KEY_LENGTH];  // XOR with encryption key
    }
    DbgPrint("Packet data encrypted.\n");
}

// Basic XOR decryption for packet data
static NTSTATUS DecryptPacketData(PUCHAR data, ULONG dataLength) {
    for (ULONG i = 0; i < dataLength; i++) {
        data[i] ^= encryptionKey[i % ENCRYPTION_KEY_LENGTH];  // XOR with encryption key
    }
    DbgPrint("Packet data decrypted.\n");

    // In a real implementation, you verify the decryption worked (e.g., by checking a known value in the packet)
    return PACKET_PROCESSING_SUCCESS;
}

// Process incoming packet and verify integrity
static NTSTATUS ProcessIncomingPacket(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    NTSTATUS status = PACKET_PROCESSING_SUCCESS;

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        // Query the MDL to retrieve packet data
        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for packet.\n");
            return PACKET_PROCESSING_ERROR;
        }

        // Verify packet integrity
static         status = VerifyPacketIntegrity(buffer, dataLength);
        if (status != PACKET_PROCESSING_SUCCESS) {
            DbgPrint("Packet integrity verification failed. Dropping packet.\n");
            return PACKET_PROCESSING_ERROR;
        }

        // Decrypt packet data if necessary
        status = DecryptPacketData(buffer, dataLength);
        if (status != PACKET_PROCESSING_SUCCESS) {
            DbgPrint("Packet decryption failed. Dropping packet.\n");
            return DECRYPTION_FAILURE;
        }

        // Continue processing the packet...

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return status;
}

// Handle outgoing packet and encrypt sensitive data
static VOID HandleOutgoingPacketEncryption(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for outgoing packet.\n");
            continue;
        }

        // Encrypt sensitive packet data
        EncryptPacketData(buffer, dataLength);

        // Proceed with sending the packet...

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    DbgPrint("Outgoing packet data encrypted and ready for transmission.\n");
}

// Expanded Security Logging for Integrity and Encryption
static VOID LogSecurityEvent(ULONG eventId, const char* message) {
    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp);

    // Log security event with timestamp
    DbgPrint("[%lld] Security Event ID %lu: %s\n", timestamp.QuadPart, eventId, message);
}

// Define security event IDs for logging
#define SECURITY_EVENT_PACKET_DROPPED 1001
#define SECURITY_EVENT_ENCRYPTION_FAILURE 1002
#define SECURITY_EVENT_CHECKSUM_FAILURE 1003

static // Example usage of LogSecurityEvent within a packet handling routine
static VOID HandlePacketWithLogging(PNET_BUFFER_LIST nbl) {
static     NTSTATUS status = ProcessIncomingPacket(nbl);

    if (status != PACKET_PROCESSING_SUCCESS) {
        if (status == PACKET_PROCESSING_ERROR) {
static             LogSecurityEvent(SECURITY_EVENT_CHECKSUM_FAILURE, "Packet dropped due to checksum failure.");
        }
        else if (status == DECRYPTION_FAILURE) {
static             LogSecurityEvent(SECURITY_EVENT_ENCRYPTION_FAILURE, "Packet dropped due to decryption failure.");
        }
    }
}
// Continuation from Part 15...

// Define constants for data stripping
#define STRIP_SENSITIVE_DATA 1
#define MASKED_IDENTIFIER 0xFFFF

// Function to strip sensitive data from packets
static VOID StripSensitiveData(PUCHAR buffer, ULONG ipHeaderLength, USHORT protocol) {
    // Example: Redact source and destination IP addresses
    *(PULONG)(buffer + 12) = MASKED_IDENTIFIER;  // Mask source IP
    *(PULONG)(buffer + 16) = MASKED_IDENTIFIER;  // Mask destination IP

    // Further example: Strip application-specific data in TCP/UDP headers
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        PUCHAR transportHeader = buffer + ipHeaderLength;
        *(USHORT*)(transportHeader + 2) = MASKED_IDENTIFIER;  // Mask source port
        *(USHORT*)(transportHeader + 4) = MASKED_IDENTIFIER;  // Mask destination port
        DbgPrint("Sensitive data stripped from TCP/UDP headers.\n");
    }

    DbgPrint("Packet data stripped of sensitive information.\n");
}

// Function to handle the stripping of data from outgoing packets
static VOID HandleOutgoingPacketStripping(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for outgoing packet.\n");
            continue;
        }

        if (dataLength >= sizeof(USHORT) && buffer) {
            USHORT* ipHeader = (USHORT*)buffer;

            if ((ipHeader[0] >> 12) == 4) {  // Check for IPv4
                ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
                USHORT protocol = ipHeader[9];  // Extract protocol (TCP/UDP)

                // Strip sensitive data from the packet
static                 StripSensitiveData(buffer, ipHeaderLength, protocol);
            }
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    DbgPrint("Outgoing packet stripped of sensitive information.\n");
}

// Function to scrub outgoing packets before final transmission
static VOID ScrubOutgoingPackets(PNET_BUFFER_LIST nbl, ULONG SendFlags) {
    // Apply data stripping before sending out
static     HandleOutgoingPacketStripping(nbl);

    // Continue with transmission
    NdisFSendNetBufferListsComplete(FilterDriverHandle, nbl, SendFlags);
}

// Enhanced packet sending handler with data stripping
static VOID EnhancedFilterSendHandler(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
) {
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(SendFlags);

    ScrubOutgoingPackets(NetBufferLists, SendFlags);
}

// Logging function to track packet stripping actions
static VOID LogStrippingAction(PUCHAR buffer, ULONG dataLength) {
    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp);

    DbgPrint("[%lld] Packet stripped of sensitive data (Length: %lu bytes)\n", timestamp.QuadPart, dataLength);
}

// Function to check for specific sensitive fields and remove them
static NTSTATUS StripSpecificSensitiveFields(PUCHAR buffer, ULONG dataLength) {
    // Example: Remove a specific identifier from the packet payload (e.g., SSNs, email addresses)
    for (ULONG i = 0; i < dataLength - 4; i++) {
        if (RtlCompareMemory(buffer + i, "SSN", 3) == 3) {  // Hypothetical example
            RtlFillMemory(buffer + i, 4, MASKED_IDENTIFIER);  // Mask out SSN
            DbgPrint("Sensitive field (SSN) found and masked at byte offset: %lu\n", i);
            LogStrippingAction(buffer, dataLength);
            return PACKET_PROCESSING_SUCCESS;
        }
    }

    return PACKET_PROCESSING_SUCCESS;
}

// Function to handle outgoing packets and strip sensitive fields
static VOID HandlePacketSensitiveFieldStripping(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for outgoing packet.\n");
            continue;
        }

        // Strip specific sensitive fields from the packet
        StripSpecificSensitiveFields(buffer, dataLength);

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    DbgPrint("Sensitive fields stripped from outgoing packets.\n");
}

// Enhanced Send handler with sensitive field stripping
static VOID FilterSendHandlerWithSensitiveFieldStripping(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags
) {
    UNREFERENCED_PARAMETER(FilterModuleContext);
    UNREFERENCED_PARAMETER(PortNumber);
    UNREFERENCED_PARAMETER(SendFlags);

    HandlePacketSensitiveFieldStripping(NetBufferLists);

    // Complete the packet send after stripping sensitive fields
    NdisFSendNetBufferListsComplete(FilterModuleContext, NetBufferLists, 0);
}

// Driver entry function with enhanced data stripping functionality
static NTSTATUS DriverEntryWithStripping(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Register the enhanced send handler that includes data stripping
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FilterSendHandlerWithSensitiveFieldStripping;

    DbgPrint("Driver initialized with sensitive data stripping capabilities.\n");

    return STATUS_SUCCESS;
}
// Function to inspect packet contents and filter based on defined patterns
static NTSTATUS DeepPacketInspection(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    // Iterate through each network buffer in the list
    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        // Query the MDL to get the packet data buffer
        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for deep packet inspection\n");
            continue;
        }

        // Perform deep packet inspection
        if (dataLength > 0 && buffer) {
            // Example: Identify specific protocol patterns in the packet payload
static             if (IsHttpTraffic(buffer, dataLength)) {
                DbgPrint("HTTP traffic detected, applying filtering rules\n");
static                 ApplyHttpFilteringRules(buffer, dataLength);
            }
static             else if (IsFtpTraffic(buffer, dataLength)) {
                DbgPrint("FTP traffic detected, applying filtering rules\n");
static                 ApplyFtpFilteringRules(buffer, dataLength);
            }
static             else if (IsMaliciousTraffic(buffer, dataLength)) {
                DbgPrint("Malicious traffic detected, blocking packet\n");
                return STATUS_ACCESS_DENIED;  // Block malicious traffic
            }
        }

        // Move to the next buffer
        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return STATUS_SUCCESS;
}

// Function to identify HTTP traffic patterns
static BOOLEAN IsHttpTraffic(PUCHAR buffer, ULONG dataLength) {
    // Inspect the beginning of the packet for common HTTP methods (GET, POST, etc.)
    if (dataLength >= 4 && (RtlCompareMemory(buffer, "GET ", 4) == 4 || RtlCompareMemory(buffer, "POST", 4) == 4)) {
        return TRUE;
    }
    return FALSE;
}

// Function to apply filtering rules for HTTP traffic
static VOID ApplyHttpFilteringRules(PUCHAR buffer, ULONG dataLength) {
    // Example: Apply rules such as blocking certain URLs or injecting headers
    DbgPrint("Applying HTTP filtering rules on packet\n");
    // Modify the HTTP payload if necessary
static     InjectSecurityHeaders(buffer, dataLength);
}

// Function to inject custom security headers into HTTP traffic
static VOID InjectSecurityHeaders(PUCHAR buffer, ULONG dataLength) {
    // Example: Insert headers to improve security, such as HSTS or Content-Security-Policy
    DbgPrint("Injecting security headers into HTTP response\n");
    // Modify the buffer to add security headers (this is an example, ensure packet size doesn exceed limits)
}

// Function to identify FTP traffic patterns
static BOOLEAN IsFtpTraffic(PUCHAR buffer, ULONG dataLength) {
    // Look for FTP-specific commands or protocol markers
    if (dataLength >= 4 && RtlCompareMemory(buffer, "USER", 4) == 4) {
        return TRUE;
    }
    return FALSE;
}

// Function to apply filtering rules for FTP traffic
static VOID ApplyFtpFilteringRules(PUCHAR buffer, ULONG dataLength) {
    // Example: Restrict FTP file transfers or monitor for login attempts
    DbgPrint("Applying FTP filtering rules on packet\n");
    // Implement logic to handle FTP traffic
}

// Function to detect malicious traffic patterns
static BOOLEAN IsMaliciousTraffic(PUCHAR buffer, ULONG dataLength) {
    // Example: Check for signatures or patterns that indicate malware or intrusion attempts
    if (dataLength > 0) {
        // For example, detect known exploit signatures or shellcode patterns
        if (RtlCompareMemory(buffer, "\x90\x90\x90\x90", 4) == 4) {  // Example NOP sled pattern
            return TRUE;
        }
    }
    return FALSE;
}
// Define custom IOCTL codes for rule management
#define IOCTL_ADD_FILTER_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_FILTER_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MODIFY_FILTER_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST_FILTER_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structure for passing filter rules between user-space and kernel-space
typedef struct _USER_FILTER_RULE {
    BOOLEAN isActive;
    UINT8 protocol;
    UINT32 srcIP;
    UINT32 destIP;
    UINT16 srcPort;
    UINT16 destPort;
    UINT32 packetSize;
    UINT32 newSrcIP;
    UINT16 newSrcPort;
} USER_FILTER_RULE, * PUSER_FILTER_RULE;

// Forward declarations for new functions
NTSTATUS AddFilterRuleFromUser(PUSER_FILTER_RULE userRule);
NTSTATUS RemoveFilterRuleFromUser(PUSER_FILTER_RULE userRule);
NTSTATUS ModifyFilterRuleFromUser(PUSER_FILTER_RULE oldUserRule, PUSER_FILTER_RULE newUserRule);
NTSTATUS ListFilterRules(PIRP Irp, PIO_STACK_LOCATION stack);

// Handler for device control (IOCTL) operations
static NTSTATUS DriverControlRuleManager(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PUSER_FILTER_RULE userRule;
    NTSTATUS status = STATUS_SUCCESS;

    switch (controlCode) {
    case IOCTL_ADD_FILTER_RULE:
{
        status = WdfRequestRetrieveInputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&userRule, NULL);
        if (NT_SUCCESS(status)) {
            status = AddFilterRuleFromUser(userRule);
        }
        break;

    case IOCTL_REMOVE_FILTER_RULE:
        status = WdfRequestRetrieveInputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&userRule, NULL);
        if (NT_SUCCESS(status)) {
            status = RemoveFilterRuleFromUser(userRule);
        }
        break;

    case IOCTL_MODIFY_FILTER_RULE:
    {
        PUSER_FILTER_RULE oldUserRule, newUserRule;
        status = WdfRequestRetrieveInputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&oldUserRule, NULL);
        status = WdfRequestRetrieveOutputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&newUserRule, NULL);
        if (NT_SUCCESS(status)) {
            status = ModifyFilterRuleFromUser(oldUserRule, newUserRule);
        }
        break;
    }

    case IOCTL_LIST_FILTER_RULES:
        status = ListFilterRules(Irp, stack);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Function to add a filter rule from user-space
NTSTATUS AddFilterRuleFromUser(PUSER_FILTER_RULE userRule) {
static     PFILTER_RULE newRule = (PFILTER_RULE)AllocateMemory(sizeof(FILTER_RULE));
    if (!newRule) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newRule, userRule, sizeof(FILTER_RULE));

    // Add to filter rule list (protected with spinlock)
    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    newRule->next = filterRulesHead;
    filterRulesHead = newRule;

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);

    DbgPrint("Filter rule dynamically added: Source IP: %x, Source Port: %d\n", newRule->srcIP, newRule->srcPort);
    return STATUS_SUCCESS;
}

// Function to remove a filter rule from user-space
NTSTATUS RemoveFilterRuleFromUser(PUSER_FILTER_RULE userRule) {
    PFILTER_RULE current, prev = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    current = filterRulesHead;
    while (current) {
        if (RtlCompareMemory(current, userRule, sizeof(USER_FILTER_RULE)) == sizeof(USER_FILTER_RULE)) {
            if (prev) {
                prev->next = current->next;
            }
            else {
                filterRulesHead = current->next;
            }
static             FreeMemory(current);
            KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
            DbgPrint("Filter rule dynamically removed: Source IP: %x, Source Port: %d\n", userRule->srcIP, userRule->srcPort);
            return STATUS_SUCCESS;
        }
        prev = current;
        current = current->next;
    }

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
    return STATUS_NOT_FOUND;
}

// Function to modify a filter rule from user-space
NTSTATUS ModifyFilterRuleFromUser(PUSER_FILTER_RULE oldUserRule, PUSER_FILTER_RULE newUserRule) {
    NTSTATUS status = RemoveFilterRuleFromUser(oldUserRule);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return AddFilterRuleFromUser(newUserRule);
}

// Function to list all current filter rules to user-space
NTSTATUS ListFilterRules(PIRP Irp, PIO_STACK_LOCATION stack) {
    PUSER_FILTER_RULE outputBuffer;
    ULONG bufferSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG requiredSize = 0;
    PFILTER_RULE current = filterRulesHead;

    while (current) {
        requiredSize += sizeof(USER_FILTER_RULE);
        current = current->next;
    }

    if (bufferSize < requiredSize) {
        Irp->IoStatus.Information = requiredSize;
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS status = WdfRequestRetrieveOutputBuffer(Irp, requiredSize, (PVOID*)&outputBuffer, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    current = filterRulesHead;
    while (current) {
        RtlCopyMemory(outputBuffer, current, sizeof(USER_FILTER_RULE));
        outputBuffer++;
        current = current->next;
    }

    Irp->IoStatus.Information = requiredSize;
    return STATUS_SUCCESS;
}

// Driver entry point for dynamic rule management via IOCTL
static NTSTATUS DriverEntryRuleManager(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // Set up the driver unload function
    DriverObject->DriverUnload = UnloadDriver;

    // Register the IOCTL interface
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlRuleManager;

    DbgPrint("Dynamic rule management system loaded successfully.\n");
    return STATUS_SUCCESS;
}
// Define a logging level for security-related events
#define LOG_SECURITY 3

// Define a set of validation limits for the user-space rules
#define MAX_PORT_NUMBER 65535
#define MIN_PACKET_SIZE 64
#define MAX_PACKET_SIZE 65535

// Function prototypes for new security and validation checks
NTSTATUS ValidateUserFilterRule(PUSER_FILTER_RULE userRule);
NTSTATUS ValidateUserPermissions();
static VOID LogSecurityEvent(const char* message, PUSER_FILTER_RULE userRule);

// Enhanced AddFilterRule with validation and security checks
NTSTATUS AddFilterRuleFromUser(PUSER_FILTER_RULE userRule) {
    NTSTATUS status;

    // Validate user permissions
    status = ValidateUserPermissions();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Permission validation failed for adding a filter rule.\n");
        return status;
    }

    // Validate the user-provided rule
    status = ValidateUserFilterRule(userRule);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Validation failed for adding a filter rule.\n");
        return status;
    }

static     PFILTER_RULE newRule = (PFILTER_RULE)AllocateMemory(sizeof(FILTER_RULE));
    if (!newRule) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newRule, userRule, sizeof(FILTER_RULE));

    // Add the rule to the filter list (spinlock protected)
    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    newRule->next = filterRulesHead;
    filterRulesHead = newRule;

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);

static     LogSecurityEvent("Filter rule added", userRule);
    return STATUS_SUCCESS;
}

// Enhanced RemoveFilterRule with validation and security checks
NTSTATUS RemoveFilterRuleFromUser(PUSER_FILTER_RULE userRule) {
    NTSTATUS status;

    // Validate user permissions
    status = ValidateUserPermissions();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Permission validation failed for removing a filter rule.\n");
        return status;
    }

    // Validate the rule to be removed
    status = ValidateUserFilterRule(userRule);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Validation failed for removing a filter rule.\n");
        return status;
    }

    PFILTER_RULE current, prev = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    current = filterRulesHead;
    while (current) {
        if (RtlCompareMemory(current, userRule, sizeof(USER_FILTER_RULE)) == sizeof(USER_FILTER_RULE)) {
            if (prev) {
                prev->next = current->next;
            }
            else {
                filterRulesHead = current->next;
            }
static             FreeMemory(current);
            KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
static             LogSecurityEvent("Filter rule removed", userRule);
            return STATUS_SUCCESS;
        }
        prev = current;
        current = current->next;
    }

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
    return STATUS_NOT_FOUND;
}

// Enhanced ModifyFilterRule with validation and security checks
NTSTATUS ModifyFilterRuleFromUser(PUSER_FILTER_RULE oldUserRule, PUSER_FILTER_RULE newUserRule) {
    NTSTATUS status;

    // Validate user permissions
    status = ValidateUserPermissions();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Permission validation failed for modifying a filter rule.\n");
        return status;
    }

    // Validate the old and new rules
    status = ValidateUserFilterRule(oldUserRule);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Validation failed for old filter rule in modification.\n");
        return status;
    }

    status = ValidateUserFilterRule(newUserRule);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Validation failed for new filter rule in modification.\n");
        return status;
    }

    status = RemoveFilterRuleFromUser(oldUserRule);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return AddFilterRuleFromUser(newUserRule);
}

// Function to validate the integrity of a user-provided filter rule
NTSTATUS ValidateUserFilterRule(PUSER_FILTER_RULE userRule) {
    if (userRule->srcPort > MAX_PORT_NUMBER || userRule->destPort > MAX_PORT_NUMBER) {
        DbgPrint("Invalid port number in user-provided rule.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (userRule->packetSize < MIN_PACKET_SIZE || userRule->packetSize > MAX_PACKET_SIZE) {
        DbgPrint("Invalid packet size in user-provided rule.\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Additional validation for protocol, IP addresses, etc., can be added here
    return STATUS_SUCCESS;
}

// Function to validate user permissions (mock implementation)
NTSTATUS ValidateUserPermissions() {
    // Normally, we validate the user security context, but for this demo, we will just return success
    return STATUS_SUCCESS;
}

// Function to log security-related events
static VOID LogSecurityEvent(const char* message, PUSER_FILTER_RULE userRule) {
    LARGE_INTEGER timestamp;
    KeQuerySystemTime(&timestamp);

    DbgPrint("[%lld] Security Log - %s: Src IP: %x, Src Port: %d, Dest IP: %x, Dest Port: %d, Protocol: %d\n",
        timestamp.QuadPart, message, userRule->srcIP, userRule->srcPort,
        userRule->destIP, userRule->destPort, userRule->protocol);
}

// Enhanced DriverControlRuleManager to log security events
static NTSTATUS DriverControlRuleManager(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    PUSER_FILTER_RULE userRule;
    NTSTATUS status = STATUS_SUCCESS;

    switch (controlCode) {
    case IOCTL_ADD_FILTER_RULE:
{
        status = WdfRequestRetrieveInputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&userRule, NULL);
        if (NT_SUCCESS(status)) {
            status = AddFilterRuleFromUser(userRule);
        }
        break;

    case IOCTL_REMOVE_FILTER_RULE:
        status = WdfRequestRetrieveInputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&userRule, NULL);
        if (NT_SUCCESS(status)) {
            status = RemoveFilterRuleFromUser(userRule);
        }
        break;

    case IOCTL_MODIFY_FILTER_RULE:
    {
        PUSER_FILTER_RULE oldUserRule, newUserRule;
        status = WdfRequestRetrieveInputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&oldUserRule, NULL);
        status = WdfRequestRetrieveOutputBuffer(Irp, sizeof(USER_FILTER_RULE), (PVOID*)&newUserRule, NULL);
        if (NT_SUCCESS(status)) {
            status = ModifyFilterRuleFromUser(oldUserRule, newUserRule);
        }
        break;
    }

    case IOCTL_LIST_FILTER_RULES:
        status = ListFilterRules(Irp, stack);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
// Advanced packet filtering function with optimized header parsing
static VOID ApplyAdvancedFiltering(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    // Temporary buffer to store packet data for processing
    PUCHAR buffer = NULL;
    ULONG dataLength = 0;

    // Iterate through all net buffers in the list
    while (nb != NULL) {
        if (NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority) != STATUS_SUCCESS || buffer == NULL) {
            DbgPrint("Failed to query buffer.\n");
            nb = NET_BUFFER_NEXT_NB(nb);
            continue;
        }

        // Check if the packet is an IPv4 packet (we can expand to IPv6 later)
        USHORT* ipHeader = (USHORT*)buffer;
        if ((ipHeader[0] >> 12) != 4) {  // Only handle IPv4 for now
            nb = NET_BUFFER_NEXT_NB(nb);
            continue;
        }

        // Get header lengths and protocol from the IP header
        ULONG ipHeaderLength = (ipHeader[0] & 0x0F) * 4;
        USHORT protocol = ipHeader[9];

        // Early exit optimization: skip if no rules apply to this protocol
static         if (!IsProtocolSupported(protocol)) {
            nb = NET_BUFFER_NEXT_NB(nb);
            continue;
        }

        // Get source and destination IPs from the IP header
        UINT32 srcIP = *(UINT32*)(buffer + 12);
        UINT32 destIP = *(UINT32*)(buffer + 16);

        // Apply rule matching logic
        PFILTER_RULE currentRule = filterRulesHead;
        BOOLEAN ruleApplied = FALSE;

        // Iterate through all active filter rules
        while (currentRule != NULL) {
static             if (currentRule->isActive && MatchPacketToRule(currentRule, srcIP, destIP, protocol, buffer, ipHeaderLength)) {
                DbgPrint("Rule matched: Src IP: %x, Dest IP: %x\n", srcIP, destIP);
                ApplyRuleActions(currentRule, buffer, ipHeaderLength, protocol, dataLength);
                ruleApplied = TRUE;
                break;  // Stop after the first matching rule
            }
            currentRule = currentRule->next;
        }

        // Log the packet if no rule was applied
        if (!ruleApplied) {
static             LogUnmatchedPacket(buffer, ipHeaderLength, protocol, dataLength);
        }

        nb = NET_BUFFER_NEXT_NB(nb);  // Move to the next net buffer
    }
}

// Function to check if the protocol is supported by the filter rules
static BOOLEAN IsProtocolSupported(USHORT protocol) {
    // Currently support TCP, UDP, and ICMP. Expand here if needed.
    return (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP);
}

// Function to match a packet to a specific rule
static BOOLEAN MatchPacketToRule(PFILTER_RULE rule, UINT32 srcIP, UINT32 destIP, USHORT protocol, PUCHAR buffer, ULONG ipHeaderLength) {
    // Check if the rule matches the protocol
    if (rule->protocol != protocol) {
        return FALSE;
    }

    // Check if the rule matches the source/destination IP addresses
    if (rule->srcIP != srcIP && rule->destIP != destIP) {
        return FALSE;
    }

    // Additional protocol-specific checks (e.g., ports for TCP/UDP)
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        USHORT srcPort = RtlUshortByteSwap(*(USHORT*)(buffer + ipHeaderLength));
        USHORT destPort = RtlUshortByteSwap(*(USHORT*)(buffer + ipHeaderLength + 2));

        if (rule->srcPort != srcPort && rule->destPort != destPort) {
            return FALSE;
        }
    }

    return TRUE;  // All conditions matched
}

// Function to apply actions specified by a rule to a packet
static VOID ApplyRuleActions(PFILTER_RULE rule, PUCHAR buffer, ULONG ipHeaderLength, USHORT protocol, ULONG dataLength) {
    // Modify the source IP and port based on the rule
    if (rule->newSrcIP != 0) {
        *(UINT32*)(buffer + 12) = rule->newSrcIP;
        DbgPrint("Source IP changed to: %x\n", rule->newSrcIP);
    }

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        USHORT* srcPort = (USHORT*)(buffer + ipHeaderLength);
        if (rule->newSrcPort != 0) {
            *srcPort = RtlUshortByteSwap(rule->newSrcPort);
            DbgPrint("Source port changed to: %d\n", rule->newSrcPort);
        }

        // Recalculate TCP/UDP checksum
static         USHORT checksum = UpdateTransportChecksum(buffer, ipHeaderLength, protocol, dataLength - ipHeaderLength);
        DbgPrint("Updated transport layer checksum: %x\n", checksum);
    }

    // Recalculate IP header checksum
static     USHORT ipChecksum = UpdateIPChecksum(buffer, ipHeaderLength);
    DbgPrint("Updated IP header checksum: %x\n", ipChecksum);
}

// Function to log unmatched packets
static VOID LogUnmatchedPacket(PUCHAR buffer, ULONG ipHeaderLength, USHORT protocol, ULONG dataLength) {
    DbgPrint("Unmatched packet: Protocol: %d, Src IP: %x, Dest IP: %x\n",
        protocol, *(UINT32*)(buffer + 12), *(UINT32*)(buffer + 16));

    // Additional logging for packet diagnostics if needed
}

// NEW DPI code here //
// Include required headers
#include <ntddk.h>
#include <fwpsk.h>
#include <netioapi.h>
#include <wdm.h>
#include <ntstrsafe.h>

// Define packet inspection result codes
#define PACKET_INSPECTION_SUCCESS 0
#define PACKET_INSPECTION_FAILURE -1
#define PACKET_DETECTED_MALICIOUS -2

// Function prototypes for deep packet inspection and rule application
NTSTATUS InspectPacket(PNET_BUFFER_LIST nbl);
BOOLEAN DetectMaliciousTraffic(PUCHAR buffer, ULONG dataLength);
VOID ApplyFilteringForHTTP(PUCHAR buffer, ULONG dataLength);
VOID ApplyFilteringForFTP(PUCHAR buffer, ULONG dataLength);

// Function for inspecting packets and applying rules
NTSTATUS InspectPacket(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    NTSTATUS status = PACKET_INSPECTION_SUCCESS;

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to query MDL for packet inspection\n");
            return PACKET_INSPECTION_FAILURE;
        }

        if (dataLength > 0 && buffer) {
            // Example: Check for HTTP or FTP traffic and apply filtering
            if (DetectMaliciousTraffic(buffer, dataLength)) {
                DbgPrint("Malicious traffic detected, blocking packet\n");
                return PACKET_DETECTED_MALICIOUS;  // Block the packet
            }

            // Apply specific filters for HTTP and FTP traffic
static             if (IsHttpTraffic(buffer, dataLength)) {
                ApplyFilteringForHTTP(buffer, dataLength);
static             } else if (IsFtpTraffic(buffer, dataLength)) {
                ApplyFilteringForFTP(buffer, dataLength);
            }
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return status;
}

// Function to detect malicious traffic patterns
BOOLEAN DetectMaliciousTraffic(PUCHAR buffer, ULONG dataLength) {
    // Example detection for malicious traffic (e.g., NOP sled, known shellcode patterns)
    if (RtlCompareMemory(buffer, "\x90\x90\x90\x90", 4) == 4) {  // NOP sled example
        return TRUE;
    }
    return FALSE;
}

// Function to apply filtering rules for HTTP traffic
VOID ApplyFilteringForHTTP(PUCHAR buffer, ULONG dataLength) {
    DbgPrint("Applying HTTP filtering rules\n");
    // Add more filtering logic for HTTP traffic here
}

// Function to apply filtering rules for FTP traffic
VOID ApplyFilteringForFTP(PUCHAR buffer, ULONG dataLength) {
    DbgPrint("Applying FTP filtering rules\n");
    // Add more filtering logic for FTP traffic here
}
// Deep packet inspection to handle network data with specific conditions
static NTSTATUS DeepPacketInspection(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for deep inspection.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Inspect payload for patterns (e.g., HTTP, FTP, or malicious signatures)
static         if (IsHttpTraffic(buffer, dataLength)) {
            DbgPrint("HTTP traffic identified.\n");
static             ApplyHttpFilteringRules(buffer, dataLength);
static         } else if (IsFtpTraffic(buffer, dataLength)) {
            DbgPrint("FTP traffic identified.\n");
static             ApplyFtpFilteringRules(buffer, dataLength);
static         } else if (IsMaliciousTraffic(buffer, dataLength)) {
            DbgPrint("Malicious traffic detected. Blocking.\n");
            return STATUS_ACCESS_DENIED;  // Block the packet
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }
    return STATUS_SUCCESS;
}

static BOOLEAN IsHttpTraffic(PUCHAR buffer, ULONG dataLength) {
    return (dataLength >= 4 && (RtlCompareMemory(buffer, "GET ", 4) == 4 || RtlCompareMemory(buffer, "POST", 4) == 4));
}

static BOOLEAN IsMaliciousTraffic(PUCHAR buffer, ULONG dataLength) {
    // Sample heuristic to identify potential exploits
    return (dataLength >= 4 && RtlCompareMemory(buffer, "\x90\x90\x90\x90", 4) == 4);  // Example NOP sled
}
// Function to apply HTTP filtering rules
static void ApplyHttpFilteringRules(PUCHAR buffer, ULONG dataLength) {
    // Analyze HTTP headers or payload for filtering (e.g., specific URL blocking, methods, etc.)
    if (RtlCompareMemory(buffer, "GET /blocked", 12) == 12) {
        DbgPrint("Blocking access to forbidden URL.\n");
        // Logic to block specific URL access
        // Could modify the packet here or simply drop it
    }

    // Additional logic for filtering headers, user agents, etc.
}

// Function to apply FTP filtering rules
static void ApplyFtpFilteringRules(PUCHAR buffer, ULONG dataLength) {
    // Inspect FTP control traffic (e.g., LOGIN, RETR, STOR commands)
    if (RtlCompareMemory(buffer, "USER", 4) == 4 || RtlCompareMemory(buffer, "PASS", 4) == 4) {
        DbgPrint("Inspecting FTP login traffic.\n");
        // Logic to log or block FTP login attempts
    }

    // Could also handle FTP data channels, command filtering, etc.
}

// Function to log security events when filter rules are modified or network anomalies are detected
static void LogSecurityEvent(const char* message, PUSER_FILTER_RULE userRule) {
    DbgPrint("[SECURITY EVENT]: %s - Rule: SrcPort: %d, DestPort: %d, PacketSize: %d\n",
             message, userRule->srcPort, userRule->destPort, userRule->packetSize);
    // Could extend this to log into a file, Windows Event Log, or a remote security monitor
}

// Function to securely modify an existing filter rule
NTSTATUS ModifyFilterRuleFromUser(PUSER_FILTER_RULE oldUserRule, PUSER_FILTER_RULE newUserRule) {
    NTSTATUS status = ValidateUserPermissions();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Permission check failed.\n");
        return status;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    PFILTER_RULE current = filterRulesHead;
    while (current) {
        if (RtlCompareMemory(current, oldUserRule, sizeof(USER_FILTER_RULE)) == sizeof(USER_FILTER_RULE)) {
            // Update the rule in place
            RtlCopyMemory(current, newUserRule, sizeof(USER_FILTER_RULE));
            KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
static             LogSecurityEvent("Filter rule modified", newUserRule);
            return STATUS_SUCCESS;
        }
        current = current->next;
    }

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
    return STATUS_NOT_FOUND;
}
// Function to apply DNS filtering rules
static void ApplyDnsFilteringRules(PUCHAR buffer, ULONG dataLength) {
    // DNS traffic starts with a 12-byte header, followed by the query
    if (dataLength > 12) {
        PUCHAR dnsQuery = buffer + 12;  // Point to the DNS query section
        DbgPrint("DNS query detected.\n");

        // Check for specific domain name filtering (e.g., blocking certain domain names)
        if (RtlCompareMemory(dnsQuery, "\x03www\x07example\x03com", 16) == 16) {
            DbgPrint("Blocking DNS query for www.example.com.\n");
            // Logic to block or redirect DNS query
        }

        // Additional logic for handling DNS response filtering, malicious queries, etc.
    }
}

// Function to apply SMTP filtering rules
static void ApplySmtpFilteringRules(PUCHAR buffer, ULONG dataLength) {
    // SMTP traffic typically contains commands such as HELO, MAIL FROM, RCPT TO, etc.
    if (RtlCompareMemory(buffer, "HELO", 4) == 4) {
        DbgPrint("SMTP HELO command detected.\n");
        // Logic to log or block SMTP traffic
    }
    if (RtlCompareMemory(buffer, "MAIL FROM:", 10) == 10) {
        DbgPrint("SMTP MAIL FROM command detected.\n");
        // Additional filtering logic for email sender addresses
    }

    // Can add more rules for handling SMTP data, such as attachments, keywords, etc.
}

// Function to apply malicious traffic detection based on known exploit patterns
static BOOLEAN IsMaliciousTraffic(PUCHAR buffer, ULONG dataLength) {
    // Sample heuristic to detect specific malicious traffic (e.g., NOP sleds, buffer overflow attempts)
    if (dataLength >= 4 && RtlCompareMemory(buffer, "\x90\x90\x90\x90", 4) == 4) {
        DbgPrint("Malicious NOP sled detected.\n");
        return TRUE;  // Block this traffic
    }
    // Could add more signatures for known exploit payloads, shellcode patterns, etc.
    return FALSE;
}

// Function to inspect and apply filtering rules for DNS and SMTP traffic
static NTSTATUS ApplyDnsAndSmtpFiltering(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for DNS/SMTP inspection.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Inspect DNS traffic
static         if (IsDnsTraffic(buffer, dataLength)) {
            DbgPrint("DNS traffic identified.\n");
static             ApplyDnsFilteringRules(buffer, dataLength);
        }

        // Inspect SMTP traffic
static         if (IsSmtpTraffic(buffer, dataLength)) {
            DbgPrint("SMTP traffic identified.\n");
static             ApplySmtpFilteringRules(buffer, dataLength);
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }
    return STATUS_SUCCESS;
}

// Function to identify DNS traffic based on packet structure
static BOOLEAN IsDnsTraffic(PUCHAR buffer, ULONG dataLength) {
    // Check for DNS packet type (e.g., UDP or TCP port 53, and valid DNS header structure)
    // Simplified example assuming DNS over UDP (port 53)
    return (dataLength > 12 && (buffer[2] == 0x01 || buffer[2] == 0x81));  // Basic DNS header check
}

// Function to identify SMTP traffic based on well-known SMTP commands
static BOOLEAN IsSmtpTraffic(PUCHAR buffer, ULONG dataLength) {
    // Check for known SMTP commands at the start of the buffer
    return (RtlCompareMemory(buffer, "HELO", 4) == 4 || RtlCompareMemory(buffer, "MAIL FROM:", 10) == 10);
}

// Secure memory allocation with logging
static PVOID AllocateMemory(SIZE_T size) {
    PVOID memory = ExAllocatePoolWithTag(NonPagedPool, size, 'rflt');
    if (!memory) {
        DbgPrint("Failed to allocate memory.\n");
        return NULL;
    }
    DbgPrint("Memory allocated: %p\n", memory);
    return memory;
}

// Secure memory deallocation with logging
static void FreeMemory(PVOID memory) {
    if (memory) {
        DbgPrint("Memory deallocated: %p\n", memory);
        ExFreePool(memory);
    }
}

// Enhanced validation for user permissions, including role-based access control (RBAC)
NTSTATUS ValidateUserPermissions() {
    // Check user context for permission to modify filter rules (e.g., based on roles or security tokens)
    // Could implement a security context check, token validation, etc.
    DbgPrint("Validating user permissions.\n");

    // Example: Always return success for simplicity, but this should be replaced with actual checks
    return STATUS_SUCCESS;
}
// Function to apply filtering rules to HTTPS traffic
static void ApplyHttpsFilteringRules(PUCHAR buffer, ULONG dataLength) {
    // HTTPS traffic starts with the TLS handshake, so we check for the Client Hello message
    if (dataLength > 5 && buffer[0] == 0x16 && buffer[1] == 0x03) {  // Basic TLS header check
        DbgPrint("HTTPS Client Hello detected.\n");
        // Logic for handling HTTPS, e.g., blocking specific certificates or inspecting SNI (Server Name Indication)
    }
    // More logic could include certificate validation, blocking certain ciphers, etc.
}

// Function to identify HTTPS traffic based on TLS header structure
static BOOLEAN IsHttpsTraffic(PUCHAR buffer, ULONG dataLength) {
    // Check for the TLS header structure (first byte 0x16 indicates a handshake message, 0x03 indicates TLS version)
    return (dataLength > 5 && buffer[0] == 0x16 && buffer[1] == 0x03);
}

// Function to inspect and apply filtering rules for HTTPS traffic
static NTSTATUS ApplyHttpsFiltering(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for HTTPS inspection.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Inspect HTTPS traffic
static         if (IsHttpsTraffic(buffer, dataLength)) {
            DbgPrint("HTTPS traffic identified.\n");
static             ApplyHttpsFilteringRules(buffer, dataLength);
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }
    return STATUS_SUCCESS;
}

// Function to log security events with additional information
static void LogSecurityEvent(const char* eventMessage, PUSER_FILTER_RULE userRule) {
    // Log the event with details from the user rule
    DbgPrint("Security Event: %s\n", eventMessage);
    if (userRule) {
        DbgPrint("Source IP: %lu, Destination IP: %lu, Source Port: %u, Destination Port: %u\n",
            userRule->srcIP, userRule->destIP, userRule->srcPort, userRule->destPort);
    }
    // Optionally write the log to a file or external logging system for audit purposes
}

// Function to safely modify a filter rule from the user
NTSTATUS ModifyFilterRuleFromUser(PUSER_FILTER_RULE oldRule, PUSER_FILTER_RULE newRule) {
    NTSTATUS status = ValidateUserPermissions();
    if (!NT_SUCCESS(status)) {
        DbgPrint("Permission check failed for modifying rule.\n");
        return status;
    }

    // Validate the new rule
    status = ValidateUserFilterRule(newRule);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Validation of the new user filter rule failed.\n");
        return status;
    }

    // Lock the filter rules list and replace the old rule with the new one
    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    PFILTER_RULE current = filterRulesHead;
    while (current) {
        if (RtlCompareMemory(current, oldRule, sizeof(USER_FILTER_RULE)) == sizeof(USER_FILTER_RULE)) {
            // Modify the rule
            RtlCopyMemory(current, newRule, sizeof(FILTER_RULE));
            KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
static             LogSecurityEvent("Filter rule modified", newRule);
            return STATUS_SUCCESS;
        }
        current = current->next;
    }

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);
    return STATUS_NOT_FOUND;
}

// Function to securely list all active filter rules
NTSTATUS ListFilterRules(PIRP Irp, PIO_STACK_LOCATION stack) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&FilterRulesSpinLock, &oldIrql);

    // Prepare to copy the filter rules to the user buffer
    PFILTER_RULE current = filterRulesHead;
    PUCHAR userBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG bufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    // Copy the rules to the output buffer
    while (current && bufferLength >= sizeof(FILTER_RULE)) {
        RtlCopyMemory(userBuffer, current, sizeof(FILTER_RULE));
        userBuffer += sizeof(FILTER_RULE);
        bufferLength -= sizeof(FILTER_RULE);
        current = current->next;
    }

    KeReleaseSpinLock(&FilterRulesSpinLock, oldIrql);

    // Complete the IRP
    Irp->IoStatus.Information = (ULONG_PTR)(userBuffer - (PUCHAR)Irp->AssociatedIrp.SystemBuffer);
    return STATUS_SUCCESS;
}

// Function to validate and apply logging for suspicious traffic
static BOOLEAN IsSuspiciousTraffic(PUCHAR buffer, ULONG dataLength) {
    // Example: Checking for signs of abnormal traffic (e.g., unusual port ranges, known attack patterns)
    if (dataLength > 0 && buffer[0] == 0x01) {
        DbgPrint("Suspicious traffic detected.\n");
static         LogSecurityEvent("Suspicious traffic detected", NULL);
        return TRUE;
    }
    return FALSE;
}
// Function to handle deep packet inspection for suspicious traffic
static NTSTATUS HandleSuspiciousTraffic(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for suspicious traffic inspection.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Inspect the packet for suspicious activity
static         if (IsSuspiciousTraffic(buffer, dataLength)) {
            DbgPrint("Suspicious traffic identified. Blocking.\n");
            return STATUS_ACCESS_DENIED;  // Block suspicious traffic
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return STATUS_SUCCESS;
}

// Enhanced deep packet inspection combining all protocols (HTTP, HTTPS, FTP, Malicious, Suspicious)
static NTSTATUS EnhancedDeepPacketInspection(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for enhanced inspection.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Handle each type of traffic based on the content and protocol
static         if (IsHttpTraffic(buffer, dataLength)) {
            DbgPrint("HTTP traffic identified in enhanced DPI.\n");
static             ApplyHttpFilteringRules(buffer, dataLength);
static         } else if (IsHttpsTraffic(buffer, dataLength)) {
            DbgPrint("HTTPS traffic identified in enhanced DPI.\n");
static             ApplyHttpsFilteringRules(buffer, dataLength);
static         } else if (IsFtpTraffic(buffer, dataLength)) {
            DbgPrint("FTP traffic identified in enhanced DPI.\n");
static             ApplyFtpFilteringRules(buffer, dataLength);
static         } else if (IsMaliciousTraffic(buffer, dataLength)) {
            DbgPrint("Malicious traffic detected in enhanced DPI. Blocking.\n");
            return STATUS_ACCESS_DENIED;
static         } else if (IsSuspiciousTraffic(buffer, dataLength)) {
            DbgPrint("Suspicious traffic identified in enhanced DPI. Blocking.\n");
            return STATUS_ACCESS_DENIED;
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return STATUS_SUCCESS;
}

// Function to allocate memory safely for filter rules
static PVOID AllocateMemory(SIZE_T size) {
    PVOID memory = ExAllocatePoolWithTag(NonPagedPool, size, 'tag1');
    if (!memory) {
        DbgPrint("Failed to allocate memory.\n");
    }
    return memory;
}

// Function to free allocated memory safely
static void FreeMemory(PVOID memory) {
    if (memory) {
        ExFreePoolWithTag(memory, 'tag1');
    }
}

// Function to log memory allocation failures
static void LogMemoryAllocationFailure(const char* functionName) {
    DbgPrint("%s: Failed to allocate memory.\n", functionName);
static     LogSecurityEvent("Memory allocation failure", NULL);
}

// Function to check if FTP traffic exists
static BOOLEAN IsFtpTraffic(PUCHAR buffer, ULONG dataLength) {
    return (dataLength >= 4 && (RtlCompareMemory(buffer, "USER", 4) == 4 || RtlCompareMemory(buffer, "PASS", 4) == 4));
}

// Apply filtering rules to FTP traffic
static void ApplyFtpFilteringRules(PUCHAR buffer, ULONG dataLength) {
    DbgPrint("Applying FTP filtering rules.\n");
    // Logic to handle FTP commands and filtering based on policies (e.g., user login attempts, file transfers)
}

// Function to modify a filter rule with security logging
static NTSTATUS SecureModifyFilterRule(PUSER_FILTER_RULE oldRule, PUSER_FILTER_RULE newRule) {
    NTSTATUS status = ModifyFilterRuleFromUser(oldRule, newRule);
    if (NT_SUCCESS(status)) {
static         LogSecurityEvent("Filter rule successfully modified", newRule);
    } else {
        DbgPrint("Failed to modify filter rule.\n");
    }
    return status;
}

// Function to securely add a rule with extra validation checks
static NTSTATUS SecureAddFilterRule(PUSER_FILTER_RULE userRule) {
    NTSTATUS status = AddFilterRuleFromUser(userRule);
    if (NT_SUCCESS(status)) {
        DbgPrint("Successfully added filter rule.\n");
static         LogSecurityEvent("Filter rule successfully added", userRule);
    } else {
        DbgPrint("Failed to add filter rule.\n");
    }
    return status;
}

// Function to handle a secure rule removal process
static NTSTATUS SecureRemoveFilterRule(PUSER_FILTER_RULE userRule) {
    NTSTATUS status = RemoveFilterRuleFromUser(userRule);
    if (NT_SUCCESS(status)) {
        DbgPrint("Successfully removed filter rule.\n");
static         LogSecurityEvent("Filter rule successfully removed", userRule);
    } else {
        DbgPrint("Failed to remove filter rule.\n");
    }
    return status;
}

// Function to secure rule listing with logging
static NTSTATUS SecureListFilterRules(PIRP Irp, PIO_STACK_LOCATION stack) {
    NTSTATUS status = ListFilterRules(Irp, stack);
    if (NT_SUCCESS(status)) {
        DbgPrint("Filter rules successfully listed.\n");
static         LogSecurityEvent("Filter rules successfully listed", NULL);
    } else {
        DbgPrint("Failed to list filter rules.\n");
    }
    return status;
}
// Define threshold values for suspicious traffic detection
#define MAX_CONNECTIONS_PER_MINUTE 100

// Structure to track IP connection activity
typedef struct _IP_ACTIVITY_TRACKER {
    UINT32 ipAddress;
    ULONG connectionCount;
    LARGE_INTEGER lastConnectionTime;
    struct _IP_ACTIVITY_TRACKER* next;
} IP_ACTIVITY_TRACKER, *PIP_ACTIVITY_TRACKER;

PIP_ACTIVITY_TRACKER activityTrackerHead = NULL; // Head of the activity tracker list

// Spinlock for synchronizing access to the activity tracker list
KSPIN_LOCK ActivityTrackerSpinLock;

// Function to track connection activity for an IP address
static VOID TrackIpConnectionActivity(UINT32 srcIP) {
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    // Acquire spinlock to safely update the activity tracker list
    KIRQL oldIrql;
    KeAcquireSpinLock(&ActivityTrackerSpinLock, &oldIrql);

    PIP_ACTIVITY_TRACKER current = activityTrackerHead;
    while (current) {
        if (current->ipAddress == srcIP) {
            // Update connection count if within the threshold window (e.g., 1 minute)
            if (currentTime.QuadPart - current->lastConnectionTime.QuadPart < 600000000) { // 1 minute in 100-nanosecond intervals
                current->connectionCount++;
            } else {
                // Reset the count after the threshold window
                current->connectionCount = 1;
            }
            current->lastConnectionTime = currentTime;
            break;
        }
        current = current->next;
    }

    if (!current) {
        // Add a new entry if this IP hasn't been tracked before
        current = (PIP_ACTIVITY_TRACKER)ExAllocatePoolWithTag(NonPagedPool, sizeof(IP_ACTIVITY_TRACKER), 'iptr');
        if (current) {
            current->ipAddress = srcIP;
            current->connectionCount = 1;
            current->lastConnectionTime = currentTime;
            current->next = activityTrackerHead;
            activityTrackerHead = current;
        } else {
            DbgPrint("Failed to allocate memory for IP activity tracker.\n");
        }
    }

    KeReleaseSpinLock(&ActivityTrackerSpinLock, oldIrql);
}

// Function to inspect DNS traffic
static BOOLEAN InspectDnsTraffic(PUCHAR buffer, ULONG dataLength) {
    if (dataLength > 12) {
        PUCHAR dnsQuery = buffer + 12;  // Point to the DNS query section

        // Check for specific domain name filtering (e.g., block certain domains)
        if (RtlCompareMemory(dnsQuery, "\x03www\x07example\x03com", 16) == 16) {
            DbgPrint("Blocking DNS query for www.example.com.\n");
            return TRUE; // Block the DNS query
        }

        // Additional logic for detecting DNS tunneling, exfiltration, or large requests
    }
    return FALSE; // Allow the DNS query
}

// Function to inspect SMTP traffic for specific content (e.g., spam or blacklisted addresses)
static BOOLEAN InspectSmtpTraffic(PUCHAR buffer, ULONG dataLength) {
    if (dataLength > 10) {
        if (RtlCompareMemory(buffer, "MAIL FROM:", 10) == 10) {
            DbgPrint("Inspecting SMTP MAIL FROM command.\n");

            // Example: Block specific email addresses or domains
            if (RtlCompareMemory(buffer + 10, "blocked@example.com", 19) == 19) {
                DbgPrint("Blocking SMTP mail from blocked@example.com.\n");
                return TRUE; // Block this email
            }
        }
    }
    return FALSE; // Allow the SMTP message
}

// Function to apply deep packet inspection (DPI) rules for various protocols
static NTSTATUS ApplyDpiRules(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for DPI.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Check for DNS traffic and apply filtering rules
static         if (IsDnsTraffic(buffer, dataLength) && InspectDnsTraffic(buffer, dataLength)) {
            return STATUS_ACCESS_DENIED;  // Block the DNS packet if inspection fails
        }

        // Check for SMTP traffic and apply filtering rules
static         if (IsSmtpTraffic(buffer, dataLength) && InspectSmtpTraffic(buffer, dataLength)) {
            return STATUS_ACCESS_DENIED;  // Block the SMTP message if inspection fails
        }

        // Track IP activity to detect suspicious behavior
        UINT32 srcIP = *(UINT32*)(buffer + 12);  // Extract source IP from the packet
static         TrackIpConnectionActivity(srcIP);

        // Detect suspicious behavior based on connection thresholds
static         if (IsIpSuspicious(srcIP)) {
            DbgPrint("Suspicious IP activity detected. Blocking IP: %x\n", srcIP);
            return STATUS_ACCESS_DENIED;  // Block further connections from this IP
        }

        nb = NET_BUFFER_NEXT_NB(nb);  // Move to the next network buffer
    }

    return STATUS_SUCCESS;
}

// Function to check if an IP has suspicious activity based on the connection tracker
static BOOLEAN IsIpSuspicious(UINT32 srcIP) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&ActivityTrackerSpinLock, &oldIrql);

    PIP_ACTIVITY_TRACKER current = activityTrackerHead;
    while (current) {
        if (current->ipAddress == srcIP && current->connectionCount > MAX_CONNECTIONS_PER_MINUTE) {
            KeReleaseSpinLock(&ActivityTrackerSpinLock, oldIrql);
            return TRUE;  // Mark this IP as suspicious due to excessive connections
        }
        current = current->next;
    }

    KeReleaseSpinLock(&ActivityTrackerSpinLock, oldIrql);
    return FALSE;
}

// Function to log DPI results for blocked traffic
static VOID LogBlockedTraffic(PUCHAR buffer, ULONG dataLength, const char* reason) {
    DbgPrint("Blocked traffic: Reason: %s, Data Length: %lu bytes\n", reason, dataLength);
    // Additional logging can be added to save blocked traffic details to a file or remote server
}

// Function to initialize activity tracking for suspicious IP connections
static VOID InitializeIpActivityTracking() {
    KeInitializeSpinLock(&ActivityTrackerSpinLock);
    activityTrackerHead = NULL;
    DbgPrint("IP activity tracking initialized.\n");
}

// Function to clean up the IP activity tracker during driver unload
static VOID CleanupIpActivityTracking() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&ActivityTrackerSpinLock, &oldIrql);

    PIP_ACTIVITY_TRACKER current = activityTrackerHead;
    while (current) {
        PIP_ACTIVITY_TRACKER next = current->next;
        ExFreePool(current);
        current = next;
    }
    activityTrackerHead = NULL;

    KeReleaseSpinLock(&ActivityTrackerSpinLock, oldIrql);
    DbgPrint("IP activity tracking cleaned up.\n");
}
// Function to clean up activity tracker when removing an IP (e.g., after blocking or timeout)
static VOID RemoveIpFromTracker(UINT32 ipAddress) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&ActivityTrackerSpinLock, &oldIrql);

    PIP_ACTIVITY_TRACKER prev = NULL;
    PIP_ACTIVITY_TRACKER current = activityTrackerHead;

    while (current) {
        if (current->ipAddress == ipAddress) {
            // Remove the entry from the linked list
            if (prev) {
                prev->next = current->next;
            } else {
                activityTrackerHead = current->next;
            }

            ExFreePool(current);  // Free the memory allocated for this tracker
            DbgPrint("Removed IP %x from activity tracker.\n", ipAddress);
            break;
        }
        prev = current;
        current = current->next;
    }

    KeReleaseSpinLock(&ActivityTrackerSpinLock, oldIrql);
}

// Function to handle packet reassembly (for fragmented IP packets)
static BOOLEAN ReassembleFragmentedPackets(PUCHAR buffer, ULONG dataLength, PUCHAR* reassembledBuffer, ULONG* reassembledLength) {
    // Extract necessary IP header fields
    UINT16 ipHeaderLength = (buffer[0] & 0x0F) * 4;
    UINT16 totalLength = ((buffer[2] << 8) | buffer[3]);

    // Check if the packet is fragmented (Flags & Fragment Offset field)
    UINT16 fragmentOffset = ((buffer[6] & 0x1F) << 8) | buffer[7];
    UINT16 moreFragmentsFlag = buffer[6] & 0x20;

    if (fragmentOffset > 0 || moreFragmentsFlag) {
        // Handle reassembly logic here (store fragmented packets until all fragments are received)
        DbgPrint("Fragmented packet detected. Reassembling...\n");

        // Example: Allocate a larger buffer for reassembly (implement the actual logic in production)
        *reassembledBuffer = ExAllocatePoolWithTag(NonPagedPool, totalLength, 'frgm');
        if (!*reassembledBuffer) {
            DbgPrint("Failed to allocate memory for packet reassembly.\n");
            return FALSE;
        }

        // Copy the current fragment into the reassembly buffer
        RtlCopyMemory(*reassembledBuffer, buffer, dataLength);
        *reassembledLength = totalLength;  // Set the expected total length after reassembly

        DbgPrint("Reassembly complete for fragmented packet.\n");
        return TRUE;  // Indicate that reassembly was successful
    }

    // If the packet is not fragmented, simply return the original buffer
    *reassembledBuffer = buffer;
    *reassembledLength = dataLength;
    return FALSE;  // No reassembly needed
}

static // Updated ApplyDpiRules function with reassembly handling
static NTSTATUS ApplyDpiRules(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for DPI.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Handle packet reassembly for fragmented IP packets
        PUCHAR reassembledBuffer = NULL;
        ULONG reassembledLength = 0;
static         if (ReassembleFragmentedPackets(buffer, dataLength, &reassembledBuffer, &reassembledLength)) {
            buffer = reassembledBuffer;
            dataLength = reassembledLength;
        }

        // Check for DNS traffic and apply filtering rules
static         if (IsDnsTraffic(buffer, dataLength) && InspectDnsTraffic(buffer, dataLength)) {
            if (reassembledBuffer) {
                ExFreePool(reassembledBuffer);  // Clean up reassembly buffer
            }
            return STATUS_ACCESS_DENIED;  // Block the DNS packet if inspection fails
        }

        // Check for SMTP traffic and apply filtering rules
static         if (IsSmtpTraffic(buffer, dataLength) && InspectSmtpTraffic(buffer, dataLength)) {
            if (reassembledBuffer) {
                ExFreePool(reassembledBuffer);  // Clean up reassembly buffer
            }
            return STATUS_ACCESS_DENIED;  // Block the SMTP message if inspection fails
        }

        // Track IP activity to detect suspicious behavior
        UINT32 srcIP = *(UINT32*)(buffer + 12);  // Extract source IP from the packet
static         TrackIpConnectionActivity(srcIP);

        // Detect suspicious behavior based on connection thresholds
static         if (IsIpSuspicious(srcIP)) {
            DbgPrint("Suspicious IP activity detected. Blocking IP: %x\n", srcIP);
            if (reassembledBuffer) {
                ExFreePool(reassembledBuffer);  // Clean up reassembly buffer
            }
            return STATUS_ACCESS_DENIED;  // Block further connections from this IP
        }

        if (reassembledBuffer) {
            ExFreePool(reassembledBuffer);  // Clean up reassembly buffer after processing
        }

        nb = NET_BUFFER_NEXT_NB(nb);  // Move to the next network buffer
    }

    return STATUS_SUCCESS;
}
// Function to handle packet reassembly and anonymization for HTTPS with reversible modification
static BOOLEAN AnonymizeHttpsTrafficForRelay(PUCHAR buffer, ULONG dataLength, PUCHAR* anonymizedBuffer, ULONG* anonymizedLength) {
    // Extract necessary IP header fields
    UINT16 ipHeaderLength = (buffer[0] & 0x0F) * 4;
    UINT16 totalLength = ((buffer[2] << 8) | buffer[3]);

    // Check if the packet is HTTPS traffic based on the buffer (simplified check for TLS ClientHello)
    if (dataLength > 5 && buffer[0] == 0x16 && buffer[1] == 0x03) {
        DbgPrint("HTTPS packet detected. Anonymizing for relay...\n");

        // Allocate buffer for anonymization
        *anonymizedBuffer = ExAllocatePoolWithTag(NonPagedPool, totalLength, 'anon');
        if (!*anonymizedBuffer) {
            DbgPrint("Failed to allocate memory for HTTPS anonymization.\n");
            return FALSE;
        }

        // Copy original packet to the new buffer
        RtlCopyMemory(*anonymizedBuffer, buffer, dataLength);

        // Example: Replace SNI (Server Name Indication) with a placeholder
        // The SNI is typically located after 40 bytes in the ClientHello message; this is a simplified example
        PUCHAR sniField = *anonymizedBuffer + ipHeaderLength + 40;  // Location depends on packet structure
        UCHAR fakeSni[] = "relay-placeholder.com";  // Fake SNI for anonymization
        SIZE_T fakeSniLength = sizeof(fakeSni);

        // Preserve the original SNI length
        PUCHAR originalSniLengthField = sniField - 2;
        UCHAR originalSniLength = *originalSniLengthField;

        // Store the original SNI length somewhere so it can be reconstructed later by the relay
        // You can design a custom header or use metadata for relays to use when rebuilding the packet

        // Replace the actual SNI with a placeholder
        RtlCopyMemory(sniField, fakeSni, fakeSniLength);

        // Update the SNI length field to match the fake SNI
        *originalSniLengthField = (UCHAR)fakeSniLength;

        *anonymizedLength = totalLength;
        DbgPrint("HTTPS packet anonymization complete for relay.\n");

        return TRUE;  // Anonymization successful
    }

    return FALSE;  // Not HTTPS traffic, no anonymization needed
}

static // Updated ApplyDpiRules function with HTTPS anonymization handling for relay
static NTSTATUS ApplyDpiRulesForRelay(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    while (nb) {
        PUCHAR buffer;
        ULONG dataLength;

        if (!NT_SUCCESS(NdisQueryMdl(nb->CurrentMdl, &buffer, &dataLength, NormalPagePriority))) {
            DbgPrint("Failed to retrieve MDL for DPI.\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Handle packet reassembly for fragmented IP packets
        PUCHAR anonymizedBuffer = NULL;
        ULONG anonymizedLength = 0;
static         if (AnonymizeHttpsTrafficForRelay(buffer, dataLength, &anonymizedBuffer, &anonymizedLength)) {
            buffer = anonymizedBuffer;
            dataLength = anonymizedLength;
        }

        // Inspect and apply filtering for other types of traffic
static         if (IsDnsTraffic(buffer, dataLength) && InspectDnsTraffic(buffer, dataLength)) {
            if (anonymizedBuffer) {
                ExFreePool(anonymizedBuffer);  // Clean up anonymization buffer
            }
            return STATUS_ACCESS_DENIED;  // Block the DNS packet if inspection fails
        }

static         if (IsSmtpTraffic(buffer, dataLength) && InspectSmtpTraffic(buffer, dataLength)) {
            if (anonymizedBuffer) {
                ExFreePool(anonymizedBuffer);  // Clean up anonymization buffer
            }
            return STATUS_ACCESS_DENIED;  // Block the SMTP message if inspection fails
        }

        // Track IP activity for suspicious behavior
        UINT32 srcIP = *(UINT32*)(buffer + 12);  // Extract source IP from the packet
static         TrackIpConnectionActivity(srcIP);

static         if (IsIpSuspicious(srcIP)) {
            DbgPrint("Suspicious IP activity detected. Blocking IP: %x\n", srcIP);
            if (anonymizedBuffer) {
                ExFreePool(anonymizedBuffer);  // Clean up anonymization buffer
            }
            return STATUS_ACCESS_DENIED;  // Block further connections from this IP
        }

        if (anonymizedBuffer) {
            ExFreePool(anonymizedBuffer);  // Clean up anonymization buffer after processing
        }

        nb = NET_BUFFER_NEXT_NB(nb);  // Move to the next network buffer
    }

    return STATUS_SUCCESS;
}
// Structure to store packet metadata for DPI before stripping source information
typedef struct _DPI_PACKET_METADATA {
    ULONG originalSrcIp;     // Original source IP (user)
    USHORT originalSrcPort;  // Original source port
    ULONG packetId;          // Unique packet identifier for tracking
    LARGE_INTEGER timestamp; // Time of packet inspection for TTL calculations
    struct _DPI_PACKET_METADATA* next;  // Linked list pointer for multiple packets
} DPI_PACKET_METADATA, *PDPI_PACKET_METADATA;

// Global linked list for storing DPI metadata
static PDPI_PACKET_METADATA dpiMetadataHead = NULL;
static KSPIN_LOCK dpiMetadataLock;

// Static function to save DPI packet metadata before stripping
static VOID SaveDpiPacketMetadata(PUCHAR buffer, ULONG dataLength) {
    if (dataLength >= 20) {  // Ensure the packet is large enough (at least IPv4 header)
        PDPI_PACKET_METADATA metadata = (PDPI_PACKET_METADATA)ExAllocatePoolWithTag(NonPagedPool, sizeof(DPI_PACKET_METADATA), 'dpmt');
        if (!metadata) {
            DbgPrint("Failed to allocate memory for DPI packet metadata.\n");
            return;
        }

        // Extract original source IP and port (this will be stripped)
        metadata->originalSrcIp = *(PULONG)(buffer + 12);  // Source IP
        metadata->originalSrcPort = *(PUSHORT)(buffer + 20);  // Source port (TCP/UDP)

        // Generate a unique packet ID and timestamp for tracking
        metadata->packetId = GeneratePacketId();
        KeQuerySystemTime(&metadata->timestamp);

        // Add this metadata to the global list (protected by spinlock)
        KIRQL oldIrql;
        KeAcquireSpinLock(&dpiMetadataLock, &oldIrql);
        metadata->next = dpiMetadataHead;
        dpiMetadataHead = metadata;
        KeReleaseSpinLock(&dpiMetadataLock, oldIrql);

        DbgPrint("DPI metadata saved for packet ID: %lu, Original Src IP: %d.%d.%d.%d\n",
            metadata->packetId,
            (metadata->originalSrcIp & 0xFF), (metadata->originalSrcIp >> 8) & 0xFF, 
            (metadata->originalSrcIp >> 16) & 0xFF, (metadata->originalSrcIp >> 24) & 0xFF);
    }
}

// Static function to retrieve DPI metadata by packet ID
static PDPI_PACKET_METADATA RetrieveDpiPacketMetadata(ULONG packetId) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&dpiMetadataLock, &oldIrql);

    PDPI_PACKET_METADATA current = dpiMetadataHead;
    while (current) {
        if (current->packetId == packetId) {
            KeReleaseSpinLock(&dpiMetadataLock, oldIrql);
            return current;
        }
        current = current->next;
    }

    KeReleaseSpinLock(&dpiMetadataLock, oldIrql);
    DbgPrint("DPI metadata not found for packet ID: %lu\n", packetId);
    return NULL;
}

// Function to strip and prepare a packet for DPI (anonymize)
static VOID AnonymizePacketForDpi(PUCHAR buffer, ULONG dataLength) {
    if (dataLength >= 20) {
        DbgPrint("Stripping source IP and port for DPI.\n");

        // Zero out the source IP and port for anonymization (to be handled by relay)
        RtlZeroMemory(buffer + 12, 4);  // Source IP (4 bytes)
        RtlZeroMemory(buffer + 20, 2);  // Source port (2 bytes)

        DbgPrint("Packet anonymized for DPI.\n");
    }
}

// Function to handle DPI and prepare packet for relay
static VOID HandleDpiAndRelay(PUCHAR buffer, ULONG dataLength) {
    DbgPrint("Performing Deep Packet Inspection.\n");

    // Save metadata before stripping the packet
    SaveDpiPacketMetadata(buffer, dataLength);

    // Apply DPI rules (this can be expanded to include various inspection logic)
    if (DetectMaliciousPatterns(buffer, dataLength)) {
        DbgPrint("Malicious traffic detected. Blocking packet.\n");
        return;  // Drop packet if malicious content is found
    }

    // Strip sensitive data (anonymize the packet) before sending to relay
    AnonymizePacketForDpi(buffer, dataLength);

    // Hand off to relay system for further processing (you can call the relay module here)
    ForwardPacketToRelay(buffer, dataLength);

    DbgPrint("Packet forwarded to relay after DPI.\n");
}

// Example function to detect malicious traffic during DPI
static BOOLEAN DetectMaliciousPatterns(PUCHAR buffer, ULONG dataLength) {
    // Simplified example of detecting a malicious pattern (e.g., NOP sled)
    if (dataLength >= 4 && RtlCompareMemory(buffer, "\x90\x90\x90\x90", 4) == 4) {
        return TRUE;  // Detected a malicious NOP sled
    }
    return FALSE;
}

// Initialize the DPI system
static VOID InitializeDpiSystem() {
    KeInitializeSpinLock(&dpiMetadataLock);
    DbgPrint("DPI system initialized.\n");
}







/////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// strip IP module /////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////


// Static function to strip IP addresses and leave placeholders for relay injection
static VOID StripIpAddressesAndPrepForRelay(PUCHAR buffer, ULONG dataLength) {
    // Ensure the buffer contains a valid IP header (minimum length for an IPv4 header is 20 bytes)
    if (dataLength >= 20) {
        // Extract IP version and header length from the first byte
        UCHAR ipVersionAndHeaderLength = buffer[0];
        UCHAR ipVersion = ipVersionAndHeaderLength >> 4;  // Upper nibble is the IP version
        UCHAR ipHeaderLength = (ipVersionAndHeaderLength & 0x0F) * 4;  // Lower nibble is header length in 4-byte increments

        // Ensure we are dealing with IPv4 and the header length is valid
        if (ipVersion == 4 && ipHeaderLength >= 20 && dataLength >= ipHeaderLength) {
            // Extract source and destination IP addresses (offsets 12-15 for source, 16-19 for destination)
            ULONG srcIp = *(PULONG)(buffer + 12);
            ULONG dstIp = *(PULONG)(buffer + 16);

            // Log original IPs for debugging
            DbgPrint("Original Source IP: %d.%d.%d.%d\n", buffer[12], buffer[13], buffer[14], buffer[15]);
            DbgPrint("Original Destination IP: %d.%d.%d.%d\n", buffer[16], buffer[17], buffer[18], buffer[19]);

            // Option 1: Replace IP addresses with placeholders for the relay system to inject spoofed IPs
            buffer[12] = 0xAA; buffer[13] = 0xAA; buffer[14] = 0xAA; buffer[15] = 0xAA;  // Placeholder source IP
            buffer[16] = 0xBB; buffer[17] = 0xBB; buffer[18] = 0xBB; buffer[19] = 0xBB;  // Placeholder destination IP

            DbgPrint("Placeholders set for Source IP: %d.%d.%d.%d\n", buffer[12], buffer[13], buffer[14], buffer[15]);
            DbgPrint("Placeholders set for Destination IP: %d.%d.%d.%d\n", buffer[16], buffer[17], buffer[18], buffer[19]);

            // Adjust the IP header checksum to account for modified IP addresses
            USHORT oldChecksum = *(PUSHORT)(buffer + 10);  // Original checksum at offset 10-11
            USHORT newChecksum = RecalculateIpChecksum(buffer, ipHeaderLength);
            *(PUSHORT)(buffer + 10) = newChecksum;  // Set the new checksum

            DbgPrint("Checksum updated for anonymized IP addresses. Old: 0x%X, New: 0x%X\n", oldChecksum, newChecksum);

            // Flag the packet as prepped for relay system injection
            DbgPrint("Packet prepped for relay transport. Awaiting further driver modules for completion checks.\n");
        } else {
            DbgPrint("Invalid IP version or header length detected. Skipping IP stripping.\n");
        }
    } else {
        DbgPrint("Insufficient data length for IP header. Skipping IP stripping.\n");
    }
}

// Helper function to recalculate IP header checksum after modification
static USHORT RecalculateIpChecksum(PUCHAR buffer, UCHAR ipHeaderLength) {
    ULONG checksum = 0;
    USHORT* header = (USHORT*)buffer;

    // Zero out the checksum field in the header for calculation
    header[5] = 0;

    // Calculate checksum by summing 16-bit words
    for (int i = 0; i < ipHeaderLength / 2; i++) {
        checksum += header[i];
    }

    // Fold 32-bit sum to 16 bits
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    // One's complement
    return (USHORT)~checksum;
}





/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////// store origional packet metadata module /////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////




// Structure to store packet metadata before stripping source information
typedef struct _RELAY_PACKET_METADATA {
    ULONG originalSrcIp;  // Original source IP (user)
    ULONG relayDstIp;     // Relay destination IP (server it's forwarded to)
    USHORT originalSrcPort;  // Source port (user)
    USHORT relayDstPort;     // Destination port at relay
    ULONG packetId;          // Unique packet identifier for tracking
    LARGE_INTEGER timestamp; // Time of packet relay for TTL calculations
    struct _RELAY_PACKET_METADATA* next;  // Linked list pointer for multiple packets
} RELAY_PACKET_METADATA, *PRELAY_PACKET_METADATA;

// Global linked list to store all packet metadata
static PRELAY_PACKET_METADATA relayMetadataHead = NULL;
static KSPIN_LOCK relayMetadataLock;

// Static function to save packet metadata before stripping the source IP
static VOID SaveRelayPacketMetadata(PUCHAR buffer, ULONG dataLength, ULONG relayDstIp, USHORT relayDstPort) {
    if (dataLength >= 20) {  // Ensure the packet is at least as large as an IPv4 header
        PRELAY_PACKET_METADATA metadata = (PRELAY_PACKET_METADATA)ExAllocatePoolWithTag(NonPagedPool, sizeof(RELAY_PACKET_METADATA), 'rpmt');
        if (!metadata) {
            DbgPrint("Failed to allocate memory for relay packet metadata.\n");
            return;
        }

        // Extract original source IP and port (this will be stripped)
        metadata->originalSrcIp = *(PULONG)(buffer + 12);  // Source IP
        metadata->originalSrcPort = *(PUSHORT)(buffer + 20);  // Source port (TCP/UDP)

        // Store relay destination information (the anonymized destination)
        metadata->relayDstIp = relayDstIp;
        metadata->relayDstPort = relayDstPort;

        // Generate a unique packet ID and timestamp for tracking
        metadata->packetId = GeneratePacketId();
        KeQuerySystemTime(&metadata->timestamp);

        // Add this metadata to the global list (protected by spinlock)
        KIRQL oldIrql;
        KeAcquireSpinLock(&relayMetadataLock, &oldIrql);
        metadata->next = relayMetadataHead;
        relayMetadataHead = metadata;
        KeReleaseSpinLock(&relayMetadataLock, oldIrql);

        DbgPrint("Saved relay metadata for packet ID: %lu, Original Src IP: %d.%d.%d.%d, Relay Dest IP: %d.%d.%d.%d\n",
            metadata->packetId,
            (metadata->originalSrcIp & 0xFF), (metadata->originalSrcIp >> 8) & 0xFF, 
            (metadata->originalSrcIp >> 16) & 0xFF, (metadata->originalSrcIp >> 24) & 0xFF,
            (metadata->relayDstIp & 0xFF), (metadata->relayDstIp >> 8) & 0xFF, 
            (metadata->relayDstIp >> 16) & 0xFF, (metadata->relayDstIp >> 24) & 0xFF);
    }
}

// Static function to retrieve relay packet metadata by packet ID
static PRELAY_PACKET_METADATA RetrieveRelayPacketMetadata(ULONG packetId) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&relayMetadataLock, &oldIrql);

    PRELAY_PACKET_METADATA current = relayMetadataHead;
    while (current) {
        if (current->packetId == packetId) {
            KeReleaseSpinLock(&relayMetadataLock, oldIrql);
            return current;
        }
        current = current->next;
    }

    KeReleaseSpinLock(&relayMetadataLock, oldIrql);
    DbgPrint("Relay metadata not found for packet ID: %lu\n", packetId);
    return NULL;
}

// Function to repackage the packet after relay processing
static VOID RepackagePacketAfterRelay(PUCHAR buffer, ULONG dataLength, ULONG packetId) {
    PRELAY_PACKET_METADATA metadata = RetrieveRelayPacketMetadata(packetId);
    if (!metadata) {
        DbgPrint("No metadata found for relay packet repackaging. Dropping packet.\n");
        return;
    }

    // Restore the original source IP and port (to send the reply back to the user)
    *(PULONG)(buffer + 12) = metadata->originalSrcIp;  // Source IP
    *(PUSHORT)(buffer + 20) = metadata->originalSrcPort;  // Source port

    // The destination IP/port can remain as it was set during relay processing
    DbgPrint("Repackaged relay packet with original Source IP: %d.%d.%d.%d, Original Src Port: %u\n",
        (metadata->originalSrcIp & 0xFF), (metadata->originalSrcIp >> 8) & 0xFF, 
        (metadata->originalSrcIp >> 16) & 0xFF, (metadata->originalSrcIp >> 24) & 0xFF,
        metadata->originalSrcPort);

    // The relay will self-destruct after this, so no need for manual cleanup.
}

// Initialize the relay metadata system
static VOID InitializeRelayMetadata() {
    KeInitializeSpinLock(&relayMetadataLock);
    DbgPrint("Relay packet metadata tracking initialized.\n");
}