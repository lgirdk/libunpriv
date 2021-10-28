# Why do we need to drop root privilege?

The root user is the most privileged user in a Linux system and has complete access to all the files, commands as well as the power to change the permissions to read/write/execute specific files or directories to other users in the system. Thus it is easy to damage the system with root access.
All processes started by root user have root privileges as well. If a minor bug arises in the process when it is run as a root, it may be exploited by a skilled attacker to gain control of the entire system with root privileges. This results in vulnerability of the system, as the attacker could modify the key system files and change the system in any desired way, thereby exploiting the entire data in it. 

# Alternate ways to secure processes: 
• Removing supplementary groups that the root user may belong, by using the init-groups function. This prevents unnecessary access to data. 

• The current working directory may be the root directory which is the parent directory to all directories in the system. It could be changed to a safer directory using chdir function. Alternatively, the root directory could also be moved elsewhere using chroot function.

• A special group could be created and the file’s ownership could be changed to it. The program could set its group id using setgid function to that group, since group ownership grants fewer rights to change the file permissions.

• Mandatory Access Control (MAC) systems like SElinux and Apparmor can be used to restrict the root user’s privileges. These systems have a central policy enforced by the OS which prevents even the root user from performing certain operations in the system.

• Processes could be run as non-root user. As non-privileged user can only access data that are owned by them, their group, or which is marked for access by all the users.

# Dropping process privileges using Capabilities – Introduction:

• When the process is run as non-root user the problem is that, at some point in time our process needs a little bit more permissions to fulfill its duties. But granting root permissions for this purpose puts the entire system at risk.

• The goal of capabilities is to divide the power of ‘root’ into specific privileges, so that if a process or binary that has one or more capability is exploited, the potential damage is limited when compared to the same process running as root.

• Normal users can not open a socket, as this requires root permissions. To start listening on one of the lower ports (<1024), you need root permissions. This web server daemon needs to be able to listen to port 80. However, it does not need access to kernel modules as that would be a serious threat to the integrity of the system. Instead of giving this daemon all root permissions, we can set a capability on the related binary, like CAP_NET_BIND_SERVICE. With this specific capability, it can open up port 80. 


# Process capabilities:
• Each Linux process has four sets of bitmaps called the effective (E), permitted (P), inheritable (I), and bset capabilities. Each capability is implemented as a bit in each of these bitmaps, which is either set or unset.

![](images/kernel_cap_struct_header.png)

• The constant KERNEL CAPABILITY U32S indicates how many capabilities the kernel has, it would be defined to be 2 if kernel has more than 32 capabilities, otherwise, 1. 

• The effective capability set indicates what capabilities are being currently set. When a process tries to do a privileged operation, the operating system will check the appropriate bit in the effective set of the process (instead of checking whether the effective uid of the process i 0 as is normally done). For example, when a process tries to set the clock, the Linux kernel will check that the process has the CAP SYS TIME bit (which is currently bit 25) set in its effective set. 

• The permitted capability set indicates what capabilities the process has the right to use. The process can have capabilities set in the permitted set that are not in the effective set. This indicates that the process has temporarily disabled this capability. 

• A process is allowed to set a bit in its effective set as well as inherited set only if it is available in its permitted set. The distinction between effective and permitted makes it possible for a process to disable, enable and drop privileges. 

• The inheritable capability set indicates what capabilities of the current process should be inherited by the program executed by the current process i.e. child processes to the program. 

• More about capabilities: http://man7.org/linux/man-pages/man7/capabilities.7.html

# Approach: 

Implemented a custom library (libprivilege.so) which internally uses libcap which is a POSIX.1e library for getting and setting capabilities. Added a new component libunpriv, libunpriv.bb which would fetch the code from (${RDK_GENERIC_ROOT_GIT}/libunpriv/generic above repo and generate libprivilege.so.

## Prerequisites:
libprivilege library dependes on libcap library. libcap or linux capabilities provide fine-grained control over super-user permissions, allowing use of the root user to be avoided.

# Implementation:

• Libprivilege when invoked would read the process-capabilities.json and apply the required capabilities to the process. 

• By default the following capabilities would be assigned to the process - CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FSETID, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_IPC_LOCK, CAP_SETPCAP.

• Apart from the default list if any process specific capabilities are identified by either code walkthrough or any other tools like apparmor, strace it needs to be added to process-capabilities.json and similarly if any capabilities that are present in default cap list are not required can be added to drop list.


## Process-capabilities.json

![](images/process-capabilities.png)

## API:

/* Check whether calling process is Blocklisted or not */ 
bool isBlocklisted(void);

/* to fetch the RFC value */ 
bool fetchRFC(char* key,char** value);

/* initializes cap_t structure */ 
cap_t init_capability(void);

/* Read the current capability of process */ 
cap_user read_capability(cap_user *);

/* Drop the capabilities of process based on cap_user structure */ 
void drop_root_caps(cap_user *);

/* Applying process/application specific capabilities */ 
int update_process_caps(cap_user *);

## Steps to be followed to convert a process as non-root:
• Identify the capabilities required for the process using apparmor , strace or code walkthrough.

• Ensure process name is not present in Blocklist string "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.NonRootSupport.Blocklist".

• Add the processes specific tag in process-capabilities.json with allow and drop caps.

• Define cap_user structure and Initialize it using init_capability().

• drop_root_caps(&appcaps) -> Reads the default and process specific capabilities from cjson file and applies the default caps

• update_process_caps(&appcaps) -> Applies the process specific capabilities

• read_capability(&appcaps) -> Reads and dumps the current process capabilities and dumps to log file.

## Blocklist Mechanism:

• RFC: Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.NonRootSupport.Blocklist.

• By Default, Blocklist String will be "Empty".

• The Calling Process will run in Nonroot Mode in two conditions:
    • Blocklist string does not contain the process name.
    • Blocklist RFC is empty.
    
• If particular process added in Blocklist String, then it will be executed in Root mode.

# Sequence Diagram:

![](images/SequenceDiagram.png)

## Debugging:

Log file CapDebug.txt will contain the logs 

root@Docsis-Gateway:~# cat /rdklogs/logs/CapDebug.txt 
Thu Jul 30 06:11:05 2020[non-root]:Dropping root privilege of CcspCrSsp: runs as unprivilege mode 

Thu Jul 30 06:11:05 2020[non-root]:unprivilege user name: non-root 

Thu Jul 30 06:11:05 2020[non-root]:Dumping current caps of the process: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fsetid,cap_kill,cap_setpcap,cap_net_bind_service,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_sys_admin+eip cap_fowner,cap_setgid,cap_setuid,cap_linux_immutable,cap_net_broadcast,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37+p

Note: For XB3's on atom side log file would be CapDebug_atom.txt

### Textual Representation of capabilities:    
• Legal operators are: =', '+', and-'.

• Legal flags are: e',i', and `p'. These flags are case-sensitive and specify the Effective, Inheritable and Permitted sets respectively.

• ‘=’ is equivalent to “all capabilities”

• ‘+’ additioanl capability sets.

• ‘-’ excluding these capabilities.

