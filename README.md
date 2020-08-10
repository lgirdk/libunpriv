# Libprivilege

Implemented a custom library (libprivilege.so) which internally use libcap API's.

## Getting Started

Add new component libunpriv , libunpriv.bb which would fetch the code from  (${RDK_GENERIC_ROOT_GIT}/libunpriv/generic above repo and generate libprivilege.so.

### Prerequisites
libprivilege library dependes on libcap library. libcap or linux Capabilities provide fine-grained control over superuser permissions, allowing use of the root user to be avoided. http://man7.org/linux/man-pages/man7/capabilities.7.html

## Default Case
Default unprivilege user name is set to non-root.

Below capabilities are part of default list and will be applied from library:
CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_DAC_READ_SEARCH,CAP_FOWNER,CAP_FSETID,CAP_LINUX_IMMUTABLE,CAP_NET_BIND_SERVICE,CAP_NET_BROADCAST,CAP_NET_ADMIN,CAP_NET_RAW,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_SYS_CHROOT,CAP_SYS_PTRACE,CAP_SETPCAP,CAP_SYS_RESOURCE,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_NICE,CAP_SYS_TTY_CONFIG,CAP_SETGID,CAP_SETUID

```
libcap-native
```

### Installing
Add the DEPENDS in package recipes:

```
DEPENDS += "${@bb.utils.contains('DISTRO_FEATURES', 'CAPABILITY', 'libunpriv', '', d)}"
```

### API
```
/* initializes cap_t structure */
cap_t init_capability(void);

/* Read the current capability of process */
cap_user* read_capability(cap_user *);

// Drop the capabilities of process based on cap_user structure
void drop_root_caps(cap_user *);

/* Applying process/application specific capabilities */
int update_process_caps(cap_user *);

```

