# OS/161 - System and Device Programming Project

[![OS](https://img.shields.io/badge/OS-OS%2F161-blue.svg)](http://os161.eecs.harvard.edu/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)]()

> **OS/161 kernel implementation** developed for the System and Device Programming course at Politecnico di Torino.  
> This project extends the base OS/161 educational operating system with full support for process management, system calls, file operations, and synchronization primitives.

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Implemented Features](#-implemented-features)
- [Project Structure](#-project-structure)
- [Build Instructions](#-build-instructions)
- [Usage](#-usage)
- [Testing](#-testing)
- [Authors](#-authors)

---

## 🎯 Project Overview

This repository contains a complete implementation of the **OS/161 operating system kernel**, including:

- **Process Management**: Full lifecycle management with `fork()`, `execv()`, `waitpid()`, and `_exit()`
- **System Calls**: Comprehensive implementation of POSIX-like system calls for I/O and process control
- **File System Support**: Open file table management with proper file descriptor handling
- **Synchronization Primitives**: Locks, condition variables, and semaphores for concurrent programming
- **Shell**: Interactive command-line shell with support for program execution and background jobs

The project extends the baseline OS/161 kernel with production-quality implementations suitable for educational and experimental purposes.

---

## ✨ Implemented Features

### 🔧 Core System Calls

#### Process Management
- **`fork()`** - Create child processes with proper memory space duplication
- **`execv()`** - Execute programs with argument passing
- **`waitpid()`** - Parent process synchronization and child status collection
- **`_exit()`** - Clean process termination with status code
- **`getpid()`** - Retrieve current process identifier

#### File Operations
- **`open()`** - Open files with flags support (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC, O_APPEND)
- **`close()`** - Release file descriptors and resources
- **`read()`** - Read data from files and devices
- **`write()`** - Write data to files and devices
- **`lseek()`** - Reposition file offset for random access
- **`dup2()`** - Duplicate file descriptors for I/O redirection
- **`chdir()`** - Change current working directory
- **`__getcwd()`** - Get current working directory path

### 🧵 Synchronization

- **Locks** - Mutual exclusion with sleep-based blocking
- **Condition Variables** - Thread coordination and signaling
- **Semaphores** - Counting semaphores for resource management (userland support via `semfs`)

### 🖥️ Process and Thread Management

- **Process Table** - Global process tracking with PID assignment
- **Parent-Child Relationships** - Proper process hierarchy management
- **Exit Status Collection** - Status code preservation and retrieval
- **Zombie Process Handling** - Cleanup of terminated processes
- **File Descriptor Table** - Per-process open file management (up to 64 descriptors)

### 📂 File System

- **System File Table** - Global tracking of open files (up to 128 system-wide)
- **Reference Counting** - Automatic resource cleanup
- **Offset Management** - Independent file positions per descriptor
- **Console I/O** - Standard input/output/error stream support

### 🐚 Shell (`sh`)

- Interactive command execution
- Background job support with `&` operator
- Built-in commands: `cd`, `exit`, `wait`
- Job control and process management
- Standard I/O redirection support

---

## 📁 Project Structure

```
os161/
├── src/
│   ├── kern/                   # Kernel source code
│   │   ├── arch/              # Architecture-specific code (MIPS)
│   │   ├── compile/           # Kernel build directories
│   │   │   ├── DUMBVM/       # Basic VM configuration
│   │   │   └── PROJECT/      # Project configuration with all features
│   │   ├── conf/              # Kernel configuration files
│   │   ├── dev/               # Device drivers
│   │   ├── fs/                # File systems (SFS, SEMFS)
│   │   ├── include/           # Kernel headers
│   │   ├── lib/               # Kernel utility libraries
│   │   ├── main/              # Kernel initialization
│   │   ├── proc/              # Process management
│   │   ├── syscall/           # System call implementations
│   │   │   ├── file_syscalls.c      # File I/O system calls
│   │   │   ├── proc_syscalls.c      # Process system calls
│   │   │   └── runprogram.c         # Program execution
│   │   ├── thread/            # Thread subsystem
│   │   ├── vfs/               # Virtual file system
│   │   └── vm/                # Virtual memory (DUMBVM)
│   ├── userland/              # User-space programs
│   │   ├── bin/              # User utilities (sh, cat, cp, etc.)
│   │   ├── testbin/          # Test programs
│   │   └── lib/              # User-space libraries
│   ├── common/                # Shared code (libc)
│   ├── mk/                    # Build system makefiles
│   └── design/                # Design documentation
│       ├── shell.txt
│       └── assignments.txt
├── root/                      # Runtime environment
│   ├── kernel                # Compiled kernel binary
│   ├── bin/                  # User binaries
│   ├── testbin/              # Test binaries
│   └── sys161.conf           # System/161 simulator configuration
└── README.md
```

---

## 🔨 Build Instructions

### Prerequisites

- **System/161 simulator** (version 2.x)
- **OS/161 toolchain** (`mips-harvard-os161-gcc`, `bmake`)
- **Linux environment** (or compatible Unix system)

### Building the Kernel

1. **Configure the kernel**:
   ```bash
   cd ~/os161/src/kern/conf
   ./config PROJECT
   ```

2. **Build dependencies**:
   ```bash
   cd ~/os161/src/kern/compile/PROJECT
   bmake depend
   ```

3. **Compile the kernel**:
   ```bash
   bmake
   ```

4. **Install the kernel**:
   ```bash
   bmake install
   ```
   The kernel will be installed to `~/os161/root/kernel`.

### Building User Programs

```bash
cd ~/os161/src
bmake
bmake install
```

This compiles all userland programs (shell, test programs, utilities) and installs them to `~/os161/root/`.

---

## 🚀 Usage

### Running OS/161

1. **Start the System/161 simulator**:
   ```bash
   cd ~/os161/root
   sys161 kernel
   ```

2. **At the kernel menu**, choose an option:
   ```
   OS/161 kernel [? for menu]: 
   ```

   - Press `?` to see available options
   - Enter `p` followed by a program path to run programs
   - Enter `s` to run the shell

3. **Run the shell**:
   ```
   OS/161 kernel [? for menu]: s
   ```

### Using the Shell

Once in the shell, you can execute commands:

```bash
OS/161$ /bin/ls          # List files
OS/161$ /bin/cat file    # Display file contents
OS/161$ /testbin/forktest  # Run test programs
OS/161$ /bin/sh &        # Run commands in background
OS/161$ exit             # Exit the shell
```

### Running Tests

Execute test programs from `testbin/`:

```bash
# Process tests
OS/161$ /testbin/forktest
OS/161$ /testbin/exectest
OS/161$ /testbin/waitpidtest

# File I/O tests
OS/161$ /testbin/filetest
OS/161$ /testbin/badcall

# Synchronization tests
OS/161$ /testbin/lock
OS/161$ /testbin/cv
```

---

## 🧪 Testing

The project includes comprehensive test suites:

### System Call Tests
- **forktest** - Tests `fork()` functionality
- **exectest** - Tests program execution
- **waitpidtest** - Tests parent-child synchronization
- **filetest** - Tests file operations
- **badcall** - Tests error handling

### Stress Tests
- **bigfork** - Large-scale process creation
- **bigfile** - Large file I/O operations
- **forkbomb** - Resource limit testing

Run tests from the kernel menu or shell:
```bash
sys161 kernel "p /testbin/forktest"
```

---

## 📚 Documentation

- **Design Documents**: See [`src/design/`](src/design/) for architecture notes
- **Manual Pages**: HTML documentation in [`src/man/`](src/man/)
- **Configuration**: Kernel options documented in `src/kern/conf/conf.kern`

---

## 👥 Authors

**Davide Santurbano** & **Luca Faieta**  
Politecnico di Torino - Computer Engineering  
Academic Year: 2024/2025

---

## 📄 License

This project is developed for academic purposes as part of the System and Device Programming course. OS/161 is Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2008, 2009 President and Fellows of Harvard College.

---

## 🔗 References

- [OS/161 Official Documentation](http://os161.eecs.harvard.edu/)
- [System/161 Simulator](http://os161.eecs.harvard.edu/download/)

---

**Note**: This implementation uses DUMBVM for virtual memory management. For production use, a complete VM system should be implemented (Assignment 3 in typical OS/161 courses).
