
# Remote Thread Hijacking

This project demonstrates remote thread hijacking on a Windows process. It involves creating a suspended process, injecting shellcode into that process, and hijacking its thread to execute the injected shellcode.

## Features
- **Create Suspended Process:** Launches a Windows process in a suspended state to allow for thread hijacking.
- **Shellcode Injection:** Allocates memory in the target process, injects shellcode, and changes memory protection for execution.
- **Thread Hijacking:** Modifies the context of the target thread to point to the injected shellcode and resumes the thread.

## Prerequisites
- **Operating System:** Windows
- **Development Environment:** Visual Studio
- **Libraries:**
  - Windows API (kernel32, ntdll)
  - Functions for process and memory management

## How It Works
1. **Create Suspended Process:** The project uses the `CreateProcess` API to start a process in suspended mode.
2. **Inject Shellcode:** The shellcode is injected into the process using `VirtualAllocEx` and `WriteProcessMemory`.
3. **Hijack Thread:** The thread's instruction pointer (`RIP`) is redirected to the shellcode and resumed.

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/RemoteThreadHijacking.git
   ```
2. Open the project in Visual Studio.
3. Build the project (make sure to enable C++20 in your project settings if needed).
4. Run the executable:
   ```bash
   RemoteThreadHijacking.exe <ProcessName>
   ```
   Replace `<ProcessName>` with the name of the process you want to hijack (e.g., `notepad.exe`).

### Example
```bash
RemoteThreadHijacking.exe notepad.exe
```

## Project Structure
- **Functions.h/Functions.cpp:** Contains the core functions for creating a process, injecting shellcode, and hijacking threads.
- **RemoteThreadHijacking.cpp:** The main entry point for the program.

## Troubleshooting
- **Linking Errors:** Ensure you're running Visual Studio as Administrator and have sufficient privileges for process manipulation.
- **Missing PDB File Errors:** Clean and rebuild the project if you encounter issues related to `.pdb` files.

## Disclaimer
This project is intended for educational purposes only. Use responsibly and ensure you have permission when running on target systems.

## License
This project is licensed under the MIT License.
