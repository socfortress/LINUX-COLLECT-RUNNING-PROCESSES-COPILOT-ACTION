## Collect Running Processes

This script collects a snapshot of all running processes on the system, including key metadata, and outputs the results in JSON format for integration with security tools like OSSEC/Wazuh.

### Overview

The `Collect-Running-Processes` script enumerates all running processes, collecting details such as PID, parent PID, user, command line, executable path, and SHA256 hash of the binary. Output is formatted as JSON for active response workflows.

### Script Details

#### Core Features

1. **Process Enumeration**: Scans `/proc` for all running processes.
2. **Metadata Collection**: Collects PID, PPID, user, command line, executable path, and SHA256 hash.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
./Collect-Running-Processes
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |
| `LogPath` | string | `/tmp/Collect-Running-Processes-script.log` | Path for detailed execution logs |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file
- Rotates the detailed log file if it exceeds the size limit
- Logs the start of the script execution

#### 2. Process Collection
- Enumerates all `/proc/[0-9]*` directories
- Collects metadata for each process

#### 3. JSON Output Generation
- Formats process details into a JSON array
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Collect-Running-Processes",
  "data": [
    {
      "pid": "1234",
      "ppid": "1",
      "user": "root",
      "cmd": "/usr/sbin/sshd -D",
      "exe": "/usr/sbin/sshd",
      "sha256": "abcdef123456..."
    },
    {
      "pid": "5678",
      "ppid": "1234",
      "user": "user",
      "cmd": "bash",
      "exe": "/usr/bin/bash",
      "sha256": "123456abcdef..."
    }
  ],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access process information
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure read access to `/proc`
2. **Missing Data**: Some processes may exit before being scanned
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./Collect-Running-Processes
```

### Contributing

When modifying this script:
1. Maintain the process metadata collection and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
