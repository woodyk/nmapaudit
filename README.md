# nmapaudit 

The nmapaudit Script is a Python script that performs network scans using Nmap and compares the results with previous scans to identify changes in open ports and services. The script supports scanning multiple networks and hosts, and can output the results to the console or to a file.

## Requirements

To run the Nmap Audit Script, you will need:

- Python 3.7 or later
- Nmap 7.80 or later

## Installation

To install the Nmap Audit Script:

1. Clone the repository:

   ```
   $ git clone https://github.com/username/nmap-audit.git
   ```

2. Install the required Python packages:

   ```
   $ pip install -r requirements.txt
   ```

## Usage

To run the Nmap Audit Script, use the following command:

```
$ python nmapaudit.py [--stdout] [--output-file] [--output-dir <directory>]
```

The script accepts the following arguments:

- `--stdout`: Display the scan results on the console.
- `--output-file`: Save the scan results to a file with a timestamp.
- `--output-dir`: The directory to save the output file to. Default: `./`.

By default, the script will read its configuration options from the `nmapaudit.conf.yml` file in the same directory as the script. You can modify this file to configure the script's behavior.

## Configuration

The Nmap Audit Script is configured using the `nmapaudit.conf.yml` file. This file contains a set of configuration options that control various aspects of the script's behavior.

### Configuration Options

The following configuration options are available:

#### `maxMinions`

The `maxMinions` option sets the maximum number of network scans that can be run in parallel. This value should be set based on the available system resources and the number of hosts being scanned. The default value is `20`.

Example:

```
maxMinions: 10
```

#### `logFile`

The `logFile` option sets the path to the log file that will be used to store the script's output. This file will contain information about the scans that have been run, as well as any errors or warnings that have been encountered. The default value is `nmapaudit.log`.

Example:

```
logFile: /var/log/nmapaudit.log
```

#### `histFile`

The `histFile` option sets the path to the history file that will be used to store the results of previous scans. This file is used to compare the results of current scans with the results of previous scans to identify changes in open ports and services. The default value is `nmapaudit.hist.yml`.

Example:

```
histFile: /var/lib/nmapaudit.hist.yml
```


#### `networks`

The `networks` option is a list of networks to scan. Each network can be specified as a CIDR block or as a single IP address. For each network, you can optionally specify a label that will be used to identify the network in the scan results. If no label is specified, the network address will be used as the label.

Example:

```
networks:
  - label1: 192.168.0.0/24
  - label2: 10.0.0.1
  - 172.16.0.0/16
```

#### `ports`

The `ports` option is a list of ports to scan. Each port should be specified as a string containing the port number. By default, the script will scan ports 80, 443, 22, and 53.

Example:

```
ports:
  - "80"
  - "443"
  - "22"
  - "53"
```

## License

The Nmap Audit Script is licensed under the [MIT License](LICENSE).
