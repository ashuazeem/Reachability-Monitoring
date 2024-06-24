# ReachabilityMonitoringfromAWS
This repository contains a Python script designed to perform TCP,UDP or ICMP connectivity checks to specified destinations from an Amazon EC2 instance. The script is particularly useful for testing network connectivity and identifying potential network issues.

# Reachability Monitoring Script

This Python script is designed to run `nping` commands from nmap utility for specified destinations (IP addresses, ports, and protocols), and publish metrics related to connection status and round-trip time to Amazon CloudWatch. Additionally, the script sends logs, including any errors, to CloudWatch Logs.

## Prerequisites

Before running the script, make sure you have the following prerequisites:

- Python 3.8 or later (Boto3 will no longer support Python 3.7 starting December 13, 2023)
- pip is installed
- git is installed
- AWS role configured with appropriate permissions for EC2, S3,CloudWatch and assigned it to the EC2 instance where the script will be run.
- `nmap` utility installed on the EC2

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/ashuazeem/Reachability-Monitoring.git
   ```

2. Change to the project directory:

   ```
   cd reachabilitymonitoringfromaws
   ```

3. Install the required Python dependencies:

   ```
   pip3 install -r requirements.txt
   ```

## Usage

The script requires command-line arguments to specify the AWS region, S3 bucket name, and CSV file name containing the destination information.

```
sudo python3.8 reachability_monitor.py --region <aws-region> --bucket <s3-bucket-name> --filename <csv-file-name>
```

- `--region`: The AWS region where the EC2 instance which will monitor the destination IPs is running (e.g., `us-east-1`).
- `--bucket`: The name of the S3 bucket containing the CSV file.
- `--filename`: The name of the CSV file in the S3 bucket, containing the monitoring target information (IP, port, protocol).

The CSV file should have the following format:

```
ip_address,port,protocol
1.2.3.4,80,tcp
5.6.7.8,53,udp
9.10.11.12,,icmp
```

## Logging and Monitoring

The script logs information and errors to CloudWatch Logs. You can monitor the logs in the CloudWatch console, under the log group `/aws/ec2/nping-monitoring`.

The script also publishes the following metrics to CloudWatch:

- `ConnectionStatus`: A metric indicating whether the connection was successful (1) or failed (0) for each destination.
- `AvgRTT`: The average round-trip time (in milliseconds) for each destination.
- `ScriptRuntime`: The total runtime of the script (in seconds).
- `ScriptExecutionStatus`: A metric indicating whether the script executed successfully (1) or failed (0).

## Contributing

If you find any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request.
