import re
import subprocess
import boto3
from datetime import datetime
import csv
from io import StringIO
import time
import socket
import logging
import sys
import argparse
from botocore.exceptions import ClientError

# Set up logging
LOG_GROUP_NAME = "/aws/ec2/nping-monitoring"
LOG_STREAM_NAME = "nping-monitoring-log-stream"

# Set up logging to CloudWatch
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a custom formatter
class InstanceIDFormatter(logging.Formatter):
    def __init__(self, instanceid, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instanceid = instanceid

    def format(self, record):
        record.instanceid = self.instanceid
        return super().format(record)

# Create a CloudWatch log handler
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(InstanceIDFormatter('Unknown', '%(asctime)s - %(name)s - %(levelname)s - %(message)s - InstanceID: %(instanceid)s'))
logger.addHandler(log_handler)


def validate_region_and_instance(region_name):
    """
    Validate the region name and check if the instance ID exists in that region.

    Args:
        region_name (str): The name of the AWS region.

    Returns:
        bool: True if the region name is valid and the instance ID exists in that region, False otherwise.
    """
    try:
        ec2 = boto3.client('ec2', region_name=region_name)
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        if region_name not in regions:
            logger.error(f"Invalid region name: {region_name}")
            return False

        # Get the private IP address of the instance
        private_ip = socket.gethostbyname(socket.gethostname())
        # Describe instances filtering by private IP
        response = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'private-ip-address',
                    'Values': [private_ip]
                }
            ]
        )

        # Check if any instances are found in the specified region
        if response['Reservations']:
            # Check if any instances are present in the first reservation
            if response['Reservations'][0]['Instances']:
                return True
            else:
                logger.error(f"No instance found with private IP: {private_ip} in region: {region_name}")
                return False
        else:
            logger.error(f"No instance found with private IP: {private_ip} in region: {region_name}")
            return False

    except Exception as e:
        logger.error(f"Failed to validate region and instance: {e}", exc_info=True)
        return False


def get_instance_id(region_name):
    """
    Get the instance ID and private IP address of the current EC2 instance.

    Args:
        region_name (str): The name of the AWS region.

    Returns:
        tuple: A tuple containing the instance ID and private IP address.
    """
    ec2 = boto3.client('ec2', region_name=region_name)
    logs_client = boto3.client('logs', region_name=region_name)

    try:
        # Get the private IP address of the instance
        private_ip = socket.gethostbyname(socket.gethostname())
        # Describe instances filtering by private IP
        response = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'private-ip-address',
                    'Values': [private_ip]
                }
            ]
        )

        # Check if any instances are present in the first reservation
        if response['Reservations'][0]['Instances']:
            # Extract instance ID
            instance_id = response['Reservations'][0]['Instances'][0]['InstanceId']
            return instance_id, private_ip

        # If no instance is found, log an error and send it to CloudWatch
        error_message = f"No instance found with private IP: {private_ip} in region: {region_name}"
        logger.error(error_message)
        log_error_to_cloudwatch(logs_client, error_message, region_name)
        return None, None

    except Exception as e:
        # Log the error and send it to CloudWatch
        error_message = f"Failed to get instance ID and private IP in region {region_name}: {e}"
        logger.error(error_message, exc_info=True)
        log_error_to_cloudwatch(logs_client, error_message, region_name)
        return None, None
def download_csv_from_s3(region_name, bucket_name, file_key):
    """
    Download a CSV file from an S3 bucket.

    Args:
        region_name (str): The name of the AWS region.
        bucket_name (str): The name of the S3 bucket.
        file_key (str): The key (path) of the CSV file in the S3 bucket.

    Returns:
        str or None: The CSV data as a string, or None if the download fails.
    """
    s3 = boto3.client('s3', region_name=region_name)
    logs_client = boto3.client('logs', region_name=region_name)

    try:
        # Check if the bucket exists
        s3.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            error_message = f"Bucket '{bucket_name}' does not exist"
            logger.error(error_message)
            log_error_to_cloudwatch(logs_client, error_message, region_name)
            return None
        else:
            error_message = f"Error checking bucket existence: {e}"
            logger.error(error_message, exc_info=True)
            log_error_to_cloudwatch(logs_client, error_message, region_name)
            return None

    try:
        response = s3.get_object(Bucket=bucket_name, Key=file_key)
        csv_data = response['Body'].read().decode('utf-8')
        return csv_data
    except Exception as e:
        instance_id, _ = get_instance_id(region_name)
        error_message = f"Failed to download CSV file from S3 on instance {instance_id}: {e}"
        logger.error(error_message, exc_info=True)
        log_error_to_cloudwatch(logs_client, error_message, region_name)
        return None

def publish_metric(region_name, metric_name, dimensions, value, timestamp=None):
    """
    Publish a metric to CloudWatch.

    Args:
        region_name (str): The name of the AWS region.
        metric_name (str): The name of the metric.
        dimensions (list): A list of dictionaries representing the dimensions of the metric.
        value (float or int): The value of the metric.
        timestamp (datetime, optional): The timestamp of the metric. If not provided, the current time is used.
    """
    cloudwatch = boto3.client('cloudwatch', region_name=region_name)
    if timestamp is None:
        timestamp = datetime.utcnow()

    cloudwatch.put_metric_data(
        Namespace='CustomMetrics',
        MetricData=[
            {
                'MetricName': metric_name,
                'Dimensions': dimensions,
                'Timestamp': timestamp,
                'Value': value
            }
        ]
    )


def nping_status(region_name, destinations, instance_id, private_ip, logger):
    """
    Run nping for the specified destinations and publish metrics to CloudWatch.

    Args:
        region_name (str): The name of the AWS region.
        destinations (list): A list of tuples containing (ip, port, protocol) for each destination.
        instance_id (str): The ID of the current EC2 instance.
        private_ip (str): The private IP address of the current EC2 instance.
        logger (logging.Logger): The logger instance to use for logging.
    """
    try:
        # Start timing
        start_time = time.time()
        for ip, port, protocol in destinations:
            # Run nping command based on protocol
            nping_command = ['nping', '-c', '2']
            if protocol.lower() == 'udp':
                nping_command.extend(['-p', str(port), '--udp', ip])
            elif protocol.lower() == 'tcp':
                nping_command.extend(['-p', str(port), '--tcp', ip])
            elif protocol.lower() == 'icmp':
                nping_command.extend(['--icmp', ip])
            else:
                logger.warning(f"Unsupported protocol: {protocol} : {ip} on instance {instance_id}", exc_info=True)
                continue

            process = subprocess.Popen(nping_command,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            # Initialize variables
            packets_sent = 0
            packets_rcvd = 0
            successful_connections = 0
            average_round_trip_time = None
            # Parse output line by line
            for line in stdout.decode('utf-8').split('\n'):
                if 'packets' in line:
                    match = re.search(r'sent: (\d+)', line)
                    if match:
                        packets_sent = int(match.group(1))
                elif 'Rcvd' in line:
                    match = re.search(r'Rcvd: (\d+)', line)
                    if match:
                        packets_rcvd = int(match.group(1))
                elif 'Successful connections' in line:
                    match = re.search(r'Successful connections: (\d+)', line)
                    if match:
                        successful_connections = int(match.group(1))
                elif 'Avg rtt' in line:
                    match = re.search(r'Avg rtt: (\d+\.\d+)ms', line)
                    if match:
                        average_round_trip_time = float(match.group(1))

            # Check if packets sent is equal to packets received or successful_connections is not 0
            successful_connection = (packets_sent == packets_rcvd) or (successful_connections != 0)

            # Publish metric values to CloudWatch
            connection_status_dimensions = [
                {'Name': 'IP', 'Value': ip},
                {'Name': 'Port', 'Value': str(port) if port else 'N/A'},
                {'Name': 'Protocol', 'Value': protocol},
                {'Name': 'InstanceId', 'Value': instance_id},
                {'Name': 'PrivateIP', 'Value': private_ip}
            ]
            publish_metric(region_name, 'ConnectionStatus', connection_status_dimensions, 1 if successful_connection else 0)
            publish_metric(region_name, 'AvgRTT', connection_status_dimensions, average_round_trip_time if average_round_trip_time is not None else 0)

        # End timing
        end_time = time.time()
        # Calculate runtime
        runtime = end_time - start_time
        logger.info(f"Script runtime: {runtime} seconds")

        # Publish script runtime to CloudWatch
        script_runtime_dimensions = [
            {'Name': 'InstanceId', 'Value': instance_id},
            {'Name': 'PrivateIP', 'Value': private_ip}
        ]
        publish_metric(region_name, 'ScriptRuntime', script_runtime_dimensions, runtime)

        # Publish successful script execution status
        script_execution_status_dimensions = [
            {'Name': 'Script', 'Value': 'ExecutionStatus'},
            {'Name': 'InstanceId', 'Value': instance_id},
            {'Name': 'PrivateIP', 'Value': private_ip}
        ]
        publish_metric(region_name, 'ScriptExecutionStatus', script_execution_status_dimensions, 1)

    except Exception as e:
        logger.error(f"Script execution failed: {e}", exc_info=True)
        # Publish failed script execution status
        instance_id, private_ip = get_instance_id(region_name)
        script_execution_status_dimensions = [
            {'Name': 'Script', 'Value': 'ExecutionStatus'},
            {'Name': 'InstanceId', 'Value': instance_id},
            {'Name': 'PrivateIP', 'Value': private_ip}
        ]
        publish_metric(region_name, 'ScriptExecutionStatus', script_execution_status_dimensions, 0)


def log_error_to_cloudwatch(logs_client, error_message, region_name):
    """
    Log an error message to CloudWatch Logs.

    Args:
        logs_client (boto3.client): The CloudWatch Logs client.
        error_message (str): The error message to log.
        region_name (str): The name of the AWS region.
    """
    try:
        logs_client.create_log_group(logGroupName=LOG_GROUP_NAME)
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
            logger.error(f"Error creating log group: {e}", exc_info=True)
            raise

    try:
        log_stream = logs_client.create_log_stream(
            logGroupName=LOG_GROUP_NAME,
            logStreamName=LOG_STREAM_NAME
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
            pass
        else:
            logger.error(f"Error creating log stream: {e}", exc_info=True)
            raise

    # Get the instance ID
    instance_id, _ = get_instance_id(region_name)

    log_record = logging.LogRecord(
        name=logger.name,
        level=logging.ERROR,
        pathname="reachability_monitor.py",
        lineno=123,
        msg=f"{error_message} - InstanceID: {instance_id if instance_id else 'Unknown'}",
        args=(),
        exc_info=None
    )

    response = logs_client.put_log_events(
        logGroupName=LOG_GROUP_NAME,
        logStreamName=LOG_STREAM_NAME,
        logEvents=[
            {
                'timestamp': int(round(time.time() * 1000)),
                'message': log_record.getMessage()
            }
        ]
    )

    logger.info(f"Successfully sent error log to CloudWatch Log Stream: {response['ResponseMetadata']['HTTPStatusCode']}")
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Run nping and publish metrics to CloudWatch')
    parser.add_argument('--region', required=True, help='AWS region (e.g., us-east-1)')
    parser.add_argument('--bucket', required=True, help='S3 bucket name')
    parser.add_argument('--filename', required=True, help='CSV file name in the S3 bucket')
    args = parser.parse_args()

    region_name = args.region
    bucket_name = args.bucket
    file_key = args.filename

    # Validate the region name and check if the instance ID exists in that region
    if not validate_region_and_instance(region_name):
        sys.exit(1)

    # Download CSV from S3
    csv_data = download_csv_from_s3(region_name, bucket_name, file_key)
    if csv_data:
        # Parse CSV data
        destinations = []
        csv_reader = csv.reader(StringIO(csv_data))
        for row in csv_reader:
            if len(row) == 3:  # Check if protocol is provided
                ip, port_str, protocol = row
                port = None if port_str == '' else int(port_str)
                destinations.append((ip, port, protocol))
        # Get the instance ID and private IP of the instance
        instance_id, private_ip = get_instance_id(region_name)

        # Update the logger formatter with the instance ID
        if instance_id:
            log_handler.setFormatter(InstanceIDFormatter(instance_id, '%(asctime)s - %(name)s - %(levelname)s - %(message)s - InstanceID: %(instanceid)s'))

        if instance_id and private_ip:
            # Run nping for each destination
            nping_status(region_name, destinations, instance_id, private_ip, logger)
# Send logs to CloudWatch Log Stream
    logs_client = boto3.client('logs', region_name=region_name)
    try:
        logs_client.create_log_group(logGroupName=LOG_GROUP_NAME)
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
            logger.error(f"Error creating log group: {e}", exc_info=True)
            raise

    try:
        log_stream = logs_client.create_log_stream(
            logGroupName=LOG_GROUP_NAME,
            logStreamName=LOG_STREAM_NAME
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
            logger.info(f"Log stream '{LOG_STREAM_NAME}' already exists in log group '{LOG_GROUP_NAME}'")
        else:
            logger.error(f"Error creating log stream: {e}", exc_info=True)
            raise

    # Create a log record
    log_record = logging.LogRecord(
        name=logger.name,
        level=logging.INFO,
        pathname="my_script.py",
        lineno=123,
        msg="Successfully sent logs to CloudWatch Log Stream",
        args=(),
        exc_info=None
    )

    # Log the record
    logger.handle(log_record)

    response = logs_client.put_log_events(
        logGroupName=LOG_GROUP_NAME,
        logStreamName=LOG_STREAM_NAME,
        logEvents=[
            {
                'timestamp': int(round(time.time() * 1000)),
                'message': log_record.getMessage()
            }
        ]
    )

    logger.info(f"Successfully sent logs to CloudWatch Log Stream: {response['ResponseMetadata']['HTTPStatusCode']}")
if __name__ == "__main__":
    main()
