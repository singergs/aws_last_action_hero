import boto3
import time
import argparse

# List of valid AWS service namespaces
SERVICE_NAMESPACE_LIST = ['a2c', 'a4b', 'access-analyzer', 'account', 'acm', 'acm-pca',
                          'activate', 'airflow', 'amplify', 'amplifybackend', 'amplifyuibuilder',
                          'aoss', 'apigateway', 'app-integrations', 'appconfig', 'appfabric', 'appflow',
                          'application-autoscaling', 'application-cost-profiler', 'applicationinsights',
                          'appmesh', 'appmesh-preview', 'apprunner', 'appstream', 'appsync', 'aps',
                          'arc-zonal-shift', 'arsenal', 'artifact', 'athena', 'auditmanager', 'autoscaling',
                          'autoscaling-plans', 'aws-marketplace', 'aws-marketplace-management', 'aws-portal',
                          'awsconnector', 'backup', 'backup-gateway', 'backup-storage', 'batch', 'bedrock',
                          'billing', 'billingconductor', 'braket', 'budgets', 'bugbust', 'cases', 'cassandra',
                          'ce', 'chatbot', 'chime', 'cleanrooms', 'cloud9', 'clouddirectory', 'cloudformation',
                          'cloudfront', 'cloudhsm', 'cloudsearch', 'cloudshell', 'cloudtrail', 'cloudtrail-data',
                          'cloudwatch', 'codeartifact', 'codebuild', 'codecatalyst', 'codecommit', 'codedeploy',
                          'codedeploy-commands-secure', 'codeguru', 'codeguru-profiler', 'codeguru-reviewer',
                          'codeguru-security', 'codepipeline', 'codestar', 'codestar-connections',
                          'codestar-notifications', 'codewhisperer', 'cognito-identity', 'cognito-idp',
                          'cognito-sync', 'comprehend', 'comprehendmedical', 'compute-optimizer', 'config',
                          'connect', 'connect-campaigns', 'consoleapp', 'consolidatedbilling', 'controltower',
                          'cur', 'customer-verification', 'databrew', 'dataexchange', 'datapipeline', 'datasync',
                          'datazone', 'datazonecontrol', 'dax', 'dbqms', 'deepcomposer', 'deeplens', 'deepracer',
                          'detective', 'devicefarm', 'devops-guru', 'directconnect', 'discovery', 'dlm', 'dms',
                          'docdb-elastic', 'drs', 'ds', 'dynamodb', 'ebs', 'ec2', 'ec2-instance-connect', 'ec2messages',
                          'ecr', 'ecr-public', 'ecs', 'eks', 'elastic-inference', 'elasticache', 'elasticbeanstalk',
                          'elasticfilesystem', 'elasticloadbalancing', 'elasticmapreduce', 'elastictranscoder',
                          'elemental-activations', 'elemental-appliances-software', 'elemental-support-cases',
                          'elemental-support-content', 'emr-containers', 'emr-serverless', 'entityresolution',
                          'es', 'events', 'evidently', 'execute-api', 'finspace', 'finspace-api', 'firehose',
                          'fis', 'fms', 'forecast', 'frauddetector', 'freertos', 'freetier', 'fsx', 'gamelift',
                          'gamesparks', 'geo', 'glacier', 'globalaccelerator', 'glue', 'grafana', 'greengrass',
                          'groundstation', 'groundtruthlabeling', 'guardduty', 'health', 'healthlake', 'honeycode',
                          'iam', 'identity-sync', 'identitystore', 'identitystore-auth', 'imagebuilder', 'importexport',
                          'inspector', 'inspector2', 'internetmonitor', 'invoicing', 'iot', 'iot-device-tester', 'iot1click',
                          'iotanalytics', 'iotdeviceadvisor', 'iotevents', 'iotfleethub', 'iotfleetwise', 'iotjobsdata',
                          'iotroborunner', 'iotsitewise', 'iottwinmaker', 'iotwireless', 'iq', 'iq-permission', 'ivs',
                          'ivschat', 'kafka', 'kafka-cluster', 'kafkaconnect', 'kendra', 'kendra-ranking', 'kinesis',
                          'kinesisanalytics', 'kinesisvideo', 'kms']

def generate_last_accessed_report(arn, granularity):
    """Generate a report for the last accessed service."""
    iam_client = boto3.client('iam')
    report = iam_client.generate_service_last_accessed_details(Arn=arn, Granularity=granularity)
    return report['JobId']

def fetch_report_details(job_id):
    """Fetch the report details based on job ID."""
    iam_client = boto3.client('iam')
    return iam_client.get_service_last_accessed_details(JobId=job_id)

def wait_for_report_completion(job_id):
    """Wait until the report generation completes."""
    report_details = fetch_report_details(job_id)
    while report_details['JobStatus'] != 'COMPLETED':
        time.sleep(10)
        report_details = fetch_report_details(job_id)
    return report_details

def print_report_details(report_details, service_namespace, granularity, arn):
    """Print the report details based on granularity and service namespace."""
    if granularity == 'SERVICE_LEVEL':
        for service in report_details['ServicesLastAccessed']:
            if service['TotalAuthenticatedEntities'] > 0:
                print(service['ServiceName'], service['TotalAuthenticatedEntities'])

    elif granularity == 'ACTION_LEVEL':
        for service in report_details['ServicesLastAccessed']:
            if service['ServiceNamespace'] == service_namespace or service_namespace == 'ALL':
                if service['TotalAuthenticatedEntities'] > 0:
                    print(f"[*] {service['ServiceName']} was accessed on {service['LastAuthenticated']} in {service['LastAuthenticatedRegion']} with principalArn {arn}")
                    for action in service.get('TrackedActionsLastAccessed', []):
                        if 'LastAccessedEntity' in action:
                            time_format = action['LastAccessedTime'].strftime("%Y-%m-%dT%H:%M:%SZ")
                            cloudwatch_search = f"fields @timestamp, @message | filter eventName = '{action['ActionName']}' and eventTime = '{time_format}'"
                            print(cloudwatch_search)

def get_last_action_for_arn(arn, granularity, service_namespace):
    """Get the last action for a specific ARN."""
    job_id = generate_last_accessed_report(arn, granularity)
    report_details = wait_for_report_completion(job_id)
    print_report_details(report_details, service_namespace, granularity, arn)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for principal arn last action.")
    parser.add_argument("--arn", required=True, help="Principal ARN of User or Role")
    parser.add_argument("--service", required=False, default='ALL', choices=SERVICE_NAMESPACE_LIST + ['ALL'], help="Service namespace")
    parser.add_argument("--granularity", required=False, default='ACTION_LEVEL', choices=['SERVICE_LEVEL', 'ACTION_LEVEL'], help="Service Level or Action Level")
    parser.add_argument("--output", required=False, type=str, help="Path to save the output to a file")
    args = parser.parse_args()

    # Redirect output to a file if specified
    if args.output:
        sys.stdout = open(args.output, 'w')

    get_last_action_for_arn(arn=args.arn, service_namespace=args.service, granularity=args.granularity)
