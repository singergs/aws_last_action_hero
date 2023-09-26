import boto3
import json
import time
import sys
import argparse

service_namespace_list = ['a2c', 'a4b', 'access-analyzer', 'account', 'acm', 'acm-pca', 'activate', 'airflow', 'amplify', 'amplifybackend', 'amplifyuibuilder', 'aoss', 'apigateway', 'app-integrations', 'appconfig', 'appfabric', 'appflow', 'application-autoscaling', 'application-cost-profiler', 'applicationinsights', 'appmesh', 'appmesh-preview', 'apprunner', 'appstream', 'appsync', 'aps', 'arc-zonal-shift', 'arsenal', 'artifact', 'athena', 'auditmanager', 'autoscaling', 'autoscaling-plans', 'aws-marketplace', 'aws-marketplace-management', 'aws-portal', 'awsconnector', 'backup', 'backup-gateway', 'backup-storage', 'batch', 'bedrock', 'billing', 'billingconductor', 'braket', 'budgets', 'bugbust', 'cases', 'cassandra', 'ce', 'chatbot', 'chime', 'cleanrooms', 'cloud9', 'clouddirectory', 'cloudformation', 'cloudfront', 'cloudhsm', 'cloudsearch', 'cloudshell', 'cloudtrail', 'cloudtrail-data', 'cloudwatch', 'codeartifact', 'codebuild', 'codecatalyst', 'codecommit', 'codedeploy', 'codedeploy-commands-secure', 'codeguru', 'codeguru-profiler', 'codeguru-reviewer', 'codeguru-security', 'codepipeline', 'codestar', 'codestar-connections', 'codestar-notifications', 'codewhisperer', 'cognito-identity', 'cognito-idp', 'cognito-sync', 'comprehend', 'comprehendmedical', 'compute-optimizer', 'config', 'connect', 'connect-campaigns', 'consoleapp', 'consolidatedbilling', 'controltower', 'cur', 'customer-verification', 'databrew', 'dataexchange', 'datapipeline', 'datasync', 'datazone', 'datazonecontrol', 'dax', 'dbqms', 'deepcomposer', 'deeplens', 'deepracer', 'detective', 'devicefarm', 'devops-guru', 'directconnect', 'discovery', 'dlm', 'dms', 'docdb-elastic', 'drs', 'ds', 'dynamodb', 'ebs', 'ec2', 'ec2-instance-connect', 'ec2messages', 'ecr', 'ecr-public', 'ecs', 'eks', 'elastic-inference', 'elasticache', 'elasticbeanstalk', 'elasticfilesystem', 'elasticloadbalancing', 'elasticmapreduce', 'elastictranscoder', 'elemental-activations', 'elemental-appliances-software', 'elemental-support-cases', 'elemental-support-content', 'emr-containers', 'emr-serverless', 'entityresolution', 'es', 'events', 'evidently', 'execute-api', 'finspace', 'finspace-api', 'firehose', 'fis', 'fms', 'forecast', 'frauddetector', 'freertos', 'freetier', 'fsx', 'gamelift', 'gamesparks', 'geo', 'glacier', 'globalaccelerator', 'glue', 'grafana', 'greengrass', 'groundstation', 'groundtruthlabeling', 'guardduty', 'health', 'healthlake', 'honeycode', 'iam', 'identity-sync', 'identitystore', 'identitystore-auth', 'imagebuilder', 'importexport', 'inspector', 'inspector2', 'internetmonitor', 'invoicing', 'iot', 'iot-device-tester', 'iot1click', 'iotanalytics', 'iotdeviceadvisor', 'iotevents', 'iotfleethub', 'iotfleetwise', 'iotjobsdata', 'iotroborunner', 'iotsitewise', 'iottwinmaker', 'iotwireless', 'iq', 'iq-permission', 'ivs', 'ivschat', 'kafka', 'kafka-cluster', 'kafkaconnect', 'kendra', 'kendra-ranking', 'kinesis', 'kinesisanalytics', 'kinesisvideo', 'kms']

def get_last_action_for_arn(arn=None, granularity='ACTION_LEVEL', service_namespace='ALL'):
    aa = boto3.client('iam')

    report = aa.generate_service_last_accessed_details(Arn=arn,
                                              Granularity=granularity)
    
    job_id = report['JobId']

    report_details = aa.get_service_last_accessed_details(JobId=job_id)
    

    print(f"Report Status {report_details['JobStatus']} searching for {service_namespace} service")
    while report_details['JobStatus'] != 'COMPLETED':
        time.sleep(10)
        report_details = aa.get_service_last_accessed_details(JobId=job_id)
        print(f"Checking Report Status {report_details['JobStatus']}")
    
    if granularity == 'SERVICE_LEVEL':
        for aService in report_details['ServicesLastAccessed']:
            if aService['TotalAuthenticatedEntities'] > 0:
                print(aService['ServiceName'], aService['TotalAuthenticatedEntities'] )
    
    elif granularity =='ACTION_LEVEL':
        
        for aService in report_details['ServicesLastAccessed']:
            if aService['ServiceNamespace'] == service_namespace or service_namespace=='ALL':
                
                if aService['TotalAuthenticatedEntities'] > 0:
                    print(f"[*] {aService['ServiceName']} was accessed on {aService['LastAuthenticated']} in {aService['LastAuthenticatedRegion']} with principalArn {arn}")
                    if 'TrackedActionsLastAccessed' in aService.keys():
                        for aAction in aService['TrackedActionsLastAccessed']:
                            if 'LastAccessedEntity' in aAction.keys():
                                eTime = aAction['LastAccessedTime'].strftime("%Y-%m-%dT%H:%M:%SZ")
                                cloudwatch_search = f"fields @timestamp, @message | filter eventName = '{aAction['ActionName']}' and eventTime = '{eTime}'"
                                print(f"{cloudwatch_search} ")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for principal arn last action.")
    parser.add_argument("--arn", required=True, help="Principal ARN of User or Role")
    parser.add_argument("--service", required=False, default='ALL', help="Service namespace")
    parser.add_argument("--granularity", required=False, default='ACTION_LEVEL', help="Service Level or Action Level")
    args = parser.parse_args()
    get_last_action_for_arn(arn=args.arn,
                        service_namespace=args.service,
                        granularity=args.granularity
                        )