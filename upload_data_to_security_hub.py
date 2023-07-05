import json
from datetime import datetime
import os
import boto3

# AWS Credentials
# Make sure you've set these up in your environment
region_name = 'us-east-1'  # set your AWS region
account_id = '950579715744'

from pydantic import BaseModel
from typing import Optional, List


class AwsSecurityHubFinding(BaseModel):
    SchemaVersion: str
    Id: str
    ProductArn: str
    GeneratorId: str
    AwsAccountId: str
    Types: List[str]
    FirstObservedAt: str
    LastObservedAt: str
    CreatedAt: str
    UpdatedAt: str
    Severity: dict
    Title: str
    Description: str
    Resources: List[dict]
    SourceUrl: Optional[str]
    ProductFields: Optional[dict]
    UserDefinedFields: Optional[dict]
    Malware: Optional[List[dict]]
    Network: Optional[dict]
    Process: Optional[dict]
    ThreatIntelIndicators: Optional[List[dict]]
    RecordState: str
    RelatedFindings: Optional[List[dict]]
    Note: Optional[dict]

def reas_report():
    with open("report.json") as f:
        return json.load(f)

def transform_gitleaks_output_to_security_hub(data):
    output = []
    for record in data:
        output.append({
            'SchemaVersion': '2018-10-08',
            'Id': record['RuleID'],
            'ProductArn': f'arn:aws:securityhub:{region_name}:{account_id}:product/{account_id}/default',
            'Types': [record['RuleID']],
            'GeneratorId': 'gitleaks',
            'AwsAccountId': account_id,
            'CreatedAt': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            'UpdatedAt': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            'Severity': {'Label': 'HIGH'},
            'Title': record['Fingerprint'],
            'Description': record['RuleID'],
            'Resources': [{'Type': 'Other', 'Id': record['File']}]
        })
    return output

if __name__ == '__main__':
    securityhub = boto3.client('securityhub',
                               aws_access_key_id=os.environ.get("AWS_ACCESS_KEY"),
                               aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                               region_name=region_name)

    # Get the report
    data = transform_gitleaks_output_to_security_hub(reas_report())

    # Then use the AWS SDK
    response = securityhub.batch_import_findings(
        # Findings=[finding.dict()]
        Findings=data
    )

    print(response)
