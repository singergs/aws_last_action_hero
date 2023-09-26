# AWS Last Action Hero

![AWS Last Action](https://www.slashfilm.com/img/gallery/why-the-last-action-hero-production-was-such-a-nightmare/the-write-stuff-1645224682.jpg)

## Overview

Here are the two new AWS IAM API calls:

- generate_service_last_accessed_details
- get_service_last_accessed_details

These two calls can produce insights into the activities of users or roles within your AWS setup.

## Running The Script

### Report For One Supported Service

```
python lah.py --arn ROLE_OR_USER_ARN --service iam
```

### Report For All Services Supported

```
python lah.py --arn ROLE_OR_USER_ARN
```

### High Level Report For Service

```
python lah.py --arn ROLE_OR_USER_ARN  --granularity SERVICE_LEVEL
```

## Whats Next

Adding the following

- Scope the report to a time period to support removing actions from a role.
