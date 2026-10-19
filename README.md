# India Job Hub

A small, responsive job-search web app for **AWS DevOps, SAP ABAP, TOSCA Testing and Quadient Inspire**, focused on India and remote work.

## What it does
- Category dropdown changes the selected job track.
- Location filter: India + Remote, India only, Remote only.
- Optional keyword search.
- Live results from public job APIs (Arbeitnow and Remotive), plus optional Adzuna API for India.
- Quick links to LinkedIn Jobs, Naukri, Indeed India, Foundit and Google/company career searches.
- Deduplicates listings and links to the source posting.
- Job discovery defaults: posting date within the last 7 days, newest first, and background refresh every 6 hours. Listings without a usable posting date are excluded from the date-filtered results.

## Important source limitations
There is no universal, lawful API that grants access to every job portal. LinkedIn, Naukri and company career sites may restrict automated collection or require approved partner APIs. This app **does not scrape or bypass login/access controls** on those sites; it opens role-specific searches instead. Public feed results can be incomplete, stale or have country restrictions. Confirm each role on the employer/source site.

## Run locally (Node.js 20+)
```bash
cp .env.example .env
npm install
npm start
```
Open http://localhost:3000. No API key is needed to try the public feeds. To enable Adzuna, create an account at https://developer.adzuna.com/ and add `ADZUNA_APP_ID` and `ADZUNA_APP_KEY` to `.env`, then restart. The defaults are configured in `.env.example`: `JOB_POSTED_WITHIN_DAYS=7`, `JOB_SORT=newest`, and `JOB_REFRESH_INTERVAL_HOURS=6`. The backend fetches each configured category once at startup and then every six hours, keeps results in an in-memory cache, and filters/sorts them when users search. Check `/api/job-discovery-config` to inspect the active settings and refresh timestamps.

### Job discovery refresh behavior
- The rolling date window is 7 days; a job without a parseable provider posting date is omitted because its age cannot be verified.
- Results are sorted by provider posting date, newest first.
- The app performs a refresh at startup and every 6 hours while the Node.js process is running. This in-process timer is suitable for local testing and a single always-on instance. For production or multiple app instances, use Amazon EventBridge Scheduler plus a dedicated refresh endpoint/worker or a scheduled ECS task, and store the cache in DynamoDB/S3/ElastiCache so refreshes survive restarts and are not duplicated.
- The current cache is in memory; a restart clears it and starts a new refresh. API availability and provider terms affect results.

## Run with Docker
```bash
docker build -t india-job-hub .
docker run --rm -p 3000:3000 --env-file .env india-job-hub
```

## AWS deployment: EC2 + Docker (starter setup)
This project includes Terraform to provision a small EC2 instance in your account's **default VPC**. This is a low-complexity starter, not a production-hardened architecture. You are responsible for AWS charges.

### 1. Prerequisites
- An AWS account and AWS CLI configured (`aws configure` or an SSO profile).
- Terraform 1.5+ and Docker installed on your local machine.
- An existing EC2 key pair if you want SSH access.
- A default VPC with a public subnet. The Terraform chooses the first subnet in the default VPC.

### 2. Provision the EC2 instance
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```
Edit `terraform.tfvars`: set `ssh_cidr` to your current public IPv4 `/32` and `key_name` to your existing EC2 key pair. If you leave `key_name` empty, SSH ingress is not opened; set up an SSM instance role before using Systems Manager.

```bash
terraform init
terraform fmt
terraform validate
terraform plan
terraform apply
```
Type `yes` when prompted. Save the `public_ip` output. Terraform creates billable resources. `t3.micro` eligibility/pricing depends on your account and region.

### 3. Copy and run the application on EC2
From the project root, replace `EC2_PUBLIC_IP` and `PATH_TO_KEY.pem`:
```bash
scp -i PATH_TO_KEY.pem -r package.json package-lock.json server.js public .env ec2-user@EC2_PUBLIC_IP:/home/ec2-user/india-job-hub/
```
First, run `npm install` locally to generate `package-lock.json`, then copy `.env.example` to `.env` and edit it (Adzuna keys are optional). Do not commit API credentials. Then copy the files and SSH in:
```bash
ssh -i PATH_TO_KEY.pem ec2-user@EC2_PUBLIC_IP
cd /home/ec2-user/india-job-hub
sudo docker build -t india-job-hub .
sudo docker run -d --name india-job-hub --restart unless-stopped -p 3000:3000 --env-file .env india-job-hub
```
Open the Terraform output `app_url_after_deployment` in a browser. This direct HTTP URL is for a starter/demo only; **do not use it for a production service carrying credentials**.

### 4. Add a domain and HTTPS before public production use
Recommended production improvements:
1. Put an Application Load Balancer in front of the app, allow inbound app traffic only from the ALB security group, and issue an ACM certificate.
2. Point a Route 53 record to the ALB and redirect HTTP to HTTPS.
3. Store API secrets in AWS Secrets Manager or SSM Parameter Store, not in the image or source repository.
4. Use an IAM instance role + Systems Manager Session Manager rather than SSH keys.
5. Add CloudWatch logs/alarms, health checks, patching, backups and deployment automation.
6. Consider ECS Fargate or AWS App Runner for managed container hosting and a custom VPC for production.

### 5. Update the app
Copy updated source files to the EC2 instance, then rebuild/restart:
```bash
sudo docker build -t india-job-hub .
sudo docker rm -f india-job-hub
sudo docker run -d --name india-job-hub --restart unless-stopped -p 3000:3000 --env-file .env india-job-hub
```

### 6. Avoid unexpected costs
Check AWS Pricing for your region before applying. When finished testing, from the `terraform` directory run:
```bash
terraform destroy
```
Review the plan and type `yes`. This deletes resources managed by this Terraform configuration. It does not delete anything outside Terraform's state.

## Troubleshooting
- Check `sudo docker logs -f india-job-hub` on EC2.
- Check health: `curl http://localhost:3000/api/health` on the instance.
- If the browser cannot connect, check the EC2 public IP, subnet route to an Internet Gateway, security group port 3000 and container status.
- If no jobs appear, use portal search links, broaden the keyword, check API availability, or configure Adzuna. APIs do not guarantee results for every specialty.


## User registration: Cognito + DynamoDB (30-day free trial)

The application supports Cognito-hosted registration/login, a 30-day access period created on the first successful signup/login, protected job search API, and a manual renewal-request button. Renewal requests are recorded in DynamoDB; an administrator must contact the user, collect payment using your chosen process, and manually extend `expiresAt` after payment is confirmed. This starter does not collect card data or process payments.

### A. Create Cognito User Pool in AWS Console
1. Open Amazon Cognito in the same AWS Region you will use for the app (example `ap-south-1`). Create a **User pool**.
2. Set sign-in identifier to **Email** and require email verification. Enable self-service sign-up.
3. Configure a Cognito domain (Cognito domain prefix is simplest for testing).
4. Create an **App client** for a server-side web application. Generate a client secret. Enable the **Authorization code grant** and scopes `openid` and `email`. Set callback URL to `https://YOUR_DOMAIN/auth/callback` (for initial local test, `http://localhost:3000/auth/callback`). Set sign-out URL to `https://YOUR_DOMAIN/`. Use HTTPS for a public production deployment.
5. Copy User pool ID, App client ID, app client secret and domain prefix. `COGNITO_DOMAIN` must be the host only, such as `your-prefix.auth.ap-south-1.amazoncognito.com`, without `https://`.

### B. Create DynamoDB table
1. Open DynamoDB → Tables → Create table.
2. Table name: `IndiaJobHubUsers`.
3. Partition key: `userId`, type **String**. No sort key is needed.
4. Use on-demand capacity for this small starter.
5. Do not enable TTL as the access-control mechanism. Expiry is checked by the application on every job-search API request.

### C. Give EC2 a least-privilege IAM role
Create an EC2 role and attach a custom policy restricted to the `IndiaJobHubUsers` table ARN. Example policy (replace REGION, ACCOUNT_ID and table name):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
    "Resource": "arn:aws:dynamodb:REGION:ACCOUNT_ID:table/IndiaJobHubUsers"
  }]
}
```
Attach the role to the EC2 instance. Do not store AWS access keys on the instance.

### D. Configure and run
Copy `.env.example` to `.env` and set `AWS_REGION`, `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID`, `COGNITO_CLIENT_SECRET`, `COGNITO_DOMAIN`, `DYNAMODB_USERS_TABLE`, and `PUBLIC_BASE_URL`. For a real public deployment, `PUBLIC_BASE_URL` must be your HTTPS site origin and the Cognito callback URL must match it exactly. Install dependencies (`npm install`) and start the app (`npm start`) or rebuild the Docker image after changing code.

### E. Manual renewal process
- User clicks **Request renewal**; DynamoDB records `renewalStatus=PENDING` and `renewalRequestedAt`.
- Contact the user and handle payment outside this app.
- Only after confirming payment, open the user's item in DynamoDB and set `expiresAt` to a future Unix epoch timestamp in **seconds**, `status` to `ACTIVE`, and `renewalStatus` to `APPROVED`.
- To calculate a date, use a trusted Unix timestamp converter and ensure the value is seconds, not milliseconds.

Example item fields:

```json
{
  "userId": "COGNITO_SUB_VALUE",
  "email": "user@example.com",
  "status": "ACTIVE",
  "registeredAt": "2026-10-17T10:00:00.000Z",
  "expiresAt": 1794919200,
  "renewalStatus": "PENDING",
  "renewalRequestedAt": "2026-11-16T10:00:00.000Z"
}
```

The numeric expiry above is illustrative; use a timestamp matching the actual renewal date. Never ask users to send passwords or payment-card details to you. For production, add an admin-only renewal interface, HTTPS reverse proxy/load balancer, backups, monitoring, and a privacy policy. If the app was already deployed, rebuild/redeploy it after these changes. Existing accounts may need to sign out and sign back in.


## Recruiter posts and hiring announcements

The homepage includes a **Recruiter posts & hiring announcements** panel. After selecting a role and clicking **Find jobs**, it builds links to public Google and LinkedIn searches for recent posts mentioning hiring, recruiter contact details, or instructions to email a resume. These searches complement the structured job feeds and use the same selected category and location mode.

**Important limitation:** this feature opens search pages; it does not automatically ingest every LinkedIn member post, scrape LinkedIn, or extract email addresses from pages. LinkedIn restricts automated collection and access depends on approved APIs and permissions. The user should open the original post and verify the author, posting date, role, and contact details. To populate recruiter posts directly inside the app, integrate a source that explicitly permits this use or add a moderated post-submission workflow.
