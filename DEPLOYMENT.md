# BinTalk Production Deployment Guide

> **Read this first: what the current code supports.** Parts of this guide describe a target
> architecture, not what BinTalk does today. In particular:
>
> - **Run exactly one API instance.** WebSocket connections, call state and uploaded files live in
>   that process and on its local volume; with several replicas, live events, calls and file
>   downloads break. Sticky sessions do not fix this.
> - **Files are stored on a local volume**, not S3. The S3 settings below are not used.
> - **There is no `/metrics` endpoint** yet. Use `/health` (liveness) and `/ready` (database,
>   Redis and encryption keys) for probes.
> - **Uploads are not virus-scanned.**
> - The supported way to run BinTalk is Docker Compose:
>   `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`, which publishes only
>   the gateway (ports 80 and 443).

## Pre-Deployment Checklist

- [ ] Security audit completed
- [ ] Penetration testing performed
- [ ] Database backups configured
- [ ] Monitoring and alerting setup
- [ ] Log aggregation configured
- [ ] TLS certificates obtained from CA
- [ ] Environment variables configured for production
- [ ] External Vault instance provisioned, with auto-unseal and the `bintalk-api` policy
- [ ] Backups of PostgreSQL, Vault storage and the uploads volume (see "Backup Strategy")
- [ ] Email service configured
- [ ] CDN configured (optional)

## Infrastructure Requirements

### Minimum Production Setup
- **Compute**: 4 CPU cores, 8GB RAM (per API server, recommend 2+ instances)
- **Database**: PostgreSQL 14+, 50GB storage minimum, automated backups
- **Cache**: Redis 7.0+, 4GB memory minimum
- **Message Queue**: Kafka 3.0+, 3 brokers minimum
- **Secret Management**: HashiCorp Vault Enterprise (HA enabled)
- **Load Balancer**: AWS ALB, Azure LB, or equivalent
- **Storage**: a persistent volume for uploads (100GB+ initial), backed up with the database
- **Network**: VPC/Private network, security groups configured

### Recommended HA Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                     Internet / CDN                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │   Load Balancer (ALB)       │
        │   - SSL/TLS Termination     │
        │   - Health Checks           │
        └──────────────┬──────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
    ┌───▼───┐      ┌───▼───┐      ┌──▼────┐
    │ API 1 │      │ API 2 │      │ API 3 │
    └───┬───┘      └───┬───┘      └──┬────┘
        │              │              │
    ┌───┴──────────────┼──────────────┴──┐
    │   PostgreSQL Primary (RDS)        │
    │   - Multi-AZ Failover             │
    │   - Automated Backups (daily)     │
    │   - Read Replicas (optional)      │
    └───┬──────────────┬────────────────┘
        │              │
    ┌───▼──┐       ┌───▼──┐
    │Redis │       │Redis │ (Sentinel)
    │Cluster       │Replica
    └──────┘       └──────┘

    Kafka Cluster (3 nodes)
    ├─ Broker 1
    ├─ Broker 2
    └─ Broker 3

    Vault Cluster (HA)
    ├─ Primary
    └─ Secondary (standby)
```

## Deployment Steps

### 1. Infrastructure Setup

```bash
# Create VPC and security groups
aws ec2 create-vpc --cidr-block 10.0.0.0/16
aws ec2 create-security-group --group-name bintalk-api --vpc-id <vpc-id>

# RDS PostgreSQL
aws rds create-db-instance \
    --db-instance-identifier bintalk-postgres \
    --db-instance-class db.t3.medium \
    --engine postgres \
    --engine-version 14.7 \
    --allocated-storage 100 \
    --master-username bintalk \
    --master-user-password <strong-password> \
    --multi-az \
    --backup-retention-period 30

# ElastiCache Redis
aws elasticache create-replication-group \
    --replication-group-description bintalk-redis \
    --engine redis \
    --engine-version 7.0 \
    --cache-node-type cache.t3.medium \
    --num-cache-clusters 3 \
    --automatic-failover-enabled
```

### 2. Database Migration

```bash
# Connect to PostgreSQL
psql -h <rds-endpoint> -U bintalk -d bintalk_db

# Run migrations
\i init.sql

# Verify tables
\dt
```

### 3. Vault Setup (High Availability)

```bash
# Using Terraform or AWS Secrets Manager for HA Vault
# Store Vault seal key securely (AWS KMS recommended)

# Initialize Vault
vault operator init \
    -key-shares=5 \
    -key-threshold=3

# Unseal all replicas
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# Enable replication
vault write -f sys/replication/dr/primary/enable \
    primary_cluster_addr=https://vault1:8201

# Apply BinTalk policy
vault policy write bintalk - < vault-policy.hcl

# Initialize secrets
./vault-init.sh
```

### 4. Configure TLS Certificates

```bash
# Using Let's Encrypt with Certbot (recommended for production)
sudo certbot certonly --dns-route53 -d api.bintalk.com -d *.bintalk.com

# Or using your CA provider
# Place certificates in /etc/bintalk/certs/

# Set restrictive permissions
sudo chmod 600 /etc/bintalk/certs/server.key
sudo chmod 644 /etc/bintalk/certs/server.crt
```

### 5. Environment Configuration

```bash
# Create production .env file
cat > /etc/bintalk/.env << 'EOF'
# Production Environment Variables
ENVIRONMENT=production
LOG_LEVEL=info

# Database
DB_HOST=<rds-endpoint>
DB_PORT=5432
DB_USER=bintalk
DB_PASSWORD=<strong-password>
DB_NAME=bintalk_db
DB_SSL_MODE=require
DB_MAX_CONNECTIONS=50

# Redis
REDIS_HOST=<elasticache-endpoint>
REDIS_PORT=6379
REDIS_PASSWORD=<redis-password>
REDIS_DB=0
REDIS_POOL_SIZE=20

# Kafka
KAFKA_BROKERS=broker1:9092,broker2:9092,broker3:9092

# Sessions (seconds)
SESSION_TTL=900
SESSION_REFRESH_TTL=86400

# Vault: a token limited to the bintalk-api policy (vault/policy.hcl), periodic so the API can
# renew it. Never a root token. VAULT_TOKEN_FILE=/path/to/token works too.
VAULT_ADDR=https://<vault-cluster>:8200
VAULT_TOKEN=<token from: vault token create -policy=bintalk-api -period=168h -orphan>

# TLS
TLS_CERT_FILE=/etc/bintalk/certs/server.crt
TLS_KEY_FILE=/etc/bintalk/certs/server.key

# Encryption
KEY_ROTATION_INTERVAL=90

# CORS (explicit origins are required in production)
CORS_ALLOWED_ORIGINS=https://app.bintalk.com

# Companies and payments (Chapa live keys; see README "Payments with Chapa")
APP_BASE_URL=https://chat.yourdomain.com
CHAPA_SECRET_KEY=<live secret key>
CHAPA_WEBHOOK_SECRET=<webhook secret>
COMPANY_REQUIRE_APPROVAL=false
SUBSCRIPTION_GRACE_DAYS=3

# Security
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=1m
MAX_REQUEST_SIZE=100M
MAX_JSON_BODY_SIZE=1M
STORAGE_QUOTA_PER_USER=5G
# The gateway's address, so client IPs cannot be spoofed with X-Forwarded-For
TRUSTED_PROXIES=<gateway-ip>

# Email
SMTP_HOST=smtp.aws-ses.com
SMTP_PORT=587
SMTP_USER=<from-vault>
SMTP_PASSWORD=<from-vault>
EOF

# Set restrictive permissions
sudo chmod 600 /etc/bintalk/.env
```

### 6. Docker Deployment

```bash
# Build and push to Docker Registry
docker build -t your-registry/bintalk-api:1.0.0 -f Dockerfile ./backend
docker push your-registry/bintalk-api:1.0.0

# Kubernetes (target architecture: needs shared upload storage and cross-instance event
# delivery first; until then keep replicas at 1, as below)
# Create deployment YAML
cat > k8s-deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bintalk-api
  namespace: bintalk
spec:
  replicas: 1          # BinTalk supports a single API instance (see the top of this guide)
  strategy:
    type: Recreate     # never run two instances at once
  selector:
    matchLabels:
      app: bintalk-api
  template:
    metadata:
      labels:
        app: bintalk-api
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - bintalk-api
              topologyKey: kubernetes.io/hostname
      containers:
      - name: api
        image: your-registry/bintalk-api:1.0.0
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: https
        envFrom:
        - secretRef:
            name: bintalk-config
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
            scheme: HTTPS
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: certs
          mountPath: /etc/bintalk/certs
          readOnly: true
      volumes:
      - name: certs
        secret:
          secretName: bintalk-tls
---
apiVersion: v1
kind: Service
metadata:
  name: bintalk-api
  namespace: bintalk
spec:
  type: ClusterIP
  ports:
  - port: 443
    targetPort: 8000
    protocol: TCP
    name: https
  selector:
    app: bintalk-api
EOF

# Deploy
kubectl apply -f k8s-deployment.yaml
```

### 7. Monitoring and Alerting

```bash
# Install Prometheus
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack

# The API does not expose /metrics yet. Until it does, alert on:
#  - GET /ready returning 503 (database, Redis or encryption keys unavailable)
#  - log lines at level "error" (the API logs JSON to stdout)
#  - container restarts and the Docker healthcheck status

# Install Grafana
helm repo add grafana https://grafana.github.io/helm-charts
helm install grafana grafana/grafana

# Setup alerting
# Configure PagerDuty/Slack webhooks for critical alerts
```

### 8. Log Aggregation

```bash
# Using ELK Stack or CloudWatch Logs
# Configure Filebeat to ship logs

filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/bintalk/*.log
  
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  username: "elastic"
  password: "${ELASTIC_PASSWORD}"

# Or use CloudWatch
aws logs create-log-group --log-group-name /bintalk/api
aws logs create-log-stream --log-group-name /bintalk/api --log-stream-name api-server
```

### 9. Backup Strategy

Encrypted data is only recoverable if **three things are restored together**:

1. **PostgreSQL**: messages, file metadata and the *wrapped* data keys.
2. **Vault storage** (`vault_data` volume, file backend): the Transit key that unwraps the data
   keys. Without it, every message and file is permanently unreadable.
3. **The uploads volume** (`uploads_data`): the encrypted file contents.

A backup procedure for the Docker Compose deployment (take all three in one maintenance window,
in this order, and keep them together):

```bash
TS=$(date +%Y%m%d-%H%M%S); mkdir -p backup-$TS
# 1. Vault (file storage must be copied while Vault is stopped)
docker compose stop vault
docker run --rm -v bintalk_vault_data:/v:ro -v "$PWD/backup-$TS":/b alpine tar czf /b/vault.tgz -C /v .
docker compose start vault
# 2. Database
docker exec bintalk_postgres pg_dump -U bintalk -Fc bintalk_db > backup-$TS/db.dump
# 3. Uploads
docker run --rm -v bintalk_uploads_data:/u:ro -v "$PWD/backup-$TS":/b alpine tar czf /b/uploads.tgz -C /u .
# Encrypt the backup and copy it off this host.
```

(Volume names are prefixed with the Compose project name; check them with `docker volume ls`.)

- Keep old Vault key versions for as long as any backup that needs them is retained.
- With Vault integrated storage (raft), use `vault operator raft snapshot save` instead of the
  volume copy.
- **Test restores** regularly in an isolated environment: restore all three, start the stack, and
  check that old messages and files decrypt. Record how long it took; that is your real RTO.

### 10. Security Hardening

```bash
# Network Security
- Restrict database access to API servers only
- Enable VPC Flow Logs
- Use security groups for ingress/egress rules
- Enable WAF on ALB

# Database Security
- Enable encryption at rest (RDS encryption)
- Use SSL/TLS for connections
- Enable audit logging
- Restrict user privileges

# Application Security
- Enable HSTS headers
- Implement rate limiting
- Enable request signing (mTLS)
- Regular security updates

# Vault Security
- Enable audit logging
- Use unseal keys (AWS KMS recommended)
- Enable TLS for all communications
- Restrict policy access
```

## Monitoring Commands

```bash
# Check service health
curl -k https://api.bintalk.com/health

# View logs
kubectl logs -f deployment/bintalk-api -n bintalk

# Check database
psql -h <rds-endpoint> -U bintalk -d bintalk_db -c "SELECT * FROM users LIMIT 1;"

# Vault status
vault status

# Redis health
redis-cli -h <elasticache-endpoint> PING

# Kafka topics
kafka-topics --bootstrap-server broker1:9092 --list
```

## Scaling Considerations

### Horizontal Scaling
Not supported yet. Running more than one API instance needs, first:
- delivery of WebSocket events across instances (e.g. Redis pub/sub),
- shared call state (e.g. in Redis, with leases),
- shared object storage for uploads.
Migrations and the RSA key creation are already safe when several instances start at once.

### Vertical Scaling
- Increase instance sizes as needed
- Monitor CPU/memory usage
- Scale database compute separately from storage

## Disaster Recovery

Targets (not yet demonstrated by a restore drill):

### Recovery Time Objective (RTO): 1 hour
### Recovery Point Objective (RPO): 15 minutes

```bash
# Failover to standby Vault
vault failover --skip-verify

# Promote read replica to primary
aws rds promote-read-replica --db-instance-identifier bintalk-postgres-replica

# Restore from Kafka backup
kafka-consumer-groups --bootstrap-server broker1:9092 --reset-offsets --to-timestamp <timestamp>
```

## Post-Deployment Validation

1. **Functional Testing**: Run integration tests against production
2. **Performance Testing**: Load testing with expected traffic
3. **Security Testing**: Verify encryption, authentication, rate limiting
4. **Compliance**: Audit logging, data retention policies
5. **Monitoring**: Verify metrics and alerts are working

## Support and Maintenance

- Regular security patches (monthly)
- Database maintenance (weekly)
- Log rotation and cleanup (daily)
- Certificate renewal (60 days before expiry)
- Vault key rotation (every 90 days)
