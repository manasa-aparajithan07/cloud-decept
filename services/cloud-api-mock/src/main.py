from fastapi import FastAPI, Request, Response, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from contextlib import asynccontextmanager
import httpx
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pathlib import Path
import random
import asyncio

from config import settings
from mock_data.profiles import (
    get_profile, generate_aws_metadata, CLOUD_PROFILES,
    generate_fake_instances, generate_fake_volumes, generate_fake_vpcs,
    generate_fake_subnets, generate_fake_security_groups, generate_fake_buckets,
    generate_fake_iam_users, generate_fake_iam_roles
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# HTTP clients for backend services
http_client: Optional[httpx.AsyncClient] = None
event_collector_client: Optional[httpx.AsyncClient] = None



@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client, event_collector_client
    http_client = httpx.AsyncClient(timeout=30.0)
    event_collector_client = httpx.AsyncClient(timeout=30.0)
    logger.info("Cloud API Mock starting up (rule-based)")
    yield
    await http_client.aclose()
    await event_collector_client.aclose()
    logger.info("Cloud API Mock shutting down")


app = FastAPI(
    title="CloudDecept Cloud API Mock",
    description="Fake AWS/Azure/GCP APIs for honeypot deception",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session storage for consistency
session_contexts: Dict[str, Dict] = {}


def get_session_id(request: Request, x_session_id: Optional[str] = Header(None)) -> str:
    """Get or create session ID for consistency"""
    if x_session_id:
        return x_session_id
    session_id = request.query_params.get("session_id", str(uuid.uuid4()))
    return session_id


def get_org_profile(session_id: str) -> str:
    """Get organization profile for session"""
    if session_id in session_contexts:
        return session_contexts[session_id].get("org_profile", settings.DEFAULT_ORG_PROFILE)
    return settings.DEFAULT_ORG_PROFILE


async def classify_intent(session_id: str, commands: List[Dict]) -> Dict[str, Any]:
    """Classify intent by calling Intent Engine service"""
    if not http_client:
        logger.error("HTTP client not initialized")
        return {"intent": "unknown", "confidence": 0.0}

    try:
        profile = get_org_profile(session_id)
        org_profile = get_profile(profile)
        cmd_list = [c.get("cmd", str(c)) for c in commands[-10:]]

        response = await http_client.post(
            f"{settings.INTENT_ENGINE_URL}/classify",
            json={
                "session_id": session_id,
                "organization_profile": profile,
                "commands": cmd_list,
                "context": {
                    "session_duration_seconds": time.time() - session_contexts.get(session_id, {}).get("start_time", time.time()),
                    "previous_intents": session_contexts.get(session_id, {}).get("intents", []),
                }
            }
        )

        if response.status_code == 200:
            result = response.json()
            if session_id not in session_contexts:
                session_contexts[session_id] = {"intents": [], "start_time": time.time()}
            session_contexts[session_id]["intents"].append(result.get("intent"))

            # Persist intent to session in ClickHouse via event collector
            if event_collector_client:
                try:
                    update_response = await event_collector_client.post(
                        f"{settings.EVENT_COLLECTOR_URL}/update-session",
                        json={
                            "session_id": session_id,
                            "intent": result.get("intent")
                        }
                    )
                    if update_response.status_code == 200:
                        update_result = update_response.json()
                        if update_result.get("success"):
                            logger.info(f"Updated session {session_id} with intent={result.get('intent')}")
                        else:
                            logger.warning(f"Failed to update session {session_id}: {update_result.get('error')}")
                    else:
                        logger.warning(f"Event collector returned {update_response.status_code} for session update")
                except Exception as e:
                    logger.warning(f"Failed to persist session intent: {e}")

            return result
        else:
            logger.warning(f"Intent Engine returned {response.status_code}: {response.text}")
            return {"intent": "unknown", "confidence": 0.0}
    except Exception as e:
        logger.error(f"Intent classification failed: {e}")
        return {"intent": "unknown", "confidence": 0.0}


async def adapt_response(
    intent: str,
    original_response: Dict,
    session_id: str,
    endpoint: str
) -> Dict:
    """Adapt response based on predicted intent using Adaptive Engine"""
    if not settings.ADAPTATION_ENABLED or not http_client:
        return original_response

    try:
        context = session_contexts.get(session_id, {})
        response = await http_client.post(
            f"{settings.ADAPTIVE_ENGINE_URL}/adapt",
            json={
                "intent": intent,
                "original_response": original_response,
                "session_context": context,
                "endpoint": endpoint
            }
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.warning(f"Response adaptation failed: {e}")
    return original_response


async def log_event(
    session_id: str,
    event_type: str,
    endpoint: str,
    request_data: Dict,
    response_data: Dict,
    intent: str = "unknown",
    adaptation_applied: bool = False
):
    """Log event to Event Collector (async, fire-and-forget)"""
    if not event_collector_client:
        return

    try:
        event = {
            "source": "cloud_api_mock",
            "event_type": "cloud_api",
            "session_id": session_id,
            "attacker_ip": "unknown",  # Would come from request context
            "payload": {
                "http_method": "GET",
                "endpoint": endpoint,
                "path": endpoint,
                "request_body": request_data,
                "response_body": response_data,
                "response_status": 200,
                "cloud_provider": "aws",  # Would be determined from endpoint
                "intent": intent,
                "adaptation_applied": adaptation_applied,
                "metadata": {
                    "org_profile": get_org_profile(session_id),
                }
            }
        }
        await event_collector_client.post(
            f"{settings.EVENT_COLLECTOR_URL}/ingest",
            json=event
        )
    except Exception as e:
        logger.warning(f"Event logging failed: {e}")


# =============================================================================
# AWS ENDPOINTS
# =============================================================================

@app.get("/aws/ec2/describe-instances")
async def aws_describe_instances(
    request: Request,
    session_id: str = Depends(get_session_id),
    x_session_id: Optional[str] = Header(None)
):
    """Mock EC2 DescribeInstances"""
    profile = get_profile(get_org_profile(session_id))
    instances = generate_fake_instances(profile)

    response = {
        "Reservations": [{
            "Instances": instances,
            "ReservationId": f"r-{''.join(['0123456789abcdef'[int(c,16)] for c in str(uuid.uuid4()).replace('-','')][:17])}",
            "OwnerId": profile.account_id,
            "RequesterId": profile.account_id,
        }]
    }

    # Process classification, adaptation, and logging in the background to avoid blocking the response
    async def process_background_tasks():
        try:
            # Classify intent
            intent_result = await classify_intent(session_id, [
                {"cmd": "aws ec2 describe-instances", "endpoint": "/aws/ec2/describe-instances"}
            ])

            # Adapt response
            adapted = await adapt_response(
                intent_result.get("intent", "cloud_recon"),
                response,
                session_id,
                "/aws/ec2/describe-instances"
            )

            await log_event(session_id, "api_call", "/aws/ec2/describe-instances",
                            {}, adapted, intent_result.get("intent"), True)
        except Exception as e:
            logger.warning(f"Background processing failed for describe-instances: {e}")

    # Fire-and-forget the background tasks
    asyncio.create_task(process_background_tasks())

    return response


@app.get("/aws/ec2/describe-volumes")
async def aws_describe_volumes(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock EC2 DescribeVolumes"""
    profile = get_profile(get_org_profile(session_id))
    volumes = generate_fake_volumes(profile)
    return {"Volumes": volumes}


@app.get("/aws/ec2/describe-vpcs")
async def aws_describe_vpcs(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock EC2 DescribeVpcs"""
    profile = get_profile(get_org_profile(session_id))
    return {"Vpcs": generate_fake_vpcs(profile)}


@app.get("/aws/ec2/describe-subnets")
async def aws_describe_subnets(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock EC2 DescribeSubnets"""
    profile = get_profile(get_org_profile(session_id))
    return {"Subnets": generate_fake_subnets(profile)}


@app.get("/aws/ec2/describe-security-groups")
async def aws_describe_security_groups(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock EC2 DescribeSecurityGroups"""
    profile = get_profile(get_org_profile(session_id))
    return {"SecurityGroups": generate_fake_security_groups(profile)}


@app.get("/aws/s3/list-buckets")
async def aws_list_buckets(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock S3 ListBuckets"""
    profile = get_profile(get_org_profile(session_id))
    buckets = generate_fake_buckets(profile)
    return {"Buckets": buckets, "Owner": {"DisplayName": profile.name, "ID": profile.account_id}}


@app.get("/aws/iam/list-users")
async def aws_list_users(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock IAM ListUsers"""
    profile = get_profile(get_org_profile(session_id))
    users = generate_fake_iam_users(profile)
    return {"Users": users, "IsTruncated": False}


@app.get("/aws/iam/list-roles")
async def aws_list_roles(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock IAM ListRoles"""
    profile = get_profile(get_org_profile(session_id))
    roles = generate_fake_iam_roles(profile)
    return {"Roles": roles, "IsTruncated": False}


@app.post("/aws/sts/assume-role")
async def aws_assume_role(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock STS AssumeRole - returns fake credentials"""
    body = await request.json()
    role_arn = body.get("RoleArn", "")
    role_session_name = body.get("RoleSessionName", "honeypot-session")

    # Generate fake temporary credentials
    fake_credentials = {
        "AccessKeyId": f"ASIA{''.join(['0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[int(c,16)] for c in str(uuid.uuid4()).replace('-','')][:16])}",
        "SecretAccessKey": f"{''.join(['0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'[int(c,16)%62] for c in str(uuid.uuid4()).replace('-','')][:40])}",
        "SessionToken": f"IQoJb3JpZ2luX2VjE...{''.join(['0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'[int(c,16)%62] for c in str(uuid.uuid4()).replace('-','')][:300])}",
        "Expiration": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    response = {
        "Credentials": fake_credentials,
        "AssumedRoleUser": {
            "AssumedRoleId": f"AROA{''.join(['0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[int(c,16)] for c in str(uuid.uuid4()).replace('-','')][:16])}:{role_session_name}",
            "Arn": role_arn,
        },
        "PackedPolicySize": 0,
    }

    intent_result = await classify_intent(session_id, [
        {"cmd": "aws sts assume-role", "endpoint": "/aws/sts/assume-role", "role_arn": role_arn}
    ])

    # If credential hunting, make credentials look more real
    if intent_result.get("intent") == "credential_hunting":
        response["Credentials"]["AccessKeyId"] = "AKIAIOSFODNN7EXAMPLE"
        response["Credentials"]["SecretAccessKey"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    await log_event(session_id, "api_call", "/aws/sts/assume-role",
                    {"role_arn": role_arn}, response, intent_result.get("intent"), True)

    return response


# =============================================================================
# AZURE ENDPOINTS
# =============================================================================

@app.get("/azure/vm/list")
async def azure_list_vms(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock Azure VM List"""
    profile = get_profile(get_org_profile(session_id))
    generators = CLOUD_PROFILES["azure"]["generators"]
    vms = generators["vms"](profile)
    return {"value": vms, "nextLink": None}


@app.get("/azure/storage/list")
async def azure_list_storage(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock Azure Storage List"""
    profile = get_profile(get_org_profile(session_id))
    generators = CLOUD_PROFILES["azure"]["generators"]
    storage = generators["storage"](profile)
    return {"value": storage}


@app.get("/azure/ad/users")
async def azure_list_ad_users(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock Azure AD Users"""
    profile = get_profile(get_org_profile(session_id))
    return {"value": [
        {"id": f"{''.join(['0123456789abcdef'[int(c,16)] for c in str(uuid.uuid4()).replace('-','')])}",
         "userPrincipalName": f"admin@{profile.name.lower().replace(' ', '')}.onmicrosoft.com",
         "displayName": "Admin User"},
        {"id": f"{''.join(['0123456789abcdef'[int(c,16)] for c in str(uuid.uuid4()).replace('-','')])}",
         "userPrincipalName": f"ci-cd@{profile.name.lower().replace(' ', '')}.onmicrosoft.com",
         "displayName": "CI/CD Service Account"},
    ]}


# =============================================================================
# GCP ENDPOINTS
# =============================================================================

@app.get("/gcp/compute/instances/list")
async def gcp_list_instances(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock GCP Compute Instances List"""
    profile = get_profile(get_org_profile(session_id))
    generators = CLOUD_PROFILES["gcp"]["generators"]
    instances = generators["instances"](profile)
    return {"items": instances}


@app.get("/gcp/storage/buckets/list")
async def gcp_list_buckets(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock GCP Storage Buckets List"""
    profile = get_profile(get_org_profile(session_id))
    return {"items": [
        {"name": f"{profile.name.lower().replace(' ', '-')}-{b}", "id": b}
        for b in ["data-bucket", "logs-bucket", "backup-bucket", "ml-models"]
    ]}


@app.get("/gcp/iam/service-accounts/list")
async def gcp_list_service_accounts(
    request: Request,
    session_id: str = Depends(get_session_id)
):
    """Mock GCP IAM Service Accounts"""
    profile = get_profile(get_org_profile(session_id))
    return {"accounts": [
        {"email": f"compute@{profile.account_id}.iam.gserviceaccount.com", "name": "Compute Engine default service account"},
        {"email": f"ci-cd@{profile.account_id}.iam.gserviceaccount.com", "name": "CI/CD Service Account"},
    ]}


# =============================================================================
# METADATA API (Simulates 169.254.169.254)
# =============================================================================

@app.get("/meta-data/")
async def metadata_root():
    """Metadata service root"""
    return PlainTextResponse("""
instance-id
instance-type
placement/
local-ipv4
public-ipv4
ami-id
ami-launch-index
ami-manifest-path
ancestor-ami-ids
block-device-mapping/
instance-action
instance-life-cycle
local-hostname
mac
network/
profile
public-keys/
reservation-id
security-groups
services/
""")


@app.get("/meta-data/instance-id")
async def metadata_instance_id(session_id: str = Depends(get_session_id)):
    profile = get_profile(get_org_profile(session_id))
    return PlainTextResponse(generate_aws_metadata(profile)["instance-id"])


@app.get("/meta-data/instance-type")
async def metadata_instance_type(session_id: str = Depends(get_session_id)):
    profile = get_profile(get_org_profile(session_id))
    return PlainTextResponse(random.choice(profile.instance_types))


@app.get("/meta-data/placement/availability-zone")
async def metadata_az(session_id: str = Depends(get_session_id)):
    profile = get_profile(get_org_profile(session_id))
    region = random.choice(profile.regions)
    return PlainTextResponse(f"{region}{random.choice(['a','b','c'])}")


@app.get("/meta-data/local-ipv4")
async def metadata_local_ipv4(session_id: str = Depends(get_session_id)):
    profile = get_profile(get_org_profile(session_id))
    return PlainTextResponse(generate_aws_metadata(profile)["local-ipv4"])


@app.get("/meta-data/public-ipv4")
async def metadata_public_ipv4(session_id: str = Depends(get_session_id)):
    profile = get_profile(get_org_profile(session_id))
    return PlainTextResponse(generate_aws_metadata(profile)["public-ipv4"])


@app.get("/meta-data/ami-id")
async def metadata_ami_id(session_id: str = Depends(get_session_id)):
    return PlainTextResponse(f"ami-{''.join(random.choices('0123456789abcdef', k=8))}")


@app.get("/meta-data/iam/security-credentials/")
async def metadata_iam_roles(session_id: str = Depends(get_session_id)):
    profile = get_profile(get_org_profile(session_id))
    roles = [r["RoleName"] for r in generate_fake_iam_roles(profile)]
    return PlainTextResponse("\n".join(roles))


@app.get("/meta-data/iam/security-credentials/{role_name}")
async def metadata_iam_credentials(role_name: str, session_id: str = Depends(get_session_id)):
    """Return fake IAM role credentials"""
    return JSONResponse({
        "Code": "Success",
        "LastUpdated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "Type": "AWS-HMAC",
        "AccessKeyId": f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
        "SecretAccessKey": f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+', k=40))}",
        "Token": f"IQoJb3JpZ2luX2VjE...{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=200))}",
        "Expiration": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })


# =============================================================================
# HEALTH & INFO
# =============================================================================

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "cloud-api-mock", "version": "1.0.0"}


@app.get("/")
async def root():
    return {
        "service": "CloudDecept Cloud API Mock",
        "version": "1.0.0",
        "endpoints": {
            "aws": ["/aws/ec2/describe-instances", "/aws/s3/list-buckets", "/aws/iam/list-users", "/aws/sts/assume-role"],
            "azure": ["/azure/vm/list", "/azure/storage/list", "/azure/ad/users"],
            "gcp": ["/gcp/compute/instances/list", "/gcp/storage/buckets/list", "/gcp/iam/service-accounts/list"],
            "metadata": ["/meta-data/", "/meta-data/instance-id", "/meta-data/iam/security-credentials/"]
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)