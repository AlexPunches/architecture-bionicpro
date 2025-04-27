from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel
import httpx
from jose.constants import ALGORITHMS
import os
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
security = HTTPBearer()

# Keycloak configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
REALM_NAME = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"

class ReportItem(BaseModel):
    date: str
    movement_type: str
    duration: int
    accuracy: float

async def get_jwks() -> dict:
    """Fetch JWKS keys from Keycloak"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(JWKS_URL, timeout=5.0)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to verify token - Keycloak unavailable"
            )

async def verify_token(token: str) -> dict:
    """Verify JWT token and return payload"""
    try:
        # Get token header to find the right key
        header = jwt.get_unverified_header(token)
        
        # Fetch JWKS keys
        jwks = await get_jwks()
        
        # Find the matching key
        rsa_key = {}
        for key in jwks.get("keys", []):
            if key["kid"] == header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                    "alg": key["alg"]
                }
                break
        
        if not rsa_key:
            logger.error("No matching key found in JWKS")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        # Verify token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=[ALGORITHMS.RS256],
            audience=CLIENT_ID,
            issuer=f"{KEYCLOAK_URL}/realms/{REALM_NAME}"
        )
        
        return payload
        
    except JWTError as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Dependency to get current user from JWT token"""
    token = credentials.credentials
    try:
        payload = await verify_token(token)
        
        # Check if user has required role
        if "prothetic_user" not in payload.get("realm_access", {}).get("roles", []):
            logger.warning(f"User {payload.get('preferred_username')} lacks required role")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
            
        logger.info(f"Authenticated user: {payload.get('preferred_username')}")
        return payload
        
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        raise

@app.get("/reports", response_model=list[ReportItem])
async def get_reports(current_user: dict = Depends(get_current_user)):
    """Get reports for authenticated user"""
    logger.info(f"Returning reports for user: {current_user.get('preferred_username')}")
    
    # Mock data - replace with DB query in production
    return [
        ReportItem(
            date="2023-01-01",
            movement_type="grasp",
            duration=500,
            accuracy=0.95
        ),
        ReportItem(
            date="2023-01-02",
            movement_type="lift",
            duration=300,
            accuracy=0.87
        )
    ]

@app.on_event("startup")
async def startup_event():
    """Verify Keycloak connection on startup"""
    logger.info("Starting API service")
    logger.info(f"Keycloak URL: {KEYCLOAK_URL}")
    logger.info(f"Realm: {REALM_NAME}")
    
    try:
        jwks = await get_jwks()
        if not jwks.get("keys"):
            logger.error("No keys found in JWKS")
            raise RuntimeError("Keycloak configuration invalid")
        logger.info("Successfully connected to Keycloak")
    except Exception as e:
        logger.critical(f"Keycloak connection failed: {str(e)}")
        raise
