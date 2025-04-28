from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from jose import jwt, JWTError
from pydantic import BaseModel
import httpx
import logging
import os
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = FastAPI()
security = HTTPBearer()

# Конфигурация
JWKS_URL = os.getenv("JWKS_URL")
AUDIENCE = os.getenv("AUDIENCE")
ISSUER = os.getenv("ISSUER")


class ReportItem(BaseModel):
    date: str
    movement_type: str
    duration: int
    accuracy: float


# Кешируем JWKS
jwks_cache = None


async def fetch_jwks():
    global jwks_cache
    if not jwks_cache:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(JWKS_URL)

                jwks_cache = response.json()
            except Exception as e:
                logger.error(f"JWKS fetch error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Service unavailable"
                )
    return jwks_cache


def get_rsa_key(header, jwks):
    for key in jwks.get("keys", []):
        if key["kid"] == header.get("kid"):
            return {
                "kty": key["kty"],
                "n": key["n"],
                "e": key["e"],
                "alg": key["alg"]
            }
    return None


async def verify_token(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        jwks = await fetch_jwks()
        rsa_key = get_rsa_key(header, jwks)
        if not rsa_key:
            raise JWTError("Invalid key ID")

        return jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER
        )

    except JWTError as e:
        logger.error(f"Token error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


async def get_current_user(credentials: HTTPBearer = Depends(security)) -> dict:
    try:
        return await verify_token(credentials.credentials)
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise


@app.get("/reports", response_model=list[ReportItem])
async def get_reports(user: dict = Depends(get_current_user)):
    logger.info(f"User {user.get('preferred_username')} accessed reports")

    return [
        ReportItem(
            date="2025-04-28",
            movement_type="grasp",
            duration=500,
            accuracy=0.95
        )
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8008)
