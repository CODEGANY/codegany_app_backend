import os
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from authlib.jose import jwt
from authlib.jose import jwk
import functools
import requests
from supabase import create_client

load_dotenv()

app: FastAPI = FastAPI()
auth0_domain: str = os.environ.get("AUTH0_DOMAIN")
auth0_audience: str = os.environ.get("AUTH0_AUDIENCE")
supabase_url: str = os.environ.get("SUPABASE_PROJECT_URL")
supabase_key: str = os.environ.get("SUPABASE_API_KEY")

# Initialize Supabase client
supabase_client = create_client(supabase_url, supabase_key)


@app.get("/")
def root():
    return {"Hello": "World"}


# Cache for JWKS
@functools.lru_cache(maxsize=1)
def get_jwks():
    jwks_url = f"https://{auth0_domain}/.well-known/jwks.json"
    response = requests.get(jwks_url)
    return response.json()


# Function to validate token
def validate_token(token):
    jwks = get_jwks()
    headers = jwt.get_unverified_headers(token)
    kid = headers["kid"]
    for key in jwks["keys"]:
        if key["kid"] == kid:
            public_key = jwk.JWK.from_dict(key)
            try:
                payload = jwt.decode(
                    token,
                    public_key,
                    audience=auth0_audience,
                    issuer=f"https://{auth0_domain}/",
                )
                return payload
            except Exception as e:
                raise HTTPException(status_code=401, detail=str(e))
    raise HTTPException(status_code=401, detail="Invalid token")


# Function to extract token from header
def extract_token(request):
    authorization_header = request.headers.get("Authorization")
    if not authorization_header or not authorization_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token missing or invalid")
    return authorization_header.split(" ")[1]


# Dependency to get the user from the token
async def get_current_user(token: str = Depends(extract_token)):
    try:
        payload = validate_token(token)
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


# Models for Supplier operations
class SupplierResponse(BaseModel):
    """
    Pydantic model representing a supplier's data in response objects.

    Attributes:
        supplier_id: Unique identifier for the supplier
        supplier_name: Name of the supplier company
        supplier_description: Optional description of the supplier
        supplier_email: Optional email contact for the supplier
    """

    supplier_id: int
    supplier_name: str
    supplier_description: str | None = None
    supplier_email: str | None = None


@app.get("/api/v1/suppliers", response_model=list[SupplierResponse], tags=["Suppliers"])
async def get_suppliers(user: dict = Depends(get_current_user)) -> list[SupplierResponse]:
    """
    Retrieves all suppliers from the database.
    
    This endpoint requires authentication via Bearer token.
    
    Args:
        user: User payload from the validated JWT token
    
    Returns:
        list[SupplierResponse]: List of all suppliers in the database
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        response = supabase_client.table("suppliers").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve suppliers: {str(e)}"
        )


# Endpoint to check if user exists and get user data
class UserResponse(BaseModel):
    """
    Pydantic model representing user data in response objects.

    Attributes:
        exists: Boolean indicating if the user exists in the database
        user_data: Optional user data if the user exists
    """

    exists: bool
    user_data: dict | None = None


@app.get(
    "/api/v1/auth/check-user", response_model=UserResponse, tags=["Authentication"]
)
async def check_user(user: dict = Depends(get_current_user)) -> UserResponse:
    """
    Checks if the authenticated user exists in the database and returns their information.

    This endpoint requires authentication via Bearer token.

    Args:
        user: User payload from the validated JWT token

    Returns:
        UserResponse: Object containing existence flag and user data if found

    Raises:
        HTTPException(500): If there's an error accessing the database
    """
    user_id = user["sub"]
    try:
        response = (
            supabase_client.table("Users").select("*").eq("user_id", user_id).execute()
        )
        exists = len(response.data) > 0
        user_data = response.data[0] if exists else None
        return UserResponse(exists=exists, user_data=user_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
