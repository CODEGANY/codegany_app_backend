import os
import json
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
from supabase import create_client

load_dotenv()

app: FastAPI = FastAPI(
    title="Equipment Purchase Management API",
    description="API for managing equipment purchases in companies",
    version="1.0.0",
)

# CORS Configuration - Allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Load environment variables
supabase_url: str = os.environ.get("SUPABASE_PROJECT_URL")
supabase_key: str = os.environ.get("SUPABASE_API_KEY")

# Initialize Supabase client
supabase_client = create_client(supabase_url, supabase_key)


@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint that returns a simple greeting.
    
    Returns:
        Dict[str, str]: A greeting message
    """
    return {"Hello": "World"}


class AuthError(Exception):
    """Custom exception class for authentication errors."""
    
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class TokenRequest(BaseModel):
    """Pydantic model representing the token request from frontend.
    
    Attributes:
        token: JWT token for authentication
    """
    token: str


async def extract_token(request: Request) -> str:
    """Extract the JWT token from the request body.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        str: The extracted JWT token
        
    Raises:
        HTTPException: If the token is missing or invalid
    """
    try:
        # Parse request body as JSON
        body = await request.json()
        
        # Check if token exists in the request body
        if not body or "token" not in body:
            raise HTTPException(status_code=401, detail="Token missing in request body")
        
        return body["token"]
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in request body")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to extract token: {str(e)}")


async def get_current_user(token: str = Depends(extract_token)) -> Dict[str, Any]:
    """Decode the JWT token sent from frontend without verification.
    
    Args:
        token: JWT token extracted from the request body
        
    Returns:
        Dict[str, Any]: The decoded JWT payload
        
    Raises:
        HTTPException: If token decoding fails
    """
    try:
        # Decode the JWT token without verification
        # Setting verify_signature=False allows us to decode the token without checking signature
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload
    except jwt.DecodeError:
        raise HTTPException(status_code=401, detail="Invalid token format")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token decoding error: {str(e)}")


class SupplierResponse(BaseModel):
    """Pydantic model representing a supplier's data in response objects.

    Attributes:
        supplier_id: Unique identifier for the supplier
        supplier_name: Name of the supplier company
        supplier_description: Optional description of the supplier
        supplier_email: Optional email contact for the supplier
    """
    supplier_id: int
    supplier_name: str
    supplier_description: Optional[str] = None
    supplier_email: Optional[str] = None


@app.get("/api/v1/suppliers", response_model=List[SupplierResponse], tags=["Suppliers"])
async def get_suppliers(user: Dict[str, Any] = Depends(get_current_user)) -> List[SupplierResponse]:
    """Retrieves all suppliers from the database.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        user: User payload from the decoded JWT token
    
    Returns:
        List[SupplierResponse]: List of all suppliers in the database
    
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


class UserResponse(BaseModel):
    """Pydantic model representing user data in response objects.

    Attributes:
        exists: Boolean indicating if the user exists in the database
        user_data: Optional user data if the user exists
    """
    exists: bool
    user_data: Optional[Dict[str, Any]] = None


@app.post(
    "/api/v1/auth/check-user", response_model=UserResponse, tags=["Authentication"]
)
async def check_user(user: Dict[str, Any] = Depends(get_current_user)) -> UserResponse:
    """Checks if the authenticated user exists in the database and returns their information.

    This endpoint requires authentication via JWT token in request body.

    Args:
        user: User payload from the decoded JWT token

    Returns:
        UserResponse: Object containing existence flag and user data if found

    Raises:
        HTTPException(500): If there's an error accessing the database
    """
    try:
        # Get the email from the decoded JWT token
        user_email = user.get("email")
        
        if not user_email:
            raise HTTPException(status_code=400, detail="Email not found in token")
            
        # Query the database using email instead of user_id
        response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )
        
        exists = len(response.data) > 0
        user_data = response.data[0] if exists else None
        
        return UserResponse(exists=exists, user_data=user_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
