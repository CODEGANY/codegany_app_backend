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


class MaterialResponse(BaseModel):
    """Pydantic model representing a material's data in response objects.

    Attributes:
        material_id: Unique identifier for the material
        name: Name of the material
        category: Category the material belongs to
        unit_price: Price per unit of the material
        supplier_id: ID of the supplier providing this material
        stock_available: Current available stock quantity
    """
    material_id: int
    name: str
    category: str
    unit_price: float
    supplier_id: int
    stock_available: int


class PaginatedMaterialsResponse(BaseModel):
    """Pydantic model representing a paginated response of materials.
    
    Attributes:
        data: List of materials for the current page
        total_count: Total number of materials in the database
        page: Current page number
        page_size: Number of items per page
        total_pages: Total number of pages available
    """
    data: List[MaterialResponse]
    total_count: int
    page: int
    page_size: int
    total_pages: int


@app.get("/api/v1/materials", response_model=PaginatedMaterialsResponse, tags=["Materials"])
async def get_materials(
    page: int = 1, 
    page_size: int = 10,
    user: Dict[str, Any] = Depends(get_current_user)
) -> PaginatedMaterialsResponse:
    """Retrieves materials from the database with pagination support.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        page: Page number to retrieve (starts from 1)
        page_size: Number of items per page
        user: User payload from the decoded JWT token
    
    Returns:
        PaginatedMaterialsResponse: Paginated list of materials with metadata
    
    Raises:
        HTTPException(400): If pagination parameters are invalid
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        if page < 1:
            raise HTTPException(
                status_code=400, detail="Page number must be greater than or equal to 1"
            )
        
        if page_size < 1:
            raise HTTPException(
                status_code=400, detail="Page size must be greater than or equal to 1"
            )
            
        # Calculate pagination parameters
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size - 1
        
        # Get total count of materials
        count_response = supabase_client.table("materials").select("*", count="exact").execute()
        total_count = count_response.count
        
        # Get paginated materials
        materials_response = (
            supabase_client.table("materials")
            .select("*")
            .range(start_idx, end_idx)
            .execute()
        )
        
        total_pages = (total_count + page_size - 1) // page_size
        
        return PaginatedMaterialsResponse(
            data=materials_response.data,
            total_count=total_count,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve materials: {str(e)}"
        )


class MaterialUpdateRequest(BaseModel):
    """Pydantic model for updating a material.
    
    Attributes:
        name: Updated name of the material
        category: Updated category of the material
        unit_price: Updated price per unit
        supplier_id: Updated ID of the supplier
        stock_available: Updated stock quantity
    """
    name: Optional[str] = None
    category: Optional[str] = None
    unit_price: Optional[float] = None
    supplier_id: Optional[int] = None
    stock_available: Optional[int] = None


@app.put("/api/v1/materials/{material_id}", response_model=MaterialResponse, tags=["Materials"])
async def update_material(
    material_id: int,
    material_data: MaterialUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> MaterialResponse:
    """Updates a material with the specified ID.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role are authorized to update materials.
    
    Args:
        material_id: ID of the material to update
        material_data: New data for the material
        user: User payload from the decoded JWT token
    
    Returns:
        MaterialResponse: The updated material data
    
    Raises:
        HTTPException(400): If the request body is invalid
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the material is not found
        HTTPException(500): If there's an error updating the database
    """
    try:
        # Check if user has the appropriate role
        user_email = user.get("email")
        user_response = supabase_client.table("users").select("role").eq("email", user_email).execute()
        
        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")
            
        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, 
                detail="Only logistics managers can update materials"
            )
        
        # Check if material exists
        material_check = (
            supabase_client.table("materials")
            .select("material_id")
            .eq("material_id", material_id)
            .execute()
        )
        
        if not material_check.data:
            raise HTTPException(status_code=404, detail=f"Material with ID {material_id} not found")
        
        # Prepare update data (only include non-None fields)
        update_data = {k: v for k, v in material_data.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No update data provided")
            
        # Update the material
        updated_material = (
            supabase_client.table("materials")
            .update(update_data)
            .eq("material_id", material_id)
            .execute()
        )
        
        if not updated_material.data:
            raise HTTPException(status_code=500, detail="Failed to update material")
            
        return updated_material.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update material: {str(e)}"
        )


@app.delete("/api/v1/materials/{material_id}", tags=["Materials"])
async def delete_material(
    material_id: int,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, str]:
    """Deletes a material with the specified ID.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role are authorized to delete materials.
    
    Args:
        material_id: ID of the material to delete
        user: User payload from the decoded JWT token
    
    Returns:
        Dict[str, str]: A message indicating successful deletion
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the material is not found
        HTTPException(409): If the material is referenced in request items or orders
        HTTPException(500): If there's an error updating the database
    """
    try:
        # Check if user has the appropriate role
        user_email = user.get("email")
        user_response = supabase_client.table("users").select("role").eq("email", user_email).execute()
        
        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")
            
        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, 
                detail="Only logistics managers can delete materials"
            )
        
        # Check if material exists
        material_check = (
            supabase_client.table("materials")
            .select("material_id")
            .eq("material_id", material_id)
            .execute()
        )
        
        if not material_check.data:
            raise HTTPException(status_code=404, detail=f"Material with ID {material_id} not found")
        
        # Check if material is referenced in request items
        request_items_check = (
            supabase_client.table("request_items")
            .select("request_item_id")
            .eq("material_id", material_id)
            .limit(1)
            .execute()
        )
        
        if request_items_check.data:
            raise HTTPException(
                status_code=409,
                detail="Cannot delete material that is referenced in purchase requests"
            )
            
        # Check if material is referenced in order items
        order_items_check = (
            supabase_client.table("order_items")
            .select("order_item_id")
            .eq("material_id", material_id)
            .limit(1)
            .execute()
        )
        
        if order_items_check.data:
            raise HTTPException(
                status_code=409,
                detail="Cannot delete material that is referenced in orders"
            )
        
        # Delete the material
        delete_result = (
            supabase_client.table("materials")
            .delete()
            .eq("material_id", material_id)
            .execute()
        )
        
        if not delete_result.data:
            raise HTTPException(status_code=500, detail="Failed to delete material")
            
        return {"message": f"Material with ID {material_id} successfully deleted"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to delete material: {str(e)}"
        )


class UserRegistrationRequest(BaseModel):
    """Pydantic model for user registration requests.
    
    Attributes:
        username: User's login username
        first_name: User's first name
        last_name: User's last name
        cin: User's identification number
        phone: User's phone number
        role: User's role in the system (logistique or daf)
        email: User's email address
    """
    username: str
    first_name: str
    last_name: str
    cin: str
    phone: str
    role: str  # Should be either 'logistique' or 'daf'
    email: str


@app.post("/api/v1/users/register", response_model=UserResponse, tags=["Users"])
async def register_user(user_data: UserRegistrationRequest) -> UserResponse:
    """Registers a new user in the system.
    
    This endpoint creates a new user with the provided information.
    
    Args:
        user_data: User registration information
    
    Returns:
        UserResponse: Object containing existence flag and user data if registration is successful
    
    Raises:
        HTTPException(400): If the request contains invalid data or role
        HTTPException(409): If a user with the same email or username already exists
        HTTPException(500): If there's an error creating the user in the database
    """
    try:
        # Validate role
        if user_data.role not in ["logistique", "daf"]:
            raise HTTPException(
                status_code=400, 
                detail="Invalid role. Must be either 'logistique' or 'daf'"
            )
            
        # Check if user with the same email already exists
        email_check = (
            supabase_client.table("users")
            .select("email")
            .eq("email", user_data.email)
            .execute()
        )
        
        if email_check.data:
            raise HTTPException(
                status_code=409,
                detail="A user with this email already exists"
            )
            
        # Check if user with the same username already exists
        username_check = (
            supabase_client.table("users")
            .select("username")
            .eq("username", user_data.username)
            .execute()
        )
        
        if username_check.data:
            raise HTTPException(
                status_code=409,
                detail="A user with this username already exists"
            )
        
        # Create the user in the database
        user_result = (
            supabase_client.table("users")
            .insert(user_data.dict())
            .execute()
        )
        
        if not user_result.data:
            raise HTTPException(status_code=500, detail="Failed to create user")
        
        # Return the created user
        return UserResponse(exists=True, user_data=user_result.data[0])
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to register user: {str(e)}"
        )
