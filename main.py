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
    """Extract the JWT token from the request.
    
    For GET and other methods without a body, extracts token from Authorization header.
    For methods that can have a body (POST, PUT, etc.), checks both Authorization header
    and request body.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        str: The extracted JWT token
        
    Raises:
        HTTPException: If the token is missing or invalid
    """
    # First try to get token from Authorization header (works for all request methods)
    auth_header = request.headers.get("Authorization")
    if (auth_header and auth_header.startswith("Bearer ")):
        return auth_header[7:]  # Remove "Bearer " prefix
    
    # For methods that can have a body, try to get token from request body
    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        try:
            body = await request.json()
            if body and "token" in body:
                return body["token"]
        except json.JSONDecodeError:
            # If JSON parsing fails, continue to error handling
            pass
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse request body: {str(e)}")
    
    # If we reach here, no token was found
    raise HTTPException(
        status_code=401, 
        detail="Authorization token missing. Please provide a JWT token in the Authorization header" +
               (" or request body" if request.method != "GET" else "")
    )


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
            supabase_client.table("requestitems")
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
            supabase_client.table("orderitems")
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


class MaterialCreateRequest(BaseModel):
    """Pydantic model for creating a new material.
    
    Attributes:
        name: Name of the material
        category: Category of the material
        unit_price: Price per unit
        supplier_id: ID of the supplier
        stock_available: Initial stock quantity
    """
    name: str
    category: str
    unit_price: float
    supplier_id: int
    stock_available: int


@app.post("/api/v1/materials", response_model=MaterialResponse, tags=["Materials"])
async def create_material(
    material_data: MaterialCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> MaterialResponse:
    """Creates a new material.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role are authorized to create materials.
    
    Args:
        material_data: Data for the new material
        user: User payload from the decoded JWT token
    
    Returns:
        MaterialResponse: The created material data
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
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
                detail="Only logistics managers can create materials"
            )
            
        # Insert the new material
        material_result = (
            supabase_client.table("materials")
            .insert(material_data.dict())
            .execute()
        )
        
        if not material_result.data:
            raise HTTPException(status_code=500, detail="Failed to create material")
            
        return material_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create material: {str(e)}"
        )


# Purchase Requests Models and Routes
class PurchaseRequestResponse(BaseModel):
    """Pydantic model for purchase request responses.
    
    Attributes:
        request_id: Unique identifier for the request
        user_id: ID of the user who created the request
        created_at: Timestamp when the request was created
        status: Current status of the request
        justification: Reason for the purchase request
    """
    request_id: int
    user_id: int
    created_at: str  # Using str to handle timestamp serialization
    status: str  # Using request_status enum values
    justification: str


class PurchaseRequestCreateRequest(BaseModel):
    """Pydantic model for creating a new purchase request.
    
    Attributes:
        justification: Reason for the purchase request
        items: List of items to include in the request
    """
    justification: str
    items: List[Dict[str, Any]]  # Will contain material_id, quantity, estimated_cost


class PurchaseRequestUpdateRequest(BaseModel):
    """Pydantic model for updating a purchase request.
    
    Attributes:
        status: New status for the request
        justification: Updated justification for the request
    """
    status: Optional[str] = None
    justification: Optional[str] = None


@app.post("/api/v1/purchase-requests", response_model=PurchaseRequestResponse, tags=["Purchase Requests"])
async def create_purchase_request(
    request_data: PurchaseRequestCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> PurchaseRequestResponse:
    """Creates a new purchase request with the specified items.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role are authorized to create purchase requests.
    
    Args:
        request_data: Data for the new purchase request including items
        user: User payload from the decoded JWT token
    
    Returns:
        PurchaseRequestResponse: The created purchase request
    
    Raises:
        HTTPException(400): If the request data is invalid
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(500): If there's an error creating the request in the database
    """
    try:
        # Check if user has the appropriate role
        user_email = user.get("email")
        user_response = supabase_client.table("users").select("*").eq("email", user_email).execute()
        
        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")
            
        user_role = user_response.data[0].get("role")
        user_id = user_response.data[0].get("user_id")
        
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, 
                detail="Only logistics managers can create purchase requests"
            )
        
        # Create the purchase request
        purchase_request_data = {
            "user_id": user_id,
            "status": "pending",  # Initial status is always pending
            "justification": request_data.justification,
            "created_at": "now()"  # Using Supabase's now() function
        }
        
        # Insert the purchase request
        request_result = (
            supabase_client.table("purchaserequests")
            .insert(purchase_request_data)
            .execute()
        )
        
        if not request_result.data:
            raise HTTPException(status_code=500, detail="Failed to create purchase request")
            
        request_id = request_result.data[0]["request_id"]
        
        # Insert the request items
        for item in request_data.items:
            item_data = {
                "request_id": request_id,
                "material_id": item["material_id"],
                "quantity": item["quantity"],
                "estimated_cost": item["estimated_cost"]
            }
            
            item_result = (
                supabase_client.table("requestitems")
                .insert(item_data)
                .execute()
            )
            
            if not item_result.data:
                # If inserting any item fails, we should roll back
                # Since Supabase doesn't support transactions, we'll just delete the request
                supabase_client.table("purchaserequests").delete().eq("request_id", request_id).execute()
                raise HTTPException(status_code=500, detail="Failed to add item to purchase request")
                
        return request_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create purchase request: {str(e)}"
        )


@app.get("/api/v1/purchase-requests/{request_id}", response_model=Dict[str, Any], tags=["Purchase Requests"])
async def get_purchase_request(
    request_id: int,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Retrieves a purchase request by ID, including its items.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        request_id: ID of the purchase request to retrieve
        user: User payload from the decoded JWT token
    
    Returns:
        Dict[str, Any]: The purchase request data with its items
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If the purchase request is not found
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Get the purchase request
        request_response = (
            supabase_client.table("purchaserequests")
            .select("*")
            .eq("request_id", request_id)
            .execute()
        )
        
        if not request_response.data:
            raise HTTPException(status_code=404, detail=f"Purchase request with ID {request_id} not found")
            
        request_data = request_response.data[0]
        
        # Get the request items
        items_response = (
            supabase_client.table("requestitems")
            .select("*, materials(*)")
            .eq("request_id", request_id)
            .execute()
        )
        
        # Get approval if exists
        approval_response = (
            supabase_client.table("approvals")
            .select("*")
            .eq("request_id", request_id)
            .execute()
        )
        
        approval_data = approval_response.data[0] if approval_response.data else None
        
        # Get user details
        user_response = (
            supabase_client.table("users")
            .select("*")
            .eq("user_id", request_data["user_id"])
            .execute()
        )
        
        user_data = user_response.data[0] if user_response.data else None
        
        # Compile complete response
        complete_response = {
            **request_data,
            "items": items_response.data,
            "approval": approval_data,
            "user": user_data
        }
        
        return complete_response
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve purchase request: {str(e)}"
        )


@app.get("/api/v1/purchase-requests", response_model=List[Dict[str, Any]], tags=["Purchase Requests"])
async def list_purchase_requests(
    status: Optional[str] = None,
    user: Dict[str, Any] = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Lists purchase requests, optionally filtered by status.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        status: Optional filter by request status
        user: User payload from the decoded JWT token
    
    Returns:
        List[Dict[str, Any]]: List of purchase requests
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Get user role
        user_email = user.get("email")
        user_response = supabase_client.table("users").select("*").eq("email", user_email).execute()
        
        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")
            
        user_role = user_response.data[0].get("role")
        user_id = user_response.data[0].get("user_id")
        
        # Build query based on user role
        query = supabase_client.table("purchaserequests").select("*")
        
        # If user is logistique, they can only see their own requests
        if user_role == "logistique":
            query = query.eq("user_id", user_id)
        
        # Filter by status if provided
        if status:
            query = query.eq("status", status)
            
        # Order by created_at descending (newest first)
        query = query.order("created_at", desc=True)
            
        # Execute query
        response = query.execute()
        
        # Return the data
        return response.data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to list purchase requests: {str(e)}"
        )


@app.put("/api/v1/purchase-requests/{request_id}", response_model=PurchaseRequestResponse, tags=["Purchase Requests"])
async def update_purchase_request(
    request_id: int,
    request_data: PurchaseRequestUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> PurchaseRequestResponse:
    """Updates a purchase request with the specified ID.
    
    This endpoint requires authentication via JWT token in request body.
    Logistics users can only update their own requests and only if they are in 'pending' status.
    Finance users can update the status of any request.
    
    Args:
        request_id: ID of the purchase request to update
        request_data: New data for the purchase request
        user: User payload from the decoded JWT token
    
    Returns:
        PurchaseRequestResponse: The updated purchase request
    
    Raises:
        HTTPException(400): If the request data is invalid
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the purchase request is not found
        HTTPException(500): If there's an error updating the database
    """
    try:
        # Check if user exists and get role
        user_email = user.get("email")
        user_response = supabase_client.table("users").select("*").eq("email", user_email).execute()
        
        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")
            
        user_role = user_response.data[0].get("role")
        user_id = user_response.data[0].get("user_id")
        
        # Check if request exists
        request_response = (
            supabase_client.table("purchaserequests")
            .select("*")
            .eq("request_id", request_id)
            .execute()
        )
        
        if not request_response.data:
            raise HTTPException(status_code=404, detail=f"Purchase request with ID {request_id} not found")
            
        current_request = request_response.data[0]
        
        # Check permissions based on role
        if user_role == "logistique":
            # Logistics users can only update their own requests
            if current_request["user_id"] != user_id:
                raise HTTPException(
                    status_code=403, 
                    detail="You can only update your own purchase requests"
                )
                
            # Logistics users can only update requests in 'pending' status
            if current_request["status"] != "pending":
                raise HTTPException(
                    status_code=403, 
                    detail="You can only update purchase requests in 'pending' status"
                )
                
            # Logistics users can't change the status
            if request_data.status is not None:
                raise HTTPException(
                    status_code=403, 
                    detail="Logistics users can't change request status directly"
                )
        
        # Prepare update data (only include non-None fields)
        update_data = {k: v for k, v in request_data.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No update data provided")
            
        # Update the request
        updated_request = (
            supabase_client.table("purchaserequests")
            .update(update_data)
            .eq("request_id", request_id)
            .execute()
        )
        
        if not updated_request.data:
            raise HTTPException(status_code=500, detail="Failed to update purchase request")
            
        return updated_request.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update purchase request: {str(e)}"
        )


# Approvals Models and Routes
class ApprovalResponse(BaseModel):
    """Pydantic model for approval responses.
    
    Attributes:
        approval_id: Unique identifier for the approval
        request_id: ID of the purchase request being approved
        daf_user_id: ID of the finance director who made the decision
        decision: The approval decision
        comment: Optional comment explaining the decision
        approved_at: Timestamp of when the approval was made
    """
    approval_id: int
    request_id: int
    daf_user_id: int
    decision: str  # Using approval_decision enum values
    comment: Optional[str] = None
    approved_at: Optional[str] = None  # Using str to handle timestamp serialization


class ApprovalCreateRequest(BaseModel):
    """Pydantic model for creating a new approval.
    
    Attributes:
        request_id: ID of the purchase request to approve/reject
        decision: The approval decision
        comment: Optional comment explaining the decision
    """
    request_id: int
    decision: str  # Should be one of 'approved', 'rejected', or 'pending_info'
    comment: Optional[str] = None


@app.post("/api/v1/approvals", response_model=ApprovalResponse, tags=["Approvals"])
async def create_approval(
    approval_data: ApprovalCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> ApprovalResponse:
    """Creates a new approval decision for a purchase request.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'daf' role are authorized to create approval decisions.
    
    Args:
        approval_data: Data for the new approval
        user: User payload from the decoded JWT token
    
    Returns:
        ApprovalResponse: The created approval
    
    Raises:
        HTTPException(400): If the approval data is invalid
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the referenced purchase request is not found
        HTTPException(409): If the purchase request already has an approval
        HTTPException(500): If there's an error creating the approval in the database
    """
    try:
        # Check if user has the appropriate role
        user_email = user.get("email")
        user_response = supabase_client.table("users").select("*").eq("email", user_email).execute()
        
        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")
            
        user_role = user_response.data[0].get("role")
        daf_user_id = user_response.data[0].get("user_id")
        
        if user_role != "daf":
            raise HTTPException(
                status_code=403, 
                detail="Only finance directors can create approval decisions"
            )
            
        # Validate decision
        if approval_data.decision not in ["approved", "rejected", "pending_info"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid decision. Must be one of 'approved', 'rejected', or 'pending_info'"
            )
            
        # Check if purchase request exists
        request_response = (
            supabase_client.table("purchaserequests")
            .select("*")
            .eq("request_id", approval_data.request_id)
            .execute()
        )
        
        if not request_response.data:
            raise HTTPException(
                status_code=404, 
                detail=f"Purchase request with ID {approval_data.request_id} not found"
            )
            
        # Check if purchase request already has an approval
        existing_approval = (
            supabase_client.table("approvals")
            .select("approval_id")
            .eq("request_id", approval_data.request_id)
            .execute()
        )
        
        if existing_approval.data:
            raise HTTPException(
                status_code=409,
                detail=f"Purchase request with ID {approval_data.request_id} already has an approval decision"
            )
            
        # Create the approval
        approval_insert_data = {
            "request_id": approval_data.request_id,
            "daf_user_id": daf_user_id,
            "decision": approval_data.decision,
            "comment": approval_data.comment,
            "approved_at": "now()"  # Using Supabase's now() function
        }
        
        # Insert the approval
        approval_result = (
            supabase_client.table("approvals")
            .insert(approval_insert_data)
            .execute()
        )
        
        if not approval_result.data:
            raise HTTPException(status_code=500, detail="Failed to create approval")
            
        # Update the purchase request status based on the decision
        request_status = "approved" if approval_data.decision == "approved" else "rejected"
        
        updated_request = (
            supabase_client.table("purchaserequests")
            .update({"status": request_status})
            .eq("request_id", approval_data.request_id)
            .execute()
        )
            
        return approval_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create approval: {str(e)}"
        )


@app.get("/api/v1/approvals/{approval_id}", response_model=ApprovalResponse, tags=["Approvals"])
async def get_approval(
    approval_id: int,
    user: Dict[str, Any] = Depends(get_current_user)
) -> ApprovalResponse:
    """Retrieves an approval by ID.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        approval_id: ID of the approval to retrieve
        user: User payload from the decoded JWT token
    
    Returns:
        ApprovalResponse: The approval data
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If the approval is not found
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Get the approval
        approval_response = (
            supabase_client.table("approvals")
            .select("*")
            .eq("approval_id", approval_id)
            .execute()
        )
        
        if not approval_response.data:
            raise HTTPException(status_code=404, detail=f"Approval with ID {approval_id} not found")
            
        return approval_response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve approval: {str(e)}"
        )


@app.get("/api/v1/purchase-requests/{request_id}/approval", response_model=ApprovalResponse, tags=["Approvals"])
async def get_request_approval(
    request_id: int,
    user: Dict[str, Any] = Depends(get_current_user)
) -> ApprovalResponse:
    """Retrieves the approval for a specific purchase request.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        request_id: ID of the purchase request
        user: User payload from the decoded JWT token
    
    Returns:
        ApprovalResponse: The approval data
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If no approval is found for the request
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Get the approval for the request
        approval_response = (
            supabase_client.table("approvals")
            .select("*")
            .eq("request_id", request_id)
            .execute()
        )
        
        if not approval_response.data:
            raise HTTPException(
                status_code=404, 
                detail=f"No approval found for purchase request with ID {request_id}"
            )
            
        return approval_response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve approval: {str(e)}"
        )


# Orders Models and Routes
class OrderResponse(BaseModel):
    """Pydantic model for order responses.
    
    Attributes:
        order_id: Unique identifier for the order
        request_id: ID of the purchase request associated with this order
        supplier_id: ID of the supplier fulfilling the order
        order_number: External reference number for the order
        tracking_status: Current tracking status of the order
        ordered_at: Timestamp when the order was placed
        delivered_at: Optional timestamp when the order was delivered
    """
    order_id: int
    request_id: int
    supplier_id: int
    order_number: str
    tracking_status: str  # Using tracking_status enum values
    ordered_at: str  # Using str to handle timestamp serialization
    delivered_at: Optional[str] = None  # Using str to handle timestamp serialization


class OrderCreateRequest(BaseModel):
    """Pydantic model for creating a new order.
    
    Attributes:
        request_id: ID of the approved purchase request
        supplier_id: ID of the supplier fulfilling the order
        order_number: External reference number for the order
        items: List of items to be ordered with their actual costs
    """
    request_id: int
    supplier_id: int
    order_number: str
    items: List[Dict[str, Any]]  # Will contain material_id, quantity, actual_cost


class OrderUpdateRequest(BaseModel):
    """Pydantic model for updating an order.
    
    Attributes:
        tracking_status: New tracking status of the order
        delivered_at: Optional timestamp when the order was delivered
    """
    tracking_status: Optional[str] = None
    delivered_at: Optional[str] = None


@app.post("/api/v1/orders", response_model=OrderResponse, tags=["Orders"])
async def create_order(
    order_data: OrderCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> OrderResponse:
    """Creates a new order based on an approved purchase request.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role are authorized to create orders.
    The referenced purchase request must be in 'approved' status.
    
    Args:
        order_data: Data for the new order including items
        user: User payload from the decoded JWT token
    
    Returns:
        OrderResponse: The created order
    
    Raises:
        HTTPException(400): If the order data is invalid
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the referenced purchase request is not found
        HTTPException(409): If the purchase request is not approved or already has an order
        HTTPException(500): If there's an error creating the order in the database
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
                detail="Only logistics managers can create orders"
            )
            
        # Check if purchase request exists and is approved
        request_response = (
            supabase_client.table("purchaserequests")
            .select("*")
            .eq("request_id", order_data.request_id)
            .execute()
        )
        
        if not request_response.data:
            raise HTTPException(
                status_code=404, 
                detail=f"Purchase request with ID {order_data.request_id} not found"
            )
            
        request = request_response.data[0]
        if request["status"] != "approved":
            raise HTTPException(
                status_code=409,
                detail="Only approved purchase requests can be converted to orders"
            )
            
        # Check if request already has an order
        existing_order = (
            supabase_client.table("orders")
            .select("order_id")
            .eq("request_id", order_data.request_id)
            .execute()
        )
        
        if existing_order.data:
            raise HTTPException(
                status_code=409,
                detail=f"Purchase request with ID {order_data.request_id} already has an order"
            )
            
        # Check if supplier exists
        supplier_response = (
            supabase_client.table("suppliers")
            .select("supplier_id")
            .eq("supplier_id", order_data.supplier_id)
            .execute()
        )
        
        if not supplier_response.data:
            raise HTTPException(
                status_code=404, 
                detail=f"Supplier with ID {order_data.supplier_id} not found"
            )
            
        # Create the order
        order_insert_data = {
            "request_id": order_data.request_id,
            "supplier_id": order_data.supplier_id,
            "order_number": order_data.order_number,
            "tracking_status": "prepared",  # Initial status is always prepared
            "ordered_at": "now()"  # Using Supabase's now() function
        }
        
        # Insert the order
        order_result = (
            supabase_client.table("orders")
            .insert(order_insert_data)
            .execute()
        )
        
        if not order_result.data:
            raise HTTPException(status_code=500, detail="Failed to create order")
            
        order_id = order_result.data[0]["order_id"]
        
        # Insert the order items
        for item in order_data.items:
            item_data = {
                "order_id": order_id,
                "material_id": item["material_id"],
                "quantity": item["quantity"],
                "actual_cost": item["actual_cost"]
            }
            
            item_result = (
                supabase_client.table("orderitems")
                .insert(item_data)
                .execute()
            )
            
            if not item_result.data:
                # If inserting any item fails, roll back
                # Since Supabase doesn't support transactions, we'll just delete the order
                supabase_client.table("orders").delete().eq("order_id", order_id).execute()
                raise HTTPException(status_code=500, detail="Failed to add item to order")
                
        # Update the purchase request status to ordered
        updated_request = (
            supabase_client.table("purchaserequests")
            .update({"status": "ordered"})
            .eq("request_id", order_data.request_id)
            .execute()
        )
            
        return order_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create order: {str(e)}"
        )


@app.get("/api/v1/orders/{order_id}", response_model=Dict[str, Any], tags=["Orders"])
async def get_order(
    order_id: int,
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Retrieves an order by ID, including its items.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        order_id: ID of the order to retrieve
        user: User payload from the decoded JWT token
    
    Returns:
        Dict[str, Any]: The order data with its items
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If the order is not found
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Get the order
        order_response = (
            supabase_client.table("orders")
            .select("*")
            .eq("order_id", order_id)
            .execute()
        )
        
        if not order_response.data:
            raise HTTPException(status_code=404, detail=f"Order with ID {order_id} not found")
            
        order_data = order_response.data[0]
        
        # Get the order items
        items_response = (
            supabase_client.table("orderitems")
            .select("*, materials(*)")
            .eq("order_id", order_id)
            .execute()
        )
        
        # Get supplier details
        supplier_response = (
            supabase_client.table("suppliers")
            .select("*")
            .eq("supplier_id", order_data["supplier_id"])
            .execute()
        )
        
        supplier_data = supplier_response.data[0] if supplier_response.data else None
        
        # Get purchase request details
        request_response = (
            supabase_client.table("purchaserequests")
            .select("*")
            .eq("request_id", order_data["request_id"])
            .execute()
        )
        
        request_data = request_response.data[0] if request_response.data else None
        
        # Compile complete response
        complete_response = {
            **order_data,
            "items": items_response.data,
            "supplier": supplier_data,
            "purchase_request": request_data
        }
        
        return complete_response
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve order: {str(e)}"
        )


@app.get("/api/v1/orders", response_model=List[Dict[str, Any]], tags=["Orders"])
async def list_orders(
    tracking_status: Optional[str] = None,
    supplier_id: Optional[int] = None,
    # user: Dict[str, Any] = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Lists orders, optionally filtered by tracking status or supplier.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        tracking_status: Optional filter by tracking status
        supplier_id: Optional filter by supplier ID
        user: User payload from the decoded JWT token
    
    Returns:
        List[Dict[str, Any]]: List of orders with their items and supplier information
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Build query
        query = supabase_client.table("orders").select("*")
        
        # Apply filters if provided
        if tracking_status:
            query = query.eq("tracking_status", tracking_status)
            
        if supplier_id:
            query = query.eq("supplier_id", supplier_id)
            
        # Order by ordered_at descending (newest first)
        query = query.order("ordered_at", desc=True)
            
        # Execute query
        response = query.execute()
        
        orders = []
        
        # For each order, fetch supplier information and items
        for order in response.data:
            # Get supplier information
            supplier_response = (
                supabase_client.table("suppliers")
                .select("supplier_name, supplier_email")
                .eq("supplier_id", order["supplier_id"])
                .execute()
            )
            
            supplier_data = supplier_response.data[0] if supplier_response.data else {"supplier_name": "Unknown"}
            
            # Get order items with material details
            items_response = (
                supabase_client.table("orderitems")
                .select("*, materials(name, category, unit_price)")
                .eq("order_id", order["order_id"])
                .execute()
            )
            
            # Add supplier and items information to order data
            orders.append({
                **order,
                "supplier_name": supplier_data.get("supplier_name"),
                "supplier_email": supplier_data.get("supplier_email"),
                "items": items_response.data
            })
        
        # Return the data
        return orders
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to list orders: {str(e)}"
        )


@app.put("/api/v1/orders/{order_id}", response_model=OrderResponse, tags=["Orders"])
async def update_order(
    order_id: int,
    order_data: OrderUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> OrderResponse:
    """Updates an order with the specified ID.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role are authorized to update orders.
    
    Args:
        order_id: ID of the order to update
        order_data: New data for the order
        user: User payload from the decoded JWT token
    
    Returns:
        OrderResponse: The updated order
    
    Raises:
        HTTPException(400): If the request body is invalid
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the order is not found
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
                detail="Only logistics managers can update orders"
            )
            
        # Check if order exists
        order_response = (
            supabase_client.table("orders")
            .select("*")
            .eq("order_id", order_id)
            .execute()
        )
        
        if not order_response.data:
            raise HTTPException(status_code=404, detail=f"Order with ID {order_id} not found")
            
        # Validate tracking status if provided
        if order_data.tracking_status and order_data.tracking_status not in ["prepared", "shipped", "delivered"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid tracking status. Must be one of 'prepared', 'shipped', or 'delivered'"
            )
            
        # Prepare update data (only include non-None fields)
        update_data = {k: v for k, v in order_data.dict().items() if v is not None}
        
        # If status is changed to delivered and delivered_at is not provided, set it
        if order_data.tracking_status == "delivered" and not order_data.delivered_at:
            update_data["delivered_at"] = "now()"  # Using Supabase's now() function
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No update data provided")
            
        # Update the order
        updated_order = (
            supabase_client.table("orders")
            .update(update_data)
            .eq("order_id", order_id)
            .execute()
        )
        
        if not updated_order.data:
            raise HTTPException(status_code=500, detail="Failed to update order")
            
        # If order is marked as delivered, update purchase request status to delivered
        if order_data.tracking_status == "delivered":
            order = updated_order.data[0]
            
            updated_request = (
                supabase_client.table("purchaserequests")
                .update({"status": "delivered"})
                .eq("request_id", order["request_id"])
                .execute()
            )
            
        return updated_order.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update order: {str(e)}"
        )


@app.get("/api/v1/orders/by-request/{request_id}", response_model=OrderResponse, tags=["Orders"])
async def get_order_by_request(
    request_id: int,
    user: Dict[str, Any] = Depends(get_current_user)
) -> OrderResponse:
    """Retrieves the order associated with a specific purchase request.
    
    This endpoint requires authentication via JWT token in request body.
    
    Args:
        request_id: ID of the purchase request
        user: User payload from the decoded JWT token
    
    Returns:
        OrderResponse: The order data
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If no order is found for the request
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Get the order for the request
        order_response = (
            supabase_client.table("orders")
            .select("*")
            .eq("request_id", request_id)
            .execute()
        )
        
        if not order_response.data:
            raise HTTPException(
                status_code=404, 
                detail=f"No order found for purchase request with ID {request_id}"
            )
            
        return order_response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve order: {str(e)}"
        )


# Create supplier endpoint
class SupplierCreateRequest(BaseModel):
    """Pydantic model for creating a new supplier.
    
    Attributes:
        supplier_name: Name of the supplier company
        supplier_description: Optional description of the supplier
        supplier_email: Optional email contact for the supplier
    """
    supplier_name: str
    supplier_description: Optional[str] = None
    supplier_email: Optional[str] = None


@app.post("/api/v1/suppliers", response_model=SupplierResponse, tags=["Suppliers"])
async def create_supplier(
    supplier_data: SupplierCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user)
) -> SupplierResponse:
    """Creates a new supplier.
    
    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role are authorized to create suppliers.
    
    Args:
        supplier_data: Data for the new supplier
        user: User payload from the decoded JWT token
    
    Returns:
        SupplierResponse: The created supplier data
    
    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(500): If there's an error creating the supplier in the database
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
                detail="Only logistics managers can create suppliers"
            )
            
        # Insert the new supplier
        supplier_result = (
            supabase_client.table("suppliers")
            .insert(supplier_data.dict())
            .execute()
        )
        
        if not supplier_result.data:
            raise HTTPException(status_code=500, detail="Failed to create supplier")
            
        return supplier_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create supplier: {str(e)}"
        )
