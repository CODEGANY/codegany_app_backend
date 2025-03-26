import os
import json
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import jwt

# Import models from models.py
from models.models import (
    TokenRequest,
    AuthError,
    UserResponse,
    SupplierResponse,
    MaterialResponse,
    PaginatedMaterialsResponse,
    MaterialUpdateRequest,
    UserRegistrationRequest,
    MaterialCreateRequest,
    PurchaseRequestResponse,
    PurchaseRequestCreateRequest,
    PurchaseRequestUpdateRequest,
    ApprovalResponse,
    ApprovalCreateRequest,
    OrderResponse,
    OrderCreateRequest,
    OrderUpdateRequest,
    SupplierCreateRequest,
    RequestItemCreate,
)

# Import Supabase client from connection_db.py
from services.connection_db import supabase_client

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


@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint that returns a simple greeting.

    Returns:
        Dict[str, str]: A greeting message
    """
    return {"Hello": "World"}


async def extract_token(request: Request) -> str:
    """Extract the JWT token from either the Authorization header or request body.

    For GET requests, extracts token from the Authorization header.
    For other requests that submit data, extracts from the request body.

    Args:
        request: The FastAPI request object

    Returns:
        str: The extracted JWT token

    Raises:
        HTTPException: If the token is missing or invalid
    """
    try:
        if request.method == "GET":
            # For GET requests, get token from Authorization header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=401,
                    detail="Bearer token missing in Authorization header",
                )

            # Extract token part after "Bearer "
            return auth_header.split(" ")[1]
        else:
            # For other requests, get from request body
            body = await request.json()

            # Check if token exists in the request body
            if not body or "token" not in body:
                raise HTTPException(
                    status_code=401, detail="Token missing in request body"
                )

            return body["token"]
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in request body")
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Failed to extract token: {str(e)}"
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


@app.get("/api/v1/suppliers", response_model=List[SupplierResponse], tags=["Suppliers"])
async def get_suppliers(
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[SupplierResponse]:
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


@app.get(
    "/api/v1/materials", response_model=PaginatedMaterialsResponse, tags=["Materials"]
)
async def get_materials(
    page: int = 1, page_size: int = 10, user: Dict[str, Any] = Depends(get_current_user)
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
        count_response = (
            supabase_client.table("materials").select("*", count="exact").execute()
        )
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
            total_pages=total_pages,
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve materials: {str(e)}"
        )


@app.put(
    "/api/v1/materials/{material_id}",
    response_model=MaterialResponse,
    tags=["Materials"],
)
async def update_material(
    material_id: int,
    material_data: MaterialUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
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
        user_response = (
            supabase_client.table("users")
            .select("role")
            .eq("email", user_email)
            .execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, detail="Only logistics managers can update materials"
            )

        # Check if material exists
        material_check = (
            supabase_client.table("materials")
            .select("material_id")
            .eq("material_id", material_id)
            .execute()
        )

        if not material_check.data:
            raise HTTPException(
                status_code=404, detail=f"Material with ID {material_id} not found"
            )

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
    material_id: int, user: Dict[str, Any] = Depends(get_current_user)
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
        user_response = (
            supabase_client.table("users")
            .select("role")
            .eq("email", user_email)
            .execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, detail="Only logistics managers can delete materials"
            )

        # Check if material exists
        material_check = (
            supabase_client.table("materials")
            .select("material_id")
            .eq("material_id", material_id)
            .execute()
        )

        if not material_check.data:
            raise HTTPException(
                status_code=404, detail=f"Material with ID {material_id} not found"
            )

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
                detail="Cannot delete material that is referenced in purchase requests",
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
                detail="Cannot delete material that is referenced in orders",
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
                detail="Invalid role. Must be either 'logistique' or 'daf'",
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
                status_code=409, detail="A user with this email already exists"
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
                status_code=409, detail="A user with this username already exists"
            )

        # Create the user in the database
        user_result = supabase_client.table("users").insert(user_data.dict()).execute()

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


@app.post("/api/v1/materials", response_model=MaterialResponse, tags=["Materials"])
async def create_material(
    material_data: MaterialCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
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
        user_response = (
            supabase_client.table("users")
            .select("role")
            .eq("email", user_email)
            .execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, detail="Only logistics managers can create materials"
            )

        # Insert the new material
        material_result = (
            supabase_client.table("materials").insert(material_data.dict()).execute()
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
@app.post(
    "/api/v1/purchase-requests",
    response_model=PurchaseRequestResponse,
    tags=["Purchase Requests"],
)
async def create_purchase_request(
    request_data: PurchaseRequestCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
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
        user_response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        user_id = user_response.data[0].get("user_id")

        if user_role != "logistique":
            raise HTTPException(
                status_code=403,
                detail="Only logistics managers can create purchase requests",
            )

        # Create the purchase request
        purchase_request_data = {
            "user_id": user_id,
            "status": "pending",  # Initial status is always pending
            "justification": request_data.justification,
            "created_at": "now()",  # Using Supabase's now() function
        }

        # Insert the purchase request
        request_result = (
            supabase_client.table("purchaserequests")
            .insert(purchase_request_data)
            .execute()
        )

        if not request_result.data:
            raise HTTPException(
                status_code=500, detail="Failed to create purchase request"
            )

        request_id = request_result.data[0]["request_id"]

        # Insert the request items
        for item in request_data.items:
            item_data = {
                "request_id": request_id,
                "material_id": item["material_id"],
                "quantity": item["quantity"],
                "estimated_cost": item["estimated_cost"],
            }

            item_result = (
                supabase_client.table("requestitems").insert(item_data).execute()
            )

            if not item_result.data:
                # If inserting any item fails, we should roll back
                # Since Supabase doesn't support transactions, we'll just delete the request
                supabase_client.table("purchaserequests").delete().eq(
                    "request_id", request_id
                ).execute()
                raise HTTPException(
                    status_code=500, detail="Failed to add item to purchase request"
                )

        return request_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create purchase request: {str(e)}"
        )


@app.get(
    "/api/v1/purchase-requests/{request_id}",
    response_model=Dict[str, Any],
    tags=["Purchase Requests"],
)
async def get_purchase_request(
    request_id: int, user: Dict[str, Any] = Depends(get_current_user)
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
            raise HTTPException(
                status_code=404,
                detail=f"Purchase request with ID {request_id} not found",
            )

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
            "user": user_data,
        }

        return complete_response
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve purchase request: {str(e)}"
        )


@app.get(
    "/api/v1/purchase-requests",
    response_model=List[Dict[str, Any]],
    tags=["Purchase Requests"],
)
async def list_purchase_requests(
    status: Optional[str] = None, user: Dict[str, Any] = Depends(get_current_user)
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
        user_response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )

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


@app.put(
    "/api/v1/purchase-requests/{request_id}",
    response_model=PurchaseRequestResponse,
    tags=["Purchase Requests"],
)
async def update_purchase_request(
    request_id: int,
    request_data: PurchaseRequestUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
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
        user_response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )

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
            raise HTTPException(
                status_code=404,
                detail=f"Purchase request with ID {request_id} not found",
            )

        current_request = request_response.data[0]

        # Check permissions based on role
        if user_role == "logistique":
            # Logistics users can only update their own requests
            if current_request["user_id"] != user_id:
                raise HTTPException(
                    status_code=403,
                    detail="You can only update your own purchase requests",
                )

            # Logistics users can only update requests in 'pending' status
            if current_request["status"] != "pending":
                raise HTTPException(
                    status_code=403,
                    detail="You can only update purchase requests in 'pending' status",
                )

            # Logistics users can't change the status
            if request_data.status is not None:
                raise HTTPException(
                    status_code=403,
                    detail="Logistics users can't change request status directly",
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
            raise HTTPException(
                status_code=500, detail="Failed to update purchase request"
            )

        return updated_request.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update purchase request: {str(e)}"
        )


# Approvals Models and Routes
@app.post("/api/v1/approvals", response_model=ApprovalResponse, tags=["Approvals"])
async def create_approval(
    approval_data: ApprovalCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
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
        user_response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        daf_user_id = user_response.data[0].get("user_id")

        if user_role != "daf":
            raise HTTPException(
                status_code=403,
                detail="Only finance directors can create approval decisions",
            )

        # Validate decision
        if approval_data.decision not in ["approved", "rejected", "pending_info"]:
            raise HTTPException(
                status_code=400,
                detail="Invalid decision. Must be one of 'approved', 'rejected', or 'pending_info'",
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
                detail=f"Purchase request with ID {approval_data.request_id} not found",
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
                detail=f"Purchase request with ID {approval_data.request_id} already has an approval decision",
            )

        # Create the approval
        approval_insert_data = {
            "request_id": approval_data.request_id,
            "daf_user_id": daf_user_id,
            "decision": approval_data.decision,
            "comment": approval_data.comment,
            "approved_at": "now()",  # Using Supabase's now() function
        }

        # Insert the approval
        approval_result = (
            supabase_client.table("approvals").insert(approval_insert_data).execute()
        )

        if not approval_result.data:
            raise HTTPException(status_code=500, detail="Failed to create approval")

        # Update the purchase request status based on the decision
        request_status = (
            "approved" if approval_data.decision == "approved" else "rejected"
        )

        updated_request = (
            supabase_client.table("purchase_requests")
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


@app.get(
    "/api/v1/approvals/{approval_id}",
    response_model=ApprovalResponse,
    tags=["Approvals"],
)
async def get_approval(
    approval_id: int, user: Dict[str, Any] = Depends(get_current_user)
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
            raise HTTPException(
                status_code=404, detail=f"Approval with ID {approval_id} not found"
            )

        return approval_response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve approval: {str(e)}"
        )


@app.get(
    "/api/v1/purchase-requests/{request_id}/approval",
    response_model=ApprovalResponse,
    tags=["Approvals"],
)
async def get_request_approval(
    request_id: int, user: Dict[str, Any] = Depends(get_current_user)
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
                detail=f"No approval found for purchase request with ID {request_id}",
            )

        return approval_response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve approval: {str(e)}"
        )


# Orders Models and Routes
@app.post("/api/v1/orders", response_model=OrderResponse, tags=["Orders"])
async def create_order(
    order_data: OrderCreateRequest, user: Dict[str, Any] = Depends(get_current_user)
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
        user_response = (
            supabase_client.table("users")
            .select("role")
            .eq("email", user_email)
            .execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, detail="Only logistics managers can create orders"
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
                detail=f"Purchase request with ID {order_data.request_id} not found",
            )

        request = request_response.data[0]
        if request["status"] != "approved":
            raise HTTPException(
                status_code=409,
                detail="Only approved purchase requests can be converted to orders",
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
                detail=f"Purchase request with ID {order_data.request_id} already has an order",
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
                detail=f"Supplier with ID {order_data.supplier_id} not found",
            )

        # Create the order
        order_insert_data = {
            "request_id": order_data.request_id,
            "supplier_id": order_data.supplier_id,
            "order_number": order_data.order_number,
            "tracking_status": "prepared",  # Initial status is always prepared
            "ordered_at": "now()",  # Using Supabase's now() function
        }

        # Insert the order
        order_result = (
            supabase_client.table("orders").insert(order_insert_data).execute()
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
                "actual_cost": item["actual_cost"],
            }

            item_result = (
                supabase_client.table("orderitems").insert(item_data).execute()
            )

            if not item_result.data:
                # If inserting any item fails, roll back
                # Since Supabase doesn't support transactions, we'll just delete the order
                supabase_client.table("orders").delete().eq(
                    "order_id", order_id
                ).execute()
                raise HTTPException(
                    status_code=500, detail="Failed to add item to order"
                )

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
        raise HTTPException(status_code=500, detail=f"Failed to create order: {str(e)}")


@app.get("/api/v1/orders/{order_id}", response_model=Dict[str, Any], tags=["Orders"])
async def get_order(
    order_id: int, user: Dict[str, Any] = Depends(get_current_user)
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
            raise HTTPException(
                status_code=404, detail=f"Order with ID {order_id} not found"
            )

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
            "purchase_request": request_data,
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
    user: Dict[str, Any] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Lists orders, optionally filtered by tracking status or supplier.

    This endpoint requires authentication via JWT token in request body.

    Args:
        tracking_status: Optional filter by tracking status
        supplier_id: Optional filter by supplier ID
        user: User payload from the decoded JWT token

    Returns:
        List[Dict[str, Any]]: List of orders

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

        # For each order, fetch supplier information
        for order in response.data:
            supplier_response = (
                supabase_client.table("suppliers")
                .select("supplier_name")
                .eq("supplier_id", order["supplier_id"])
                .execute()
            )

            supplier_name = (
                supplier_response.data[0]["supplier_name"]
                if supplier_response.data
                else "Unknown"
            )

            # Add supplier name to order data
            orders.append({**order, "supplier_name": supplier_name})

        # Return the data
        return orders
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list orders: {str(e)}")


@app.put("/api/v1/orders/{order_id}", response_model=OrderResponse, tags=["Orders"])
async def update_order(
    order_id: int,
    order_data: OrderUpdateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
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
        user_response = (
            supabase_client.table("users")
            .select("role")
            .eq("email", user_email)
            .execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, detail="Only logistics managers can update orders"
            )

        # Check if order exists
        order_response = (
            supabase_client.table("orders")
            .select("*")
            .eq("order_id", order_id)
            .execute()
        )

        if not order_response.data:
            raise HTTPException(
                status_code=404, detail=f"Order with ID {order_id} not found"
            )

        # Validate tracking status if provided
        if order_data.tracking_status and order_data.tracking_status not in [
            "prepared",
            "shipped",
            "delivered",
        ]:
            raise HTTPException(
                status_code=400,
                detail="Invalid tracking status. Must be one of 'prepared', 'shipped', or 'delivered'",
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
        raise HTTPException(status_code=500, detail=f"Failed to update order: {str(e)}")


@app.get(
    "/api/v1/orders/by-request/{request_id}",
    response_model=OrderResponse,
    tags=["Orders"],
)
async def get_order_by_request(
    request_id: int, user: Dict[str, Any] = Depends(get_current_user)
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
                detail=f"No order found for purchase request with ID {request_id}",
            )

        return order_response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve order: {str(e)}"
        )


# Create supplier endpoint
@app.post("/api/v1/suppliers", response_model=SupplierResponse, tags=["Suppliers"])
async def create_supplier(
    supplier_data: SupplierCreateRequest,
    user: Dict[str, Any] = Depends(get_current_user),
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
        user_response = (
            supabase_client.table("users")
            .select("role")
            .eq("email", user_email)
            .execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        if user_role != "logistique":
            raise HTTPException(
                status_code=403, detail="Only logistics managers can create suppliers"
            )

        # Insert the new supplier
        supplier_result = (
            supabase_client.table("suppliers").insert(supplier_data.dict()).execute()
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


@app.get(
    "/api/v1/request-items/{request_id}",
    response_model=List[Dict[str, Any]],
    tags=["Request Items"],
)
async def get_request_items(
    request_id: int, user: Dict[str, Any] = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Retrieves all items for a specific purchase request.

    This endpoint requires authentication via JWT token in request body.

    Args:
        request_id: ID of the purchase request
        user: User payload from the decoded JWT token

    Returns:
        List[Dict[str, Any]]: List of request items with material details

    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If the purchase request is not found
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Check if purchase request exists
        request_check = (
            supabase_client.table("purchaserequests")
            .select("request_id")
            .eq("request_id", request_id)
            .execute()
        )

        if not request_check.data:
            raise HTTPException(
                status_code=404,
                detail=f"Purchase request with ID {request_id} not found",
            )

        # Get request items with material details
        items_response = (
            supabase_client.table("requestitems")
            .select("*, materials(*)")
            .eq("request_id", request_id)
            .execute()
        )

        return items_response.data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve request items: {str(e)}"
        )


@app.post("/api/v1/request-items/{request_id}", tags=["Request Items"])
async def add_request_item(
    request_id: int,
    item_data: RequestItemCreate,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Adds a new item to an existing purchase request.

    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role can add items to their own pending requests.

    Args:
        request_id: ID of the purchase request
        item_data: Data for the new request item
        user: User payload from the decoded JWT token

    Returns:
        Dict[str, Any]: The created request item

    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the purchase request or material is not found
        HTTPException(409): If the request is not in pending status
        HTTPException(500): If there's an error creating the item in the database
    """
    try:
        # Check user role and get user ID
        user_email = user.get("email")
        user_response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        user_id = user_response.data[0].get("user_id")

        if user_role != "logistique":
            raise HTTPException(
                status_code=403,
                detail="Only logistics managers can add items to purchase requests",
            )

        # Check if purchase request exists and belongs to user
        request_check = (
            supabase_client.table("purchaserequests")
            .select("*")
            .eq("request_id", request_id)
            .execute()
        )

        if not request_check.data:
            raise HTTPException(
                status_code=404,
                detail=f"Purchase request with ID {request_id} not found",
            )

        request = request_check.data[0]

        # Check if request belongs to user
        if request["user_id"] != user_id:
            raise HTTPException(
                status_code=403,
                detail="You can only add items to your own purchase requests",
            )

        # Check if request is in pending status
        if request["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail="Can only add items to purchase requests in pending status",
            )

        # Check if material exists
        material_check = (
            supabase_client.table("materials")
            .select("material_id")
            .eq("material_id", item_data.material_id)
            .execute()
        )

        if not material_check.data:
            raise HTTPException(
                status_code=404,
                detail=f"Material with ID {item_data.material_id} not found",
            )

        # Create request item
        item_insert_data = {
            "request_id": request_id,
            "material_id": item_data.material_id,
            "quantity": item_data.quantity,
            "estimated_cost": item_data.estimated_cost,
        }

        item_result = (
            supabase_client.table("requestitems").insert(item_insert_data).execute()
        )

        if not item_result.data:
            raise HTTPException(
                status_code=500, detail="Failed to add item to purchase request"
            )

        return item_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to add request item: {str(e)}"
        )


@app.delete("/api/v1/request-items/{request_item_id}", tags=["Request Items"])
async def delete_request_item(
    request_item_id: int, user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, str]:
    """Deletes a specific item from a purchase request.

    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role can delete items from their own pending requests.

    Args:
        request_item_id: ID of the request item to delete
        user: User payload from the decoded JWT token

    Returns:
        Dict[str, str]: Success message

    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the request item is not found
        HTTPException(409): If the associated request is not in pending status
        HTTPException(500): If there's an error deleting the item from the database
    """
    try:
        # Get user role and ID
        user_email = user.get("email")
        user_response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        user_id = user_response.data[0].get("user_id")

        if user_role != "logistique":
            raise HTTPException(
                status_code=403,
                detail="Only logistics managers can delete request items",
            )

        # Get request item and associated request details
        item_response = (
            supabase_client.table("requestitems")
            .select("*, purchaserequests!inner(*)")
            .eq("request_item_id", request_item_id)
            .execute()
        )

        if not item_response.data:
            raise HTTPException(
                status_code=404,
                detail=f"Request item with ID {request_item_id} not found",
            )

        request_data = item_response.data[0]["purchaserequests"]

        # Check if request belongs to user
        if request_data["user_id"] != user_id:
            raise HTTPException(
                status_code=403,
                detail="You can only delete items from your own purchase requests",
            )

        # Check if request is in pending status
        if request_data["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail="Can only delete items from purchase requests in pending status",
            )

        # Delete the item
        delete_result = (
            supabase_client.table("requestitems")
            .delete()
            .eq("request_item_id", request_item_id)
            .execute()
        )

        if not delete_result.data:
            raise HTTPException(status_code=500, detail="Failed to delete request item")

        return {
            "message": f"Request item with ID {request_item_id} successfully deleted"
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to delete request item: {str(e)}"
        )


@app.put("/api/v1/request-items/{request_item_id}", tags=["Request Items"])
async def update_request_item(
    request_item_id: int,
    item_data: RequestItemCreate,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Updates a specific item in a purchase request.

    This endpoint requires authentication via JWT token in request body.
    Only users with 'logistique' role can update items in their own pending requests.

    Args:
        request_item_id: ID of the request item to update
        item_data: Updated data for the request item
        user: User payload from the decoded JWT token

    Returns:
        Dict[str, Any]: The updated request item

    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(403): If the user doesn't have appropriate permissions
        HTTPException(404): If the request item or material is not found
        HTTPException(409): If the associated request is not in pending status
        HTTPException(500): If there's an error updating the item in the database
    """
    try:
        # Get user role and ID
        user_email = user.get("email")
        user_response = (
            supabase_client.table("users").select("*").eq("email", user_email).execute()
        )

        if not user_response.data:
            raise HTTPException(status_code=403, detail="User not found in the system")

        user_role = user_response.data[0].get("role")
        user_id = user_response.data[0].get("user_id")

        if user_role != "logistique":
            raise HTTPException(
                status_code=403,
                detail="Only logistics managers can update request items",
            )

        # Get request item and associated request details
        item_response = (
            supabase_client.table("requestitems")
            .select("*, purchaserequests!inner(*)")
            .eq("request_item_id", request_item_id)
            .execute()
        )

        if not item_response.data:
            raise HTTPException(
                status_code=404,
                detail=f"Request item with ID {request_item_id} not found",
            )

        request_data = item_response.data[0]["purchaserequests"]

        # Check if request belongs to user
        if request_data["user_id"] != user_id:
            raise HTTPException(
                status_code=403,
                detail="You can only update items in your own purchase requests",
            )

        # Check if request is in pending status
        if request_data["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail="Can only update items in purchase requests with pending status",
            )

        # Check if material exists
        material_check = (
            supabase_client.table("materials")
            .select("material_id")
            .eq("material_id", item_data.material_id)
            .execute()
        )

        if not material_check.data:
            raise HTTPException(
                status_code=404,
                detail=f"Material with ID {item_data.material_id} not found",
            )

        # Update the item
        update_result = (
            supabase_client.table("requestitems")
            .update(item_data.dict())
            .eq("request_item_id", request_item_id)
            .execute()
        )

        if not update_result.data:
            raise HTTPException(status_code=500, detail="Failed to update request item")

        return update_result.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to update request item: {str(e)}"
        )


@app.get("/api/v1/suppliers/{supplier_id}", response_model=SupplierResponse, tags=["Suppliers"])
async def get_supplier(
    supplier_id: int,
    user: Dict[str, Any] = Depends(get_current_user),
) -> SupplierResponse:
    """Retrieves a specific supplier by ID.

    This endpoint requires authentication via JWT token in request body.

    Args:
        supplier_id: ID of the supplier to retrieve
        user: User payload from the decoded JWT token

    Returns:
        SupplierResponse: The supplier data

    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If the supplier is not found
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        response = (
            supabase_client.table("suppliers")
            .select("*")
            .eq("supplier_id", supplier_id)
            .execute()
        )

        if not response.data:
            raise HTTPException(
                status_code=404,
                detail=f"Supplier with ID {supplier_id} not found"
            )

        return response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve supplier: {str(e)}"
        )


@app.get(
    "/api/v1/order-items/{order_id}",
    response_model=List[Dict[str, Any]],
    tags=["Orders"]
)
async def get_order_items(
    order_id: int, 
    user: Dict[str, Any] = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Retrieves all items for a specific order.

    This endpoint requires authentication via JWT token in request body.

    Args:
        order_id: ID of the order
        user: User payload from the decoded JWT token

    Returns:
        List[Dict[str, Any]]: List of order items with material details

    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If the order is not found
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        # Check if order exists
        order_check = (
            supabase_client.table("orders")
            .select("order_id")
            .eq("order_id", order_id)
            .execute()
        )

        if not order_check.data:
            raise HTTPException(
                status_code=404,
                detail=f"Order with ID {order_id} not found"
            )

        # Get order items with material details
        items_response = (
            supabase_client.table("orderitems")
            .select("*, materials(*)")
            .eq("order_id", order_id)
            .execute()
        )

        return items_response.data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve order items: {str(e)}"
        )


@app.get(
    "/api/v1/materials/{material_id}",
    response_model=MaterialResponse,
    tags=["Materials"],
)
async def get_material(
    material_id: int, 
    user: Dict[str, Any] = Depends(get_current_user)
) -> MaterialResponse:
    """Retrieves a specific material by ID.

    This endpoint requires authentication via JWT token in request body.

    Args:
        material_id: ID of the material to retrieve
        user: User payload from the decoded JWT token

    Returns:
        MaterialResponse: The material data

    Raises:
        HTTPException(401): If authentication fails or token is invalid
        HTTPException(404): If the material is not found
        HTTPException(500): If there's an error retrieving data from the database
    """
    try:
        material_response = (
            supabase_client.table("materials")
            .select("*")
            .eq("material_id", material_id)
            .execute()
        )

        if not material_response.data:
            raise HTTPException(
                status_code=404,
                detail=f"Material with ID {material_id} not found"
            )

        return material_response.data[0]
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve material: {str(e)}"
        )
