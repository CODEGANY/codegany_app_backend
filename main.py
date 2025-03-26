import json
from typing import Optional, List, Dict, Any
from services.connection_db import supabase_client

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import jwt

from models.models import *

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


class AuthError(Exception):
    """Custom exception class for authentication errors."""
    
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message





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








@app.get("/api/v1/materials", response_model=PaginatedMaterialsResponse, tags=["Materials"])
async def get_materials(
    page: int = 1, 
    page_size: int = 10,
    #user: Dict[str, Any] = Depends(get_current_user)
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



    
@app.post("/api/v1/purchase-requests", status_code=201, tags=["Purchase Requests"])
async def create_purchase_request(
    request: PurchaseRequestCreate,
    user = Depends(get_current_user)
) -> dict:
    """Create a new purchase request."""
    try:
        user_data = supabase_client.table("users").select("role").eq("email", user.get("email")).execute()
        if not user_data.data or user_data.data[0]["role"] != "logistique":
            raise HTTPException(status_code=403, detail="Unauthorized access")

        purchase_request = {
            "user_id": user_data.data[0]["user_id"],
            "created_at": datetime.now().isoformat(),
            "status": RequestStatus.PENDING,
            "justification": request.justification
        }
        
        result = supabase_client.table("purchase_requests").insert(purchase_request).execute()
        if not result.data:
            raise HTTPException(
                status_code=500, 
                detail="Error creating request."
            )
        request_id = result.data[0]["request_id"]

        # Add items
        items = [{
            "request_id": request_id,
            "material_id": item.material_id,
            "quantity": item.quantity,
            "estimated_cost": item.estimated_cost
        } for item in request.items]
        
        supabase_client.table("request_items").insert(items).execute()

        return {"request_id": request_id, "message": "Purchase request successfully created."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/purchase-requests", response_model=List[PurchaseRequestResponse], tags=["Purchase Requests"])
async def list_purchase_requests(
    status: Optional[RequestStatus] = None,
    user = Depends(get_current_user)
) -> List[PurchaseRequestResponse]:
    """List all purchase requests."""
    try:
        query = supabase_client.table("purchase_requests").select("*")
        if status:
            query = query.eq("status", status)
        
        # Filter by user except for the daf
        if user.get("role") != "daf":
            query = query.eq("user_id", user.get("user_id"))
            
        result = query.execute()
        return result.data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/purchase-requests/{request_id}", response_model=PurchaseRequestResponse, tags=["Purchase Requests"])
async def get_purchase_request(
    request_id: int,
    user = Depends(get_current_user)
) -> PurchaseRequestResponse:
    """Retrieve details of a purchase request."""
    try:
        result = supabase_client.table("purchase_requests")\
            .select("*, request_items(*)")\
            .eq("request_id", request_id)\
            .single()\
            .execute()
            
        if not result.data:
            raise HTTPException(status_code=404, detail="Request not found")
            
        # Check permissions
        if user.get("role") != "daf" and result.data["user_id"] != user.get("user_id"):
            raise HTTPException(status_code=403, detail="Unauthorized access")
            
        return result.data
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/purchase-requests/{request_id}", tags=["Purchase Requests"])
async def update_purchase_request(
    request_id: int,
    request: PurchaseRequestUpdate,
    user = Depends(get_current_user)
) -> dict:
    """Update a purchase request."""
    try:
        # Check existence
        current_request = supabase_client.table("purchase_requests")\
            .select("user_id, status")\
            .eq("request_id", request_id)\
            .single()\
            .execute()
            
        if not current_request.data:
            raise HTTPException(status_code=404, detail="Request not found")
            
        
        if user.get("role") != "daf" and current_request.data["user_id"] != user.get("user_id"):
            raise HTTPException(status_code=403, detail="Unauthorized access")
            
        
        if current_request.data["status"] not in [RequestStatus.PENDING, RequestStatus.REJECTED]:
            raise HTTPException(status_code=400, detail="Unable to edit an approved request")
            
        update_data = request.dict(exclude_unset=True)
        result = supabase_client.table("purchase_requests")\
            .update(update_data)\
            .eq("request_id", request_id)\
            .execute()
            
        return {"message": "Request updated successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/purchase-requests/{request_id}",tags=["Purchase Requests"])
async def delete_purchase_request(
    request_id: int,
    user = Depends(get_current_user)
) -> dict:
    """Delete a purchase request."""
    try:
        
        current_request = supabase_client.table("purchase_requests")\
            .select("user_id, status")\
            .eq("request_id", request_id)\
            .single()\
            .execute()
            
        if not current_request.data:
            raise HTTPException(status_code=404, detail="Request not found")
            
        
        if user.get("role") != "daf" and current_request.data["user_id"] != user.get("user_id"):
            raise HTTPException(status_code=403, detail="Unauthorized access")
            
        
        if current_request.data["status"] not in [RequestStatus.PENDING, RequestStatus.REJECTED]:
            raise HTTPException(status_code=400, detail="Unable to delete an approved request")
            
    
        supabase_client.table("request_items").delete().eq("request_id", request_id).execute()
        
        supabase_client.table("purchase_requests").delete().eq("request_id", request_id).execute()
            
        return {"message": "Request deleted successfully"}
            
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/v1/request-items", response_model=RequestItemResponse, tags=["Request Items"])
async def create_request_item(
    item: RequestItemCreate,
    user = Depends(get_current_user)
) -> RequestItemResponse:
    """Create a new request item."""
    try:
        
        user_data = supabase_client.table("users").select("role").eq("email", user.get("email")).execute()
        if not user_data.data or user_data.data[0]["role"] != "logistique":
            raise HTTPException(status_code=403, detail="Unauthorized access")

        
        material = supabase_client.table("materials").select("*").eq("material_id", item.material_id).execute()
        if not material.data:
            raise HTTPException(status_code=404, detail="Material not found")

        
        request = supabase_client.table("purchase_requests").select("status").eq("request_id", item.request_id).execute()
        if not request.data:
            raise HTTPException(status_code=404, detail="Request not found")
        if request.data[0]["status"] != RequestStatus.PENDING:
            raise HTTPException(status_code=400, detail="The request is no longer editable")

        result = supabase_client.table("request_items").insert(item.dict()).execute()
        return result.data[0]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/request-items/{request_id}", response_model=List[RequestItemResponse], tags=["Request Items"])
async def list_request_items(
    request_id: int,
    user = Depends(get_current_user)
) -> List[RequestItemResponse]:
    """List the items of a request."""
    try:
        result = supabase_client.table("request_items")\
            .select("*")\
            .eq("request_id", request_id)\
            .execute()
        return result.data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/request-items/{item_id}", response_model=RequestItemResponse,tags=["Request Items"])
async def update_request_item(
    item_id: int,
    item: RequestItemBase,
    user = Depends(get_current_user)
) -> RequestItemResponse:
    """Update item."""
    try:
        
        current_item = supabase_client.table("request_items").select("request_id").eq("request_item_id", item_id).execute()
        if not current_item.data:
            raise HTTPException(status_code=404, detail="Item not found")

        request = supabase_client.table("purchase_requests")\
            .select("status")\
            .eq("request_id", current_item.data[0]["request_id"])\
            .execute()
        
        if request.data[0]["status"] != RequestStatus.PENDING:
            raise HTTPException(status_code=400, detail="The request is no longer editable")

        result = supabase_client.table("request_items")\
            .update(item.dict())\
            .eq("request_item_id", item_id)\
            .execute()
        return result.data[0]
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/request-items/{item_id}",tags=["Request Items"])
async def delete_request_item(
    item_id: int,
    user = Depends(get_current_user)
) -> dict:
    """Delete item."""
    try:
        current_item = supabase_client.table("request_items").select("request_id").eq("request_item_id", item_id).execute()
        if not current_item.data:
            raise HTTPException(status_code=404, detail="Item not found")

        request = supabase_client.table("purchase_requests")\
            .select("status")\
            .eq("request_id", current_item.data[0]["request_id"])\
            .execute()
        
        if request.data[0]["status"] != RequestStatus.PENDING:
            raise HTTPException(status_code=400, detail="The request is no longer editabl")

        supabase_client.table("request_items").delete().eq("request_item_id", item_id).execute()
        return {"message": "Item deleted successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/v1/approvals/{request_id}", response_model=ApprovalResponse,tags=["Approvals"])
async def create_approval(
    request_id: int,
    approval: ApprovalCreate,
    user = Depends(get_current_user)
) -> ApprovalResponse:
    """Create an approval for a request."""
    try:
        
        user_data = supabase_client.table("users").select("*").eq("email", user.get("email")).execute()
        if not user_data.data or user_data.data[0]["role"] != "daf":
            raise HTTPException(status_code=403, detail="Only the DAF can approve requests")

        
        request = supabase_client.table("purchase_requests").select("status").eq("request_id", request_id).execute()
        if not request.data:
            raise HTTPException(status_code=404, detail="Request not found")
        if request.data[0]["status"] != RequestStatus.PENDING:
            raise HTTPException(status_code=400, detail="The request is not pending approval")

        approval_data = {
            "request_id": request_id,
            "daf_user_id": user_data.data[0]["user_id"],
            "decision": approval.decision,
            "comment": approval.comment,
            "approved_at": datetime.now().isoformat()
        }

        result = supabase_client.table("approvals").insert(approval_data).execute()
        
        
        new_status = RequestStatus.APPROVED if approval.decision == ApprovalDecision.APPROVED else RequestStatus.REJECTED
        supabase_client.table("purchase_requests")\
            .update({"status": new_status})\
            .eq("request_id", request_id)\
            .execute()

        return result.data[0]
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/approvals/{request_id}", response_model=ApprovalResponse,tags=["Approvals"])
async def get_approval(
    request_id: int,
    user = Depends(get_current_user)
) -> ApprovalResponse:
    """Getting an application approved."""
    try:
        result = supabase_client.table("approvals")\
            .select("*")\
            .eq("request_id", request_id)\
            .execute()
            
        if not result.data:
            raise HTTPException(status_code=404, detail="Approval not found")
            
        return result.data[0]
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/approvals", response_model=List[ApprovalResponse],tags=["Approvals"])
async def list_approvals(
    user = Depends(get_current_user)
) -> List[ApprovalResponse]:
    """List all approvals (accessible only to the daf)."""
    try:
        if user.get("role") != "daf":
            raise HTTPException(status_code=403, detail="Unauthorized access")
            
        result = supabase_client.table("approvals")\
            .select("*")\
            .execute()
            
        return result.data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/api/v1/orders", response_model=OrderResponse,tags=["Orders"])
async def create_order(
    order: OrderCreate,
    user = Depends(get_current_user)
) -> OrderResponse:
    """Create a new order."""
    try:
        
        if user.get("role") != "logistique":
            raise HTTPException(status_code=403, detail="Unauthorized access")

        # Check application approved
        request = supabase_client.table("purchase_requests")\
            .select("status")\
            .eq("request_id", order.request_id)\
            .single()\
            .execute()
            
        if not request.data or request.data["status"] != RequestStatus.APPROVED:
            raise HTTPException(status_code=400, detail="The request must be approved")

        # Add order
        order_data = {
            "request_id": order.request_id,
            "supplier_id": order.supplier_id,
            "order_number": order.order_number,
            "tracking_status": TrackingStatus.PREPARED,
            "ordered_at": datetime.now().isoformat()
        }

        result = supabase_client.table("orders").insert(order_data).execute()
        order_id = result.data[0]["order_id"]

        # Add items
        for item in order.items:
            item_data = {
                "order_id": order_id,
                "material_id": item.material_id,
                "quantity": item.quantity,
                "actual_cost": item.actual_cost
            }
            supabase_client.table("order_items").insert(item_data).execute()

        
        supabase_client.table("purchase_requests")\
            .update({"status": RequestStatus.ORDERED})\
            .eq("request_id", order.request_id)\
            .execute()

        return {**result.data[0], "items": order.items}
    
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/orders/{order_id}/tracking",tags=["Orders"])
async def update_tracking(
    order_id: int,
    tracking_status: TrackingStatus,
    user = Depends(get_current_user)
) -> dict:
    """Update delivery status."""
    try:
        if user.get("role") != "logistique":
            raise HTTPException(status_code=403, detail="Unauthorized access")

        update_data = {"tracking_status": tracking_status}
        if tracking_status == TrackingStatus.DELIVERED:
            update_data["delivered_at"] = datetime.now().isoformat()

        result = supabase_client.table("orders")\
            .update(update_data)\
            .eq("order_id", order_id)\
            .execute()

        if tracking_status == TrackingStatus.DELIVERED:
            
            order = result.data[0]
            supabase_client.table("purchase_requests")\
                .update({"status": RequestStatus.DELIVERED})\
                .eq("request_id", order["request_id"])\
                .execute()

        return {"message": "Status updated successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/orders", response_model=List[OrderResponse],tags=["Orders"])
async def list_orders(user = Depends(get_current_user)) -> List[OrderResponse]:
    """List all commands."""
    try:
        if user.get("role") not in ["logistique", "daf"]:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        
        result = supabase_client.table("orders")\
            .select("*, order_items(*)")\
            .execute()
        return result.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/orders/{order_id}", response_model=OrderResponse,tags=["Orders"])
async def get_order(
    order_id: int,
    user = Depends(get_current_user)
) -> OrderResponse:
    """Get order details."""
    try:
        if user.get("role") not in ["logistique", "daf"]:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        
        result = supabase_client.table("orders")\
            .select("*, order_items(*)")\
            .eq("order_id", order_id)\
            .single()\
            .execute()
            
        if not result.data:
            raise HTTPException(status_code=404, detail="Order not found")
            
        return result.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/orders", response_model=OrderResponse,tags=["Orders"])
async def create_order(
    order: OrderCreate,
    user = Depends(get_current_user)
) -> OrderResponse:
    """Create a new order."""
    try:
        if user.get("role") != "logistique":
            raise HTTPException(status_code=403, detail="Unauthorized access")

    
        request = supabase_client.table("purchase_requests")\
            .select("status")\
            .eq("request_id", order.request_id)\
            .single()\
            .execute()
            
        if not request.data or request.data["status"] != "approved":
            raise HTTPException(status_code=400, detail="The request must be approved")

        
        order_data = {
            "request_id": order.request_id,
            "supplier_id": order.supplier_id,
            "order_number": order.order_number,
            "tracking_status": TrackingStatus.PREPARED,
            "ordered_at": datetime.now().isoformat()
        }

        order_result = supabase_client.table("orders").insert(order_data).execute()
        order_id = order_result.data[0]["order_id"]

        
        for item in order.items:
            order_item = {
                "order_id": order_id,
                "material_id": item.material_id,
                "quantity": item.quantity,
                "actual_cost": item.actual_cost
            }
            supabase_client.table("order_items").insert(order_item).execute()

        
        supabase_client.table("purchase_requests")\
            .update({"status": RequestStatus.ORDERED})\
            .eq("request_id", order.request_id)\
            .execute()

        return await get_order(order_id, user)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/orders/{order_id}/tracking",tags=["Orders"])
async def update_order_tracking(
    order_id: int,
    tracking_status: TrackingStatus,
    user = Depends(get_current_user)
) -> dict:
    """Update the delivery status of an order."""
    try:
        if user.get("role") != "logistique":
            raise HTTPException(status_code=403, detail="Unauthorized access")

        update_data = {"tracking_status": tracking_status}
        if tracking_status == TrackingStatus.DELIVERED:
            update_data["delivered_at"] = datetime.now().isoformat()

        order = supabase_client.table("orders")\
            .update(update_data)\
            .eq("order_id", order_id)\
            .execute()

        if tracking_status == TrackingStatus.DELIVERED:
            supabase_client.table("purchase_requests")\
                .update({"status": RequestStatus.DELIVERED})\
                .eq("request_id", order.data[0]["request_id"])\
                .execute()

        return {"message": "Order status updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))