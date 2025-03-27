from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime

# Custom exception for authentication errors
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

class UserResponse(BaseModel):
    """Pydantic model representing user data in response objects.

    Attributes:
        exists: Boolean indicating if the user exists in the database
        user_data: Optional user data if the user exists
    """
    exists: bool
    user_data: Optional[Dict[str, Any]] = None

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
    
class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ORDERED = "ordered"
    DELIVERED = "delivered"
    CLOSED = "closed"

class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    PENDING_INFO = "pending_info"

class TrackingStatus(str, Enum):
    PREPARED = "prepared"
    SHIPPED = "shipped"
    DELIVERED = "delivered"

# PurchaseRequest related models
class RequestItemCreate(BaseModel):
    """
    Represents data required to create a new request item.
    
    This model is used for adding new items to an existing purchase request.
    
    Attributes:
        material_id (int): ID of the material to be requested
        quantity (int): Quantity of the material being requested
        estimated_cost (float): Estimated cost for the requested quantity
    """
    material_id: int
    quantity: int
    estimated_cost: float

class PurchaseRequestCreateRequest(BaseModel):
    """Pydantic model for creating a new purchase request.
    
    Attributes:
        justification: Reason for the purchase request
        items: List of items to include in the request
    """
    justification: str
    items: List[Dict[str, Any]]  # Will contain material_id, quantity, estimated_cost

class PurchaseRequestUpdate(BaseModel):
    """Pydantic model for updating a purchase request.
    
    Attributes:
        justification: Updated justification for the request
    """
    justification: Optional[str] = None
    status: Optional[RequestStatus] = None

class PurchaseRequestUpdateRequest(BaseModel):
    """Pydantic model for updating a purchase request.
    
    Attributes:
        status: New status for the request
        justification: Updated justification for the request
    """
    status: Optional[str] = None
    justification: Optional[str] = None

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

class RequestItemBase(BaseModel):
    material_id: int
    quantity: int = Field(gt=0)
    estimated_cost: float = Field(gt=0)

class RequestItemResponse(RequestItemBase):
    request_item_id: int
    request_id: int
    created_at: datetime

# Approval related models
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

class ApprovalCreate(BaseModel):
    decision: ApprovalDecision
    comment: Optional[str] = None

# Order related models
class OrderItemCreate(BaseModel):
    material_id: int
    quantity: int = Field(gt=0)
    actual_cost: float = Field(gt=0)

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

class OrderCreate(BaseModel):
    request_id: int
    supplier_id: int
    order_number: str
    items: List[OrderItemCreate]

class OrderResponse(BaseModel):
    """Pydantic model for order responses.
    
    Attributes:
        order_id: Unique identifier for the order
        request_id: ID of the purchase request associated with this order
        supplier_id: ID of the supplier fulfilling the order
        order_number: External reference number for the order
        tracking_status: Current tracking status of the order
        ordered_at: str  # Using str to handle timestamp serialization
        delivered_at: Optional[str] = None  # Using str to handle timestamp serialization
        items: Optional[List[OrderItemCreate]] = None
    """
    order_id: int
    request_id: int
    supplier_id: int
    order_number: str
    tracking_status: str  # Using tracking_status enum values
    ordered_at: str  # Using str to handle timestamp serialization
    delivered_at: Optional[str] = None  # Using str to handle timestamp serialization
    items: Optional[List[OrderItemCreate]] = None