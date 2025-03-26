from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime

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

# Modèles pour PurchaseRequest
class RequestItemCreate(BaseModel):
    material_id: int
    quantity: int = Field(gt=0)
    estimated_cost: float = Field(gt=0)

class PurchaseRequestCreate(BaseModel):
    justification: str
    items: List[RequestItemCreate]

class PurchaseRequestUpdate(BaseModel):
    justification: Optional[str] = None
    status: Optional[RequestStatus] = None

class PurchaseRequestResponse(BaseModel):
    request_id: int
    user_id: int
    created_at: datetime
    status: RequestStatus
    justification: str
    items: Optional[List[RequestItemCreate]]

class RequestItemBase(BaseModel):
    material_id: int
    quantity: int = Field(gt=0)
    estimated_cost: float = Field(gt=0)

class RequestItemCreate(RequestItemBase):
    request_id: int

class RequestItemResponse(RequestItemBase):
    request_item_id: int
    request_id: int
    created_at: datetime
class ApprovalCreate(BaseModel):
    decision: ApprovalDecision
    comment: Optional[str] = None

class ApprovalResponse(BaseModel):
    approval_id: int
    request_id: int
    daf_user_id: int
    decision: ApprovalDecision
    comment: Optional[str]
    approved_at: datetime

class OrderItemCreate(BaseModel):
    material_id: int
    quantity: int = Field(gt=0)
    actual_cost: float = Field(gt=0)

class OrderCreate(BaseModel):
    request_id: int
    supplier_id: int
    order_number: str
    items: List[OrderItemCreate]

class OrderResponse(BaseModel):
    order_id: int
    request_id: int
    supplier_id: int
    order_number: str
    tracking_status: TrackingStatus
    ordered_at: datetime
    delivered_at: Optional[datetime]
    items: List[OrderItemCreate]