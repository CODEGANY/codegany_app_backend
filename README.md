# Codegany App Backend

The backend of the Codegany's application.

## Description

This project is a FastAPI-based backend service that provides API endpoints for the Codegany's application that will be presented on the DEVHUB Hackathon 2025.

## Setup

### Prerequisites

- Python 3.6+
- pip (Python package manager)

### Installation

1. Clone this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

Start the server with uvicorn:

```bash
uvicorn main:app --reload
```

The API will be available at http://localhost:8000

## API Endpoints

### Authentication
- `POST /api/v1/auth/check-user`: Check if user exists in the system and return their information

### Suppliers
- `GET /api/v1/suppliers`: Get list of all suppliers
- `GET /api/v1/suppliers/{supplier_id}`: Get a specific supplier
- `POST /api/v1/suppliers`: Create a new supplier

### Materials
- `GET /api/v1/materials`: Get paginated list of materials
- `PUT /api/v1/materials/{material_id}`: Update a specific material
- `DELETE /api/v1/materials/{material_id}`: Delete a specific material
- `POST /api/v1/materials`: Create a new material

### Purchase Requests
- `POST /api/v1/purchase-requests`: Create a new purchase request
- `GET /api/v1/purchase-requests/{request_id}`: Get a specific purchase request
- `GET /api/v1/purchase-requests`: List all purchase requests
- `PUT /api/v1/purchase-requests/{request_id}`: Update a specific purchase request

### Request Items
- `GET /api/v1/request-items/{request_id}`: Get all items for a specific purchase request
- `POST /api/v1/request-items/{request_id}`: Add a new item to a purchase request
- `DELETE /api/v1/request-items/{request_item_id}`: Delete a specific request item
- `PUT /api/v1/request-items/{request_item_id}`: Update a specific request item

### Approvals
- `POST /api/v1/approvals`: Create a new approval decision
- `GET /api/v1/approvals/{approval_id}`: Get a specific approval
- `GET /api/v1/purchase-requests/{request_id}/approval`: Get approval for a specific purchase request

### Orders
- `POST /api/v1/orders`: Create a new order
- `GET /api/v1/orders/{order_id}`: Get a specific order
- `GET /api/v1/orders`: List all orders
- `PUT /api/v1/orders/{order_id}`: Update a specific order
- `GET /api/v1/orders/by-request/{request_id}`: Get order associated with a purchase request

Each endpoint requires authentication via JWT token and implements role-based access control. The token should be included in:
- GET requests: As a Bearer token in the Authorization header
- Other requests: In the request body as a "token" field
