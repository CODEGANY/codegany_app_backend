## Code Generation Instructions

### Project Context
- This is a FastAPI backend project for managing equipment purchases in companies
- Written in Python with a focus on asynchronous operations
- Uses Supabase as the backend service

### Code Style Guidelines
- Follow PEP 8 standards
- Use type hints for all function parameters and return values
- Implement proper error handling with custom exception classes
- Use async/await patterns where appropriate
- Document all functions, classes, and modules with docstrings

### API Design Principles
- Follow RESTful API design principles
- Implement proper request validation with Pydantic models
- Use appropriate HTTP status codes and error responses
- Structure endpoints hierarchically (e.g., /api/v1/equipment)

### Database Design
- Use the Supabase Python client library for database operations

### Authentication & Authorization
- Implement authentication using Supabase auth services
- Use role-based access control for authorization
- Secure all endpoints appropriately
- Utilize Supabase policies for fine-grained access control

### Database Tables Structure

### Custom Types
- `user_role`: ENUM('logistique', 'daf')
- `request_status`: ENUM('pending', 'approved', 'rejected', 'ordered', 'delivered', 'closed')
- `approval_decision`: ENUM('approved', 'rejected', 'pending_info')
- `tracking_status`: ENUM('prepared', 'shipped', 'delivered')

### Users
Represents the actors: Logistics Manager, Finance Director, and Supplier.
- `user_id`: VARCHAR(255) [Primary Key]
- `username`: VARCHAR(50) [NOT NULL]
- `role`: user_role [NOT NULL]
- `email`: VARCHAR(100) [NOT NULL]

### Suppliers
Represents the suppliers providing materials.
- `supplier_id`: SERIAL [Primary Key]
- `supplier_name`: VARCHAR(100) [NOT NULL]
- `supplier_description`: VARCHAR(255)
- `supplier_email`: VARCHAR(100)

### Materials
Lists the available materials or those referenced for purchases (e.g., internal catalog).
- `material_id`: SERIAL [Primary Key]
- `name`: VARCHAR(100) [NOT NULL]
- `category`: VARCHAR(50) [NOT NULL]
- `unit_price`: DECIMAL(10,2) [NOT NULL]
- `supplier_id`: INT [Foreign Key -> Suppliers.supplier_id, NOT NULL]
- `stock_available`: INT [NOT NULL]

### PurchaseRequests
Represents the requests submitted by the Logistics Manager.
- `request_id`: SERIAL [Primary Key]
- `user_id`: VARCHAR(255) [Foreign Key -> Users.user_id, NOT NULL]
- `created_at`: TIMESTAMP WITH TIME ZONE [NOT NULL]
- `status`: request_status [NOT NULL]
- `justification`: TEXT [NOT NULL]

### RequestItems
Links purchase requests with requested materials (allows multiple items per request).
- `request_item_id`: SERIAL [Primary Key]
- `request_id`: INT [Foreign Key -> PurchaseRequests.request_id, NOT NULL]
- `material_id`: INT [Foreign Key -> Materials.material_id, NOT NULL]
- `quantity`: INT [NOT NULL]
- `estimated_cost`: DECIMAL(10,2) [NOT NULL]

### Approvals
Records the decisions of the Financial Director (DAF).
- `approval_id`: SERIAL [Primary Key]
- `request_id`: INT [Foreign Key -> PurchaseRequests.request_id, NOT NULL]
- `daf_user_id`: VARCHAR(255) [Foreign Key -> Users.user_id, NOT NULL]
- `decision`: approval_decision [NOT NULL]
- `comment`: TEXT
- `approved_at`: TIMESTAMP WITH TIME ZONE

### Orders
Represents orders placed with suppliers.
- `order_id`: SERIAL [Primary Key]
- `request_id`: INT [Foreign Key -> PurchaseRequests.request_id, NOT NULL]
- `supplier_id`: INT [Foreign Key -> Suppliers.supplier_id, NOT NULL]
- `order_number`: VARCHAR(50) [NOT NULL]
- `tracking_status`: tracking_status [NOT NULL]
- `ordered_at`: TIMESTAMP WITH TIME ZONE [NOT NULL]
- `delivered_at`: TIMESTAMP WITH TIME ZONE

### OrderItems
Details the materials ordered in each order.
- `order_item_id`: SERIAL [Primary Key]
- `order_id`: INT [Foreign Key -> Orders.order_id, NOT NULL]
- `material_id`: INT [Foreign Key -> Materials.material_id, NOT NULL]
- `quantity`: INT [NOT NULL]
- `actual_cost`: DECIMAL(10,2) [NOT NULL]