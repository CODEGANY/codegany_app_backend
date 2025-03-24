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

- `GET /`: Returns a simple greeting message
