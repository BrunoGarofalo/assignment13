# Calculator Instructions


## Table of Contents

* Prerequisites
* Setup
* Running Tests
* Docker
* License

---

## Prerequisites

Make sure you have the following installed:

* Python 3.10+
* pip (Python package manager)
* Docker (optional, for containerized environment)

---

## Setup

1. Clone the repository:

```
git clone https://github.com/BrunoGarofalo/assignment12
cd your-repo
```

2. Create a virtual environment:

```
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

3. Install dependencies:

```
pip install -r requirements.txt
```

## Running Tests

You can run all pytests tests locally with:

```
pytest
```


To run a single test file:

```
pytest tests/integration/test_user.py
```

## Running the model:
- Start Docker with docker compose up or create the containers with docker compose up --build if they are not available yet
- go to localhost:8000 to user the model

## Docker hub repository:
- https://hub.docker.com/repository/docker/legioxi/assignment12/general



# Manual Testing Guide (OpenAPI / Swagger UI)

## Start the Application

### Using Docker
```
docker compose up --build
```

### Or run locally
```
uvicorn app.main:app --reload
```

Open: http://localhost:8000/docs

## Manual API Testing Steps

### Health Check
GET /health
Expected response:
{ "status": "ok" }

### Register a New User
POST /auth/register
Payload:
```json
{
  "username": "johndoe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "confirm_password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe"
}
```
### Login and Retrieve JWT Token
POST /auth/login or /auth/token
Copy the access_token.

### Authenticate Swagger UI
Click Authorize → paste:
Bearer <your_token_here>

### Create a Calculation
POST /calculations
```json
{
  "type": "addition",
  "inputs": [10, 5]
}
```
### List Calculations
GET /calculations

### Update a Calculation
PUT /calculations/{calc_id}
```json
{
  "inputs": [100, 10],
  "type": "addition"
}
```
### Delete a Calculation
DELETE /calculations/{calc_id}


## Using the app
Open: http://localhost:8000/dashboard

Register new user, then you'll be automatically redirected to the login page

After a successful login, select the operation type, then enther the operands divided by a comma; finally click calculate

The results will appear in the table below



