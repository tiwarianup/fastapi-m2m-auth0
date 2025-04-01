# fastapi-m2m-auth0

# FastAPI Auth0 ML Model Access Control

A secure system for controlling access to ML models using Auth0 for authentication and authorization.

## Overview

This implementation provides a complete solution for managing ML model access with Auth0, supporting:

* JWT token-based authentication through Auth0
* Dual authentication modes: regular users and M2M applications
* Fine-grained permission control for ML model access
* Full CRUD operations for ML models
* SQLite database for model metadata storage

## Prerequisites

* Python 3.7+
* Auth0 account

## Installation

Install the required dependencies:

```
pip install fastapi uvicorn sqlalchemy pyjwt requests python-jose python-multipart
```

## Auth0 Setup

1. Create an Auth0 account if you don't have one
2. Create a new API in Auth0 with an identifier (this will be your `AUTH0_AUDIENCE`)
3. Create an M2M application and authorize it to use your API
4. Add a permission scope `read:models` to your API
5. Grant this scope to your M2M application

## Configuration

Set the required environment variables:

```
export AUTH0_DOMAIN=your-tenant.auth0.com
export AUTH0_AUDIENCE=your-api-identifier
```

## Running the Application
1. Save the code as app.py
2. Start the server:

```
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

## Test User Access

```
curl -X GET "http://localhost:8000/models/" \
-H "Authorization: Bearer YOUR_USER_TOKEN"
```

## Test M2M Access

```
curl -X GET "http://localhost:8000/models/" \
-H "Authorization: Bearer YOUR_M2M_TOKEN"
```

## Creating a model in db for testing

```
curl -X POST "http://localhost:8000/models/" \
-H "Authorization: Bearer YOUR_USER_TOKEN" \
-H "Content-Type: application/json" \
-d '{ "name": "New GPT Model", "description": "A large language model for text generation", "model_type": "generation", "version": "1.0.0", "accuracy": 0.95 }'
```
