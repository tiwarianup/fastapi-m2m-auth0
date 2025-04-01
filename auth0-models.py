from fastapi import Depends, HTTPException, status, FastAPI
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Float, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker
from pydantic import BaseModel as PydanticBaseModel
import requests
import json
from functools import lru_cache
import os
from datetime import datetime

# FastAPI app
app = FastAPI(title="ML Model Access Management with Auth0")

# Setup security scheme
security = HTTPBearer()

# Config for Auth0 - in production, use environment variables
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "your-tenant.auth0.com")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "your-api-identifier")
ALGORITHMS = ["RS256"]

# SQLAlchemy setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./ml_models.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Database models
class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(Text, nullable=True)
    model_type = Column(String, index=True)  # e.g., "classification", "generation", "embedding"
    version = Column(String)
    accuracy = Column(Float, nullable=True)
    owner_id = Column(String, index=True)  # Auth0 user ID
    created_at = Column(String, default=lambda: datetime.now().isoformat())
    updated_at = Column(String, default=lambda: datetime.now().isoformat(), 
                       onupdate=lambda: datetime.now().isoformat())


# Create database tables
Base.metadata.create_all(bind=engine)


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Pydantic models for API
class MLModelBase(PydanticBaseModel):
    name: str
    description: Optional[str] = None
    model_type: str
    version: str
    accuracy: Optional[float] = None


class MLModelCreate(MLModelBase):
    pass


class MLModelResponse(MLModelBase):
    id: int
    owner_id: str
    created_at: str
    updated_at: str

    class Config:
        orm_mode = True


class User(PydanticBaseModel):
    id: str
    email: Optional[str] = None


# JWKS caching function
@lru_cache(maxsize=1)
def get_jwks(jwks_url: str) -> Dict:
    """
    Fetch and cache the JWKS (JSON Web Key Set) from Auth0
    """
    try:
        response = requests.get(jwks_url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        # In a production app, you'd want to log this
        print(f"Error fetching JWKS: {e}")
        return {"keys": []}


def get_key_from_jwks(token: str, jwks: Dict) -> Optional[str]:
    """
    Extract the appropriate key from JWKS based on the token header
    """
    # This is a simplified version for demo purposes
    # In production, you'd properly match the key ID (kid) from the token header
    # to the corresponding key in the JWKS
    
    # Parse token header to get key ID
    header = jwt.get_unverified_header(token)
    key_id = header.get("kid")
    
    if not key_id:
        return None
    
    # Find the key in JWKS
    for key in jwks.get("keys", []):
        if key.get("kid") == key_id:
            # Construct PEM from key components (this is simplified)
            # In production, use a proper JWT library that can work with JWKS format
            return json.dumps(key)
    
    return None


# Auth0 token validation
def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Validate the Auth0 JWT token from the Authorization header
    """
    token = credentials.credentials
    
    try:
        # Get the public key from Auth0
        jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        jwks = get_jwks(jwks_url)
        
        # For demo purposes:
        # In a real implementation with PyJWT, you would:
        # 1. Get the appropriate key from JWKS 
        # 2. Properly format it as a public key
        # 3. Use it to verify the token
        # 
        # key = get_key_from_jwks(token, jwks)
        # 
        # For this demo, we'll assume the JWT validation works properly
        # In production, use a library that can work with JWKS format like authlib
        
        # Simplified for demo - in real implementation, use proper verification
        # This is a mock verification for demonstration
        # DO NOT USE THIS IN PRODUCTION
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        
        # In a real implementation, you would properly verify the token:
        # payload = jwt.decode(
        #     token,
        #     key,
        #     algorithms=ALGORITHMS,
        #     audience=AUTH0_AUDIENCE,
        #     issuer=f"https://{AUTH0_DOMAIN}/"
        # )
        
        # For demo purpose, we'll use the unverified payload
        payload = unverified_payload
        
        # Check if it's an M2M token by inspecting claims
        # M2M tokens typically have a 'client_id' claim and no 'sub' that looks like an email
        is_m2m = 'client_id' in payload and (
            'sub' not in payload or '@' not in payload.get('sub', '')
        )
        
        return {
            "token": token,
            "payload": payload,
            "is_m2m": is_m2m,
            "user_id": payload.get("sub"),
        }
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error validating token: {str(e)}",
        )


# Get current user from token
def get_current_user(token_data: dict = Depends(validate_token)) -> Optional[User]:
    """
    Extract user information from the token
    """
    if token_data["is_m2m"]:
        # For M2M, we don't have a real user, return None
        return None
    
    user_id = token_data["user_id"]
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # In a real app, you might fetch more user data from your database
    # Here we'll return a user object based just on the token
    return User(
        id=user_id, 
        email=token_data["payload"].get("email", "")
    )


# Permission dependency factory
def has_model_permission(model_id: int):
    """
    Factory function that creates a permission dependency for a specific ML model
    """
    def check_permission(
        token_data: dict = Depends(validate_token),
        current_user: Optional[User] = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> bool:
        """
        Check if the current request has permission to access the specified ML model.
        
        Allows access if:
        1. The request is from an M2M application with proper scope
        2. The current user is the owner of the model
        """
        # Get the model from the database
        model = db.query(MLModel).filter(MLModel.id == model_id).first()
        
        if not model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ML model with id {model_id} not found"
            )
        
        # Case 1: M2M access - check if the token has proper scope
        if token_data["is_m2m"]:
            scopes = token_data["payload"].get("scope", "").split()
            if "read:models" in scopes:
                return True
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="M2M application lacks required scope"
                )
        
        # Case 2: Regular user access - check if user is the owner
        if current_user and model.owner_id == current_user.id:
            return True
        
        # If we get here, access is denied
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this ML model"
        )
    
    return check_permission


# CRUD operations
@app.post("/models/", response_model=MLModelResponse)
def create_model(
    model: MLModelCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new ML model owned by the current user"""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="M2M tokens cannot create models"
        )
    
    db_model = MLModel(
        **model.dict(),
        owner_id=current_user.id
    )
    db.add(db_model)
    db.commit()
    db.refresh(db_model)
    return db_model


@app.get("/models/{model_id}", response_model=MLModelResponse)
def read_model(
    model_id: int,
    _: bool = Depends(has_model_permission(model_id)),
    db: Session = Depends(get_db)
):
    """
    Get an ML model by ID.
    
    This endpoint is protected:
    - Owner of the model can access it
    - Auth0 M2M applications with read:models scope can access it
    """
    # If we get here, permission is granted
    model = db.query(MLModel).filter(MLModel.id == model_id).first()
    return model


@app.get("/models/", response_model=List[MLModelResponse])
def read_models(
    skip: int = 0, 
    limit: int = 100,
    current_user: Optional[User] = Depends(get_current_user),
    token_data: dict = Depends(validate_token),
    db: Session = Depends(get_db)
):
    """
    Get all ML models that the user has access to.
    
    - Regular users can only see their own models
    - M2M applications with read:models scope can see all models
    """
    if token_data["is_m2m"]:
        # Check if the M2M token has the required scope
        scopes = token_data["payload"].get("scope", "").split()
        if "read:models" in scopes:
            models = db.query(MLModel).offset(skip).limit(limit).all()
            return models
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="M2M application lacks required scope"
            )
    elif current_user:
        # Regular users can only see their own models
        models = db.query(MLModel).filter(
            MLModel.owner_id == current_user.id
        ).offset(skip).limit(limit).all()
        return models
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )


@app.put("/models/{model_id}", response_model=MLModelResponse)
def update_model(
    model_id: int,
    model_update: MLModelCreate,
    _: bool = Depends(has_model_permission(model_id)),
    db: Session = Depends(get_db)
):
    """
    Update an ML model.
    
    This endpoint is protected:
    - Only the owner of the model can update it
    """
    db_model = db.query(MLModel).filter(MLModel.id == model_id).first()
    
    # Update model attributes
    for key, value in model_update.dict().items():
        setattr(db_model, key, value)
    
    # Update timestamp
    db_model.updated_at = datetime.now().isoformat()
    
    db.commit()
    db.refresh(db_model)
    return db_model


@app.delete("/models/{model_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_model(
    model_id: int,
    _: bool = Depends(has_model_permission(model_id)),
    db: Session = Depends(get_db)
):
    """
    Delete an ML model.
    
    This endpoint is protected:
    - Only the owner of the model can delete it
    """
    db_model = db.query(MLModel).filter(MLModel.id == model_id).first()
    db.delete(db_model)
    db.commit()
    return None


# Health check endpoint
@app.get("/health")
def health_check():
    """Health check endpoint that doesn't require authentication"""
    return {"status": "healthy", "version": "1.0.0"}


# Seed data (for testing purposes)
@app.on_event("startup")
def seed_data():
    db = SessionLocal()
    # Check if we already have models
    model_count = db.query(MLModel).count()
    if model_count == 0:
        # Add some sample models
        sample_models = [
            MLModel(
                name="Sentiment Analysis LLM", 
                description="A transformer-based model for sentiment analysis", 
                model_type="classification",
                version="1.0.0",
                accuracy=0.92,
                owner_id="auth0|user1",
                created_at=datetime.now().isoformat(),
                updated_at=datetime.now().isoformat()
            ),
            MLModel(
                name="Image Generation Diffusion", 
                description="A diffusion model for generating images from text prompts", 
                model_type="generation",
                version="2.1.3",
                accuracy=None,
                owner_id="auth0|user2",
                created_at=datetime.now().isoformat(),
                updated_at=datetime.now().isoformat()
            ),
            MLModel(
                name="Text Embedding Model", 
                description="A model for converting text to vector embeddings", 
                model_type="embedding",
                version="0.9.5",
                accuracy=0.88,
                owner_id="auth0|user1",
                created_at=datetime.now().isoformat(),
                updated_at=datetime.now().isoformat()
            ),
        ]
        db.add_all(sample_models)
        db.commit()
    db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
