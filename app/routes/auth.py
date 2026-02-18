from fastapi import APIRouter, HTTPException, status
from app.models.user import UserCreate, UserLogin, Token
from app.core.security import hash_password, verify_password, create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory "database" for demo
fake_db = {}

@router.post("/register", response_model=Token)
def register(user: UserCreate):
    if user.email in fake_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    hashed = hash_password(user.password)
    fake_db[user.email] = hashed

    access_token = create_access_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login", response_model=Token)
def login(user: UserLogin):
    stored_password = fake_db.get(user.email)
    if not stored_password or not verify_password(user.password, stored_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}
