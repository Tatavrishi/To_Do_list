from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
from pymongo import MongoClient
from bson import ObjectId
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt

# Create a new instance of the FastAPI application
app = FastAPI()


# Define the database connection
client = MongoClient()
db = client['todo-db']


# Define the Pydantic models for our to-do list items and user authentication
class TodoItem(BaseModel):
    title: str
    description: str
    done: bool = False


class User(BaseModel):
    username: str
    password: str


# Define the password hashing functions
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    """
    Verify that the provided password matches the hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    """
    Hash the provided password using the bcrypt algorithm.
    """
    return pwd_context.hash(password)


# Define the authentication functions
JWT_SECRET = "secret-key"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Create a new access token using the provided data dictionary and expiration time delta.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str):
    """
    Decode the provided access token and return its payload dictionary.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def authenticate_user(username: str, password: str):
    """
    Authenticate the provided user credentials and return the user object if successful.
    """
    user = db.users.find_one({"username": username})
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Retrieve the current user object from the database using the provided access token.
    """
    payload = decode_access_token(token)
    user = db.users.find_one({"username": payload['sub']})
    if not user:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return user


# Define the API endpoints for our to-do list
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate the user and return a new access token if successful.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    access_token = create_access_token(data={"sub": user['username']})
    return {"access_token": access_token, "token_type": "bearer"}

async def create_todo_item(item: TodoItem, user: dict = Depends(get_current_user)):
    """
    Create a new to-do item in the database and return its ID.
    """
    item_dict = item.dict()
    item_dict['user_id'] = user['_id']
    result = db.items.insert_one(item_dict)
    return {"id": str(result.inserted_id)}


@app.get("/items", response_model=List[TodoItem])
async def read_todo_items(user: dict = Depends(get_current_user)):
    """
    Retrieve a list of to-do items belonging to the authenticated user.
    """
    items = db.items.find({"user_id": user['_id']})
    return [TodoItem(**item) for item in items]


@app.get("/items/{item_id}", response_model=TodoItem)
async def read_todo_item(item_id: str, user: dict = Depends(get_current_user)):
    """
    Retrieve the details of a specific to-do item belonging to the authenticated user.
    """
    item = db.items.find_one({"_id": ObjectId(item_id), "user_id": user['_id']})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return TodoItem(**item)


@app.put("/items/{item_id}")
async def update_todo_item(item_id: str, item: TodoItem, user: dict = Depends(get_current_user)):
    """
    Update the details of a specific to-do item belonging to the authenticated user.
    """
    result = db.items.update_one({"_id": ObjectId(item_id), "user_id": user['_id']}, {"$set": item.dict()})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item updated successfully"}


@app.delete("/items/{item_id}")
async def delete_todo_item(item_id: str, user: dict = Depends(get_current_user)):
    """
    Delete a specific to-do item belonging to the authenticated user.
    """
    result = db.items.delete_one({"_id": ObjectId(item_id), "user_id": user['_id']})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted successfully"}