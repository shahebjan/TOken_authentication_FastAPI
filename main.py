from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from datetime import datetime, timedelta
import jwt

app = FastAPI()
security = HTTPBasic()

SECRET_KEY = "tech"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

users = {
    "mirza": {
        "password": "s123"
    }
}

used_tokens = set()

def create_access_token(data: dict, expires_delta: timedelta):
    expire = datetime.utcnow() + expires_delta
    data_to_encode = data.copy()
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(data_to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = users.get(credentials.username)
    if user is None or user["password"] != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return credentials.username

@app.get("/generate_token")
def generate_token(username: str = Depends(authenticate_user)):
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    tokens = create_access_token({"sub": username}, access_token_expires)
    return {"access_token": tokens, "token_type": "bearer"}

@app.post("/logout")
def logout(request: Request):
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        return "Invalid or missing token"
    else:
        encoded_token = authorization_header.replace("Bearer ", "")
        used_tokens.add(encoded_token)
        return {"message": "Logout successful", "token is going into used tokens": used_tokens}
    


# This endpoint is to validate my token expiration.
@app.post("/login_check/")
def login_check(request: Request):
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        return "Invalid or missing token"
    else:
        encoded_token = authorization_header.replace("Bearer ", "")
    try:
        if encoded_token in used_tokens:
            return "Session expired."
#This below code will take encrypted token and will decode and extract the data and will tell the validation.    
        decoded_token = jwt.decode(encoded_token, SECRET_KEY, algorithms=['HS256'])
        expiration_time = datetime.fromtimestamp(decoded_token["exp"])
        current_time = datetime.utcnow()
        if current_time>=expiration_time:
            return "Token expired"
        else:
            return {"message": "Your token is valid", "user_data": decoded_token}
    except Exception as e:
        return e
    

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
