from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.auth.router import router as auth_router

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://localhost:8000", # Обязательно добавьте сам бэкенд, чтобы Swagger не ругался
]

# 1. Сессии для локальной разработки без SSL
app.add_middleware(
    SessionMiddleware, 
    secret_key="your-super-secret-key",
    session_cookie="oauth_session",
    same_site="lax",       # Защита cookies для локального http хоста
    https_only=False,      # Вот так правильно отключается требование HTTPS в Starlette!
)

# 2. CORS (выполняется самым первым при обработке запроса)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            
    allow_credentials=True,
    allow_methods=["*"],              
    allow_headers=["*"],              
)

app.include_router(auth_router)
